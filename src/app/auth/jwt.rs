use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    constants::jwt::{AUDIENCE, ISSUER},
    shared::time::now_unix,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pools: Vec<PoolGrant>,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub all_instances: bool,
    pub instances: Vec<String>,
    /// Binds a selected-instance token to the exact metadata generations that
    /// existed when it was issued. The claim is omitted for node-wide tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_generation_digest: Option<String>,
    pub scopes: Vec<String>,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub jti: String,
}

impl Claims {
    /// Node-wide access is explicit. An empty allow-list never silently
    /// broadens a token to every tenant.
    pub fn allows_instance(&self, instance_id: &str) -> bool {
        self.pools.is_empty()
            && (self.all_instances || self.instances.iter().any(|allowed| allowed == instance_id))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolGrant {
    pub runtime_id: String,
    pub owner: crate::placement::PoolOwner,
    pub created_at: String,
}

impl PoolGrant {
    pub(crate) fn matches(&self, pool: &crate::placement::EngineRuntime) -> bool {
        pool.deployment_mode == crate::placement::DeploymentMode::Shared
            && pool.runtime_id == self.runtime_id
            && pool.created_at == self.created_at
            && pool.owner.as_ref() == Some(&self.owner)
    }
}

pub(crate) enum WsTargets {
    Instances {
        instances: Vec<String>,
        all_instances: bool,
        generation: Option<String>,
    },
    Pools(Vec<PoolGrant>),
}

#[derive(Debug, Deserialize)]
struct TokenIdentityClaims {
    jti: String,
    #[serde(rename = "exp")]
    _expiration: i64,
    #[serde(rename = "nbf")]
    _not_before: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum JwtAuthError {
    #[error("jwt validation failed")]
    Invalid(#[from] jsonwebtoken::errors::Error),
    #[error("jwt is missing required scope {scope}")]
    MissingScope { scope: String },
    #[error("jwt is not scoped to instance {instance_id}")]
    MissingInstance { instance_id: String },
}

pub(crate) fn issue_ws_token(
    secret: &[u8],
    subject: &str,
    scopes: Vec<String>,
    targets: WsTargets,
    ttl_seconds: i64,
) -> Result<(String, i64), JwtAuthError> {
    let now = now_unix();
    let exp = now + ttl_seconds;
    let (instances, all_instances, instance_generation_digest, pools) = match targets {
        WsTargets::Instances {
            instances,
            all_instances,
            generation,
        } => (instances, all_instances, generation, Vec::new()),
        WsTargets::Pools(pools) => (Vec::new(), false, None, pools),
    };
    let claims = Claims {
        pools,
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        sub: subject.to_string(),
        all_instances,
        instances,
        instance_generation_digest,
        scopes,
        iat: now,
        nbf: now,
        exp,
        jti: Uuid::new_v4().to_string(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )?;
    Ok((token, exp))
}

/// Computes the compact identity bound carried by selected-instance tokens.
/// Length-prefixing avoids ambiguous concatenations, while sorting makes the
/// result independent of request order.
pub(crate) fn instance_generation_digest(pairs: &[(String, String)]) -> String {
    let mut pairs = pairs.iter().collect::<Vec<_>>();
    pairs.sort_unstable();
    let mut digest = Sha256::new();
    digest.update(b"dbev-ws-instance-generations-v1\0");
    for (instance_id, generation) in pairs {
        update_digest_field(&mut digest, instance_id.as_bytes());
        update_digest_field(&mut digest, generation.as_bytes());
    }
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn update_digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

pub fn validate_ws_token(
    token: &str,
    secret: &[u8],
    required_scope: &str,
    instance_id: Option<&str>,
) -> Result<Claims, JwtAuthError> {
    let claims = validate_ws_token_claims(token, secret)?;

    if !claims.scopes.iter().any(|scope| scope == required_scope) {
        return Err(JwtAuthError::MissingScope {
            scope: required_scope.to_string(),
        });
    }

    if let Some(instance_id) = instance_id
        && !claims.allows_instance(instance_id)
    {
        return Err(JwtAuthError::MissingInstance {
            instance_id: instance_id.to_string(),
        });
    }

    Ok(claims)
}

pub fn validate_ws_token_claims(token: &str, secret: &[u8]) -> Result<Claims, JwtAuthError> {
    let token = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &strict_hs256_validation(),
    )?;
    Ok(token.claims)
}

/// Returns the stable identity of an otherwise valid daemon JWT. This is used
/// only after signature and time validation, so attacker-controlled garbage is
/// never allowed to create unbounded rate-limit buckets.
pub(crate) fn validated_token_jti(token: &str, secret: &[u8]) -> Result<String, JwtAuthError> {
    let token = decode::<TokenIdentityClaims>(
        token,
        &DecodingKey::from_secret(secret),
        &strict_hs256_validation(),
    )?;
    Ok(token.claims.jti)
}

pub(crate) fn strict_hs256_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[AUDIENCE]);
    validation.set_issuer(&[ISSUER]);
    validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss"]);
    validation.validate_nbf = true;
    validation.leeway = 0;
    validation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::scopes;

    #[test]
    fn accepts_required_scope_and_instance() {
        let secret = b"secret";
        let token = encode(
            &Header::default(),
            &claims(scopes::MONITOR_READ, "inst_abc", 3600),
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let claims =
            validate_ws_token(&token, secret, scopes::MONITOR_READ, Some("inst_abc")).unwrap();

        assert_eq!(claims.sub, "admin");
    }

    #[test]
    fn rejects_missing_scope() {
        let secret = b"secret";
        let token = encode(
            &Header::default(),
            &claims(scopes::LOGS_READ, "inst_abc", 3600),
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let error =
            validate_ws_token(&token, secret, scopes::MONITOR_READ, Some("inst_abc")).unwrap_err();

        assert!(matches!(error, JwtAuthError::MissingScope { .. }));
    }

    #[test]
    fn instance_scope_rejects_foreign_and_empty_instance_claims() {
        let secret = b"secret";
        for instances in [vec!["inst_abc".to_string()], Vec::new()] {
            let mut claims = claims(scopes::LOGS_READ, "inst_abc", 3600);
            claims.instances = instances;
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(secret),
            )
            .unwrap();
            assert!(matches!(
                validate_ws_token(&token, secret, scopes::LOGS_READ, Some("inst_other")),
                Err(JwtAuthError::MissingInstance { .. })
            ));
        }
    }

    #[test]
    fn explicit_node_wide_claim_allows_other_instances() {
        let secret = b"secret";
        let mut claims = claims(scopes::LOGS_READ, "inst_abc", 3600);
        claims.instances.clear();
        claims.all_instances = true;
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        validate_ws_token(&token, secret, scopes::LOGS_READ, Some("inst_other")).unwrap();
    }

    #[test]
    fn rejects_expired_token_without_clock_skew_leeway() {
        let secret = b"secret";
        let token = encode(
            &Header::default(),
            &claims(scopes::MONITOR_READ, "inst_abc", -1),
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let error =
            validate_ws_token(&token, secret, scopes::MONITOR_READ, Some("inst_abc")).unwrap_err();

        assert!(matches!(error, JwtAuthError::Invalid(_)));
    }

    #[test]
    fn rate_limit_identity_requires_a_valid_signature() {
        let claims = claims(scopes::MONITOR_READ, "inst_abc", 60);
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"other-secret"),
        )
        .unwrap();

        assert!(validated_token_jti(&token, b"secret").is_err());
    }

    #[test]
    fn issued_token_validates() {
        let secret = b"secret";
        let (token, exp) = issue_ws_token(
            secret,
            "panel",
            vec![scopes::MONITOR_READ.to_string()],
            WsTargets::Instances {
                instances: vec!["inst_abc".into()],
                all_instances: false,
                generation: Some(instance_generation_digest(&[(
                    "inst_abc".into(),
                    "generation-a".into(),
                )])),
            },
            60,
        )
        .unwrap();

        let claims =
            validate_ws_token(&token, secret, scopes::MONITOR_READ, Some("inst_abc")).unwrap();

        assert_eq!(claims.sub, "panel");
        assert_eq!(claims.exp, exp);
    }

    fn claims(scope: &str, instance_id: &str, ttl_seconds: i64) -> Claims {
        let now = now_unix();
        Claims {
            pools: Vec::new(),
            iss: ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            sub: "admin".to_string(),
            all_instances: false,
            instances: vec![instance_id.to_string()],
            instance_generation_digest: Some(instance_generation_digest(&[(
                instance_id.to_string(),
                "generation-a".to_string(),
            )])),
            scopes: vec![scope.to_string()],
            iat: now,
            nbf: now,
            exp: now + ttl_seconds,
            jti: "nonce".to_string(),
        }
    }

    #[test]
    fn generation_digest_is_order_independent_and_identity_sensitive() {
        let first = vec![
            ("inst_b".to_string(), "generation-b".to_string()),
            ("inst_a".to_string(), "generation-a".to_string()),
        ];
        let reversed = vec![first[1].clone(), first[0].clone()];
        assert_eq!(
            instance_generation_digest(&first),
            instance_generation_digest(&reversed)
        );

        let recreated = vec![
            ("inst_a".to_string(), "generation-new".to_string()),
            ("inst_b".to_string(), "generation-b".to_string()),
        ];
        assert_ne!(
            instance_generation_digest(&first),
            instance_generation_digest(&recreated)
        );
    }
}
