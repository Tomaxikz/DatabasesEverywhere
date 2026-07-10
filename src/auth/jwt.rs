use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::constants::jwt::{AUDIENCE, ISSUER};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    #[serde(default)]
    pub all_instances: bool,
    pub instances: Vec<String>,
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
        self.all_instances || self.instances.iter().any(|allowed| allowed == instance_id)
    }
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

pub fn issue_ws_token(
    secret: &[u8],
    subject: &str,
    scopes: Vec<String>,
    instances: Vec<String>,
    all_instances: bool,
    ttl_seconds: i64,
) -> Result<(String, i64), JwtAuthError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let exp = now + ttl_seconds;
    let claims = Claims {
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        sub: subject.to_string(),
        all_instances,
        instances,
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
    fn rejects_missing_instance() {
        let secret = b"secret";
        let token = encode(
            &Header::default(),
            &claims(scopes::LOGS_READ, "inst_abc", 3600),
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let error =
            validate_ws_token(&token, secret, scopes::LOGS_READ, Some("inst_other")).unwrap_err();

        assert!(matches!(error, JwtAuthError::MissingInstance { .. }));
    }

    #[test]
    fn empty_instance_list_does_not_grant_node_wide_access() {
        let secret = b"secret";
        let mut claims = claims(scopes::LOGS_READ, "inst_abc", 3600);
        claims.instances.clear();
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let error =
            validate_ws_token(&token, secret, scopes::LOGS_READ, Some("inst_other")).unwrap_err();

        assert!(matches!(error, JwtAuthError::MissingInstance { .. }));
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
            vec!["inst_abc".to_string()],
            false,
            60,
        )
        .unwrap();

        let claims =
            validate_ws_token(&token, secret, scopes::MONITOR_READ, Some("inst_abc")).unwrap();

        assert_eq!(claims.sub, "panel");
        assert_eq!(claims.exp, exp);
    }

    fn claims(scope: &str, instance_id: &str, ttl_seconds: i64) -> Claims {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        Claims {
            iss: ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            sub: "admin".to_string(),
            all_instances: false,
            instances: vec![instance_id.to_string()],
            scopes: vec![scope.to_string()],
            iat: now,
            nbf: now,
            exp: now + ttl_seconds,
            jti: "nonce".to_string(),
        }
    }
}
