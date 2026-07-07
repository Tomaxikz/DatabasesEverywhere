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
    pub instances: Vec<String>,
    pub scopes: Vec<String>,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub jti: String,
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
    ttl_seconds: i64,
) -> Result<(String, i64), JwtAuthError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let exp = now + ttl_seconds;
    let claims = Claims {
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        sub: subject.to_string(),
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
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[AUDIENCE]);
    validation.set_issuer(&[ISSUER]);
    validation.validate_nbf = true;

    let token = decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)?;
    let claims = token.claims;

    if !claims.scopes.iter().any(|scope| scope == required_scope) {
        return Err(JwtAuthError::MissingScope {
            scope: required_scope.to_string(),
        });
    }

    if let Some(instance_id) = instance_id {
        let is_allowed = claims
            .instances
            .iter()
            .any(|allowed| allowed == instance_id);
        if !is_allowed {
            return Err(JwtAuthError::MissingInstance {
                instance_id: instance_id.to_string(),
            });
        }
    }

    Ok(claims)
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
    fn issued_token_validates() {
        let secret = b"secret";
        let (token, exp) = issue_ws_token(
            secret,
            "panel",
            vec![scopes::MONITOR_READ.to_string()],
            vec!["inst_abc".to_string()],
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
            instances: vec![instance_id.to_string()],
            scopes: vec![scope.to_string()],
            iat: now,
            nbf: now,
            exp: now + ttl_seconds,
            jti: "nonce".to_string(),
        }
    }
}
