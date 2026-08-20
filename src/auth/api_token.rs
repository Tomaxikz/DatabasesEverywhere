use std::sync::Arc;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::auth::scopes;

#[derive(Debug, Clone)]
pub struct ApiToken {
    tokens: Arc<[NamedToken]>,
}

#[derive(Debug)]
struct NamedToken {
    name: Arc<str>,
    token: Arc<str>,
    scopes: Arc<[String]>,
    rate_limit_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedApiToken {
    pub name: Arc<str>,
    pub scopes: Arc<[String]>,
    rate_limit_fingerprint: [u8; 32],
}

impl AcceptedApiToken {
    pub fn has_scope(&self, required_scope: &str) -> bool {
        scopes::allows(&self.scopes, required_scope)
    }

    pub(crate) fn rate_limit_fingerprint(&self) -> [u8; 32] {
        self.rate_limit_fingerprint
    }
}

impl ApiToken {
    pub fn new(expected: impl Into<String>) -> Self {
        let expected = expected.into();
        let tokens = if expected.trim().is_empty() {
            Vec::new()
        } else {
            vec![named_token(
                "default".to_string(),
                expected,
                vec![scopes::ALL.to_string()],
            )]
        };
        Self {
            tokens: tokens.into(),
        }
    }

    pub fn from_config(config: &crate::config::Config) -> Self {
        let mut tokens = Vec::new();
        if !config.token.trim().is_empty() {
            tokens.push(named_token(
                config.token_id.clone(),
                config.token.clone(),
                vec![scopes::ALL.to_string()],
            ));
        }
        Self {
            tokens: tokens.into(),
        }
    }

    pub fn accepted_from_authorization_header(
        &self,
        header: Option<&str>,
    ) -> Option<AcceptedApiToken> {
        let header = header?;
        let token = header.strip_prefix("Bearer ")?;
        self.accepted_token(token)
    }

    fn accepted_token(&self, token: &str) -> Option<AcceptedApiToken> {
        self.accepted_named_token(token)
            .map(|token| AcceptedApiToken {
                name: token.name.clone(),
                scopes: token.scopes.clone(),
                rate_limit_fingerprint: token.rate_limit_fingerprint,
            })
    }

    fn accepted_named_token(&self, token: &str) -> Option<&NamedToken> {
        self.tokens.iter().find(|expected| {
            token.len() == expected.token.len()
                && bool::from(token.as_bytes().ct_eq(expected.token.as_bytes()))
        })
    }
}

fn named_token(name: String, token: String, scopes: Vec<String>) -> NamedToken {
    let mut fingerprint = Sha256::new();
    fingerprint.update(b"api");
    fingerprint.update([0]);
    fingerprint.update(name.as_bytes());
    NamedToken {
        name: Arc::from(name),
        token: Arc::from(token),
        scopes: scopes.into(),
        rate_limit_fingerprint: fingerprint.finalize().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_matching_bearer_token() {
        let token = ApiToken::new("secret");

        for (header, accepted) in [
            (Some("Bearer secret"), true),
            (Some("Bearer other"), false),
            (Some("secret"), false),
            (None, false),
        ] {
            assert_eq!(
                token.accepted_from_authorization_header(header).is_some(),
                accepted,
                "unexpected authorization result for {header:?}"
            );
        }
    }

    #[test]
    fn accepts_config_token() {
        let token = ApiToken::from_config(&crate::config::Config {
            token_id: "panel-a".to_string(),
            token: "secret-a".to_string(),
            ..Default::default()
        });

        let accepted = token
            .accepted_from_authorization_header(Some("Bearer secret-a"))
            .unwrap();
        assert_eq!(accepted.name.as_ref(), "panel-a");
        assert!(accepted.has_scope(scopes::INSTANCES_READ));
    }
}
