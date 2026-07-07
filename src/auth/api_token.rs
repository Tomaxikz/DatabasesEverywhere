use subtle::ConstantTimeEq;

use crate::auth::scopes;

#[derive(Debug, Clone)]
pub struct ApiToken {
    tokens: Vec<NamedToken>,
}

#[derive(Debug, Clone)]
struct NamedToken {
    name: String,
    token: String,
    scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedApiToken {
    pub name: String,
    pub scopes: Vec<String>,
}

impl AcceptedApiToken {
    pub fn has_scope(&self, required_scope: &str) -> bool {
        scopes::allows(&self.scopes, required_scope)
    }
}

impl ApiToken {
    pub fn new(expected: impl Into<String>) -> Self {
        let expected = expected.into();
        let tokens = if expected.trim().is_empty() {
            Vec::new()
        } else {
            vec![NamedToken {
                name: "default".to_string(),
                token: expected,
                scopes: vec![scopes::ALL.to_string()],
            }]
        };
        Self { tokens }
    }

    pub fn from_config(config: &crate::config::Config) -> Self {
        let mut tokens = Vec::new();
        if !config.token.trim().is_empty() {
            tokens.push(NamedToken {
                name: config.token_id.clone(),
                token: config.token.clone(),
                scopes: vec![scopes::ALL.to_string()],
            });
        }
        Self { tokens }
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
            })
    }

    fn accepted_named_token(&self, token: &str) -> Option<&NamedToken> {
        self.tokens.iter().find(|expected| {
            token.len() == expected.token.len()
                && bool::from(token.as_bytes().ct_eq(expected.token.as_bytes()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_matching_bearer_token() {
        let token = ApiToken::new("secret");

        assert!(
            token
                .accepted_from_authorization_header(Some("Bearer secret"))
                .is_some()
        );
    }

    #[test]
    fn rejects_wrong_token() {
        let token = ApiToken::new("secret");

        assert!(
            token
                .accepted_from_authorization_header(Some("Bearer other"))
                .is_none()
        );
    }

    #[test]
    fn rejects_missing_bearer_prefix() {
        let token = ApiToken::new("secret");

        assert!(
            token
                .accepted_from_authorization_header(Some("secret"))
                .is_none()
        );
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
        assert_eq!(accepted.name, "panel-a");
        assert!(accepted.has_scope(scopes::INSTANCES_READ));
    }
}
