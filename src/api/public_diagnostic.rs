use std::fmt::Display;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::api_response::ApiError;

const MAX_PUBLIC_DIAGNOSTIC_CHARS: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicDiagnostic {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_id: Option<String>,
}

impl PublicDiagnostic {
    pub fn public(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: bounded(code.into()),
            message: bounded(message.into()),
            error_id: None,
        }
    }

    pub fn internal(context: &'static str, cause: impl Display) -> Self {
        let error_id = Uuid::new_v4().to_string();
        tracing::error!(error_id, context, error = %cause, "asynchronous operation failed internally");
        Self {
            code: "internal_error".to_string(),
            message: format!("{context} failed"),
            error_id: Some(error_id),
        }
    }

    pub fn from_api_error(context: &'static str, error: &ApiError) -> Self {
        match error {
            ApiError::BadRequest(message) => Self::public("bad_request", message),
            ApiError::Unauthorized
            | ApiError::InvalidWebSocketJwt(_)
            | ApiError::HostNotAllowed
            | ApiError::QueryTokenRejected => Self::public("unauthorized", "unauthorized"),
            ApiError::Forbidden(scope) => {
                Self::public("forbidden", format!("missing required scope {scope}"))
            }
            ApiError::NotFound => Self::public("not_found", "not found"),
            ApiError::Conflict(message) => Self::public("conflict", message),
            ApiError::RateLimited => Self::public("rate_limited", "rate limit exceeded"),
            ApiError::ServiceUnavailable(message) => Self::public("service_unavailable", message),
            ApiError::NotImplemented(message) => Self::public("not_implemented", message),
            ApiError::RequestRejected { status, message } if !status.is_server_error() => {
                Self::public("request_rejected", message)
            }
            ApiError::Runtime(_) | ApiError::RequestRejected { .. } => {
                Self::internal(context, error)
            }
        }
    }

    pub fn to_storage_string(&self) -> String {
        serde_json::to_string(self).expect("public diagnostic serialization cannot fail")
    }

    pub fn from_storage(context: &'static str, stored: &str) -> Self {
        serde_json::from_str(stored)
            .unwrap_or_else(|_| Self::internal(context, "legacy job failure detail redacted"))
    }
}

fn bounded(value: String) -> String {
    value.chars().take(MAX_PUBLIC_DIAGNOSTIC_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_diagnostics_never_expose_the_cause() {
        let diagnostic = PublicDiagnostic::internal(
            "container operation",
            "password=hunter2 path=/var/lib/private",
        );

        let encoded = serde_json::to_string(&diagnostic).unwrap();
        assert_eq!(diagnostic.code, "internal_error");
        assert!(diagnostic.error_id.is_some());
        assert!(!encoded.contains("hunter2"));
        assert!(!encoded.contains("/var/lib/private"));
    }

    #[test]
    fn stored_diagnostics_round_trip() {
        let expected = PublicDiagnostic::public("not_running", "instance is stopped");

        assert_eq!(
            PublicDiagnostic::from_storage("job", &expected.to_storage_string()),
            expected
        );
    }
}
