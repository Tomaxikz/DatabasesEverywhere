use axum::{
    Json,
    extract::{FromRequest, FromRequestParts, Path, Query, Request},
    http::{HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

/// The single JSON success response used by the HTTP API.
///
/// Keeping status and header construction here prevents individual handlers from
/// inventing subtly different asynchronous-operation contracts.
#[derive(Debug)]
pub struct ApiResponse<T> {
    status: StatusCode,
    location: Option<String>,
    body: T,
}

impl<T> ApiResponse<T> {
    pub fn ok(body: T) -> Self {
        Self {
            status: StatusCode::OK,
            location: None,
            body,
        }
    }

    pub fn accepted(body: T) -> Self {
        Self {
            status: StatusCode::ACCEPTED,
            location: None,
            body,
        }
    }

    pub fn accepted_at(body: T, location: impl Into<String>) -> Self {
        Self {
            status: StatusCode::ACCEPTED,
            location: Some(location.into()),
            body,
        }
    }

    pub fn with_status(status: StatusCode, body: T) -> Self {
        Self {
            status,
            location: None,
            body,
        }
    }

    pub fn into_body(self) -> T {
        self.body
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(self.body)).into_response();
        if let Some(location) = self.location {
            let value = HeaderValue::from_str(&location)
                .expect("API-generated Location must be a valid header value");
            response.headers_mut().insert(header::LOCATION, value);
        }
        response
    }
}

pub type ApiResult<T> = Result<ApiResponse<T>, ApiError>;

/// Public API errors retain actionable client messages while internal causes are
/// logged under an opaque error ID and never returned over the network.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden: missing required scope {0}")]
    Forbidden(String),
    #[error("request host is not allowed")]
    HostNotAllowed,
    #[error("token in query string is not accepted")]
    QueryTokenRejected,
    #[error("websocket jwt is invalid: {0}")]
    InvalidWebSocketJwt(String),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("runtime error: {0}")]
    Runtime(String),
    #[error("{message}")]
    RequestRejected { status: StatusCode, message: String },
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized
            | Self::HostNotAllowed
            | Self::QueryTokenRejected
            | Self::InvalidWebSocketJwt(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            Self::Runtime(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::RequestRejected { status, .. } => *status,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Unauthorized | Self::InvalidWebSocketJwt(_) => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::HostNotAllowed => "host_not_allowed",
            Self::QueryTokenRejected => "query_token_rejected",
            Self::NotFound => "not_found",
            Self::Conflict(_) => "conflict",
            Self::RateLimited => "rate_limited",
            Self::ServiceUnavailable(_) => "service_unavailable",
            Self::NotImplemented(_) => "not_implemented",
            Self::Runtime(_) => "internal_error",
            Self::RequestRejected { status, .. } => match *status {
                StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
                StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
                StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported_media_type",
                _ => "bad_request",
            },
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::Runtime(_) => "internal server error".to_string(),
            Self::InvalidWebSocketJwt(_) => "unauthorized".to_string(),
            _ => self.to_string(),
        }
    }

    fn from_rejection(status: StatusCode, message: String) -> Self {
        Self::RequestRejected { status, message }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let error_id = status.is_server_error().then(|| Uuid::new_v4().to_string());
        if let Some(error_id) = error_id.as_deref() {
            tracing::error!(error_id, error = %self, "API request failed internally");
        }
        let mut response = (
            status,
            Json(ErrorBody {
                error: self.public_message(),
                code: self.code(),
                error_id: error_id.clone(),
            }),
        )
            .into_response();
        if let Some(error_id) = error_id
            && let Ok(value) = HeaderValue::from_str(&error_id)
        {
            response.headers_mut().insert("x-error-id", value);
        }
        response
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_id: Option<String>,
}

pub async fn route_not_found() -> ApiError {
    ApiError::NotFound
}

pub async fn method_not_allowed() -> ApiError {
    ApiError::RequestRejected {
        status: StatusCode::METHOD_NOT_ALLOWED,
        message: "method not allowed".to_string(),
    }
}

/// JSON extractor whose failures use the API's JSON error contract.
#[derive(Debug)]
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|error| ApiError::from_rejection(error.status(), error.body_text()))
    }
}

/// Optional JSON is absent only when the request has no Content-Type header.
/// Once a client claims to send JSON, malformed/empty JSON is rejected normally.
#[derive(Debug)]
pub struct ApiOptionalJson<T>(pub Option<T>);

impl<S, T> FromRequest<S> for ApiOptionalJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !request.headers().contains_key(header::CONTENT_TYPE) {
            let declared_body = request
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|length| length > 0)
                || request.headers().contains_key(header::TRANSFER_ENCODING);
            if declared_body {
                return Err(ApiError::from_rejection(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "expected Content-Type: application/json".to_string(),
                ));
            }
            return Ok(Self(None));
        }
        ApiJson::<T>::from_request(request, state)
            .await
            .map(|ApiJson(value)| Self(Some(value)))
    }
}

/// Path and query wrappers keep all extractor failures in the same JSON envelope.
#[derive(Debug)]
pub struct ApiPath<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|error| ApiError::from_rejection(error.status(), error.body_text()))
    }
}

#[derive(Debug)]
pub struct ApiQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|error| ApiError::from_rejection(error.status(), error.body_text()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};

    #[test]
    fn runtime_errors_have_a_safe_public_message() {
        let error = ApiError::Runtime(
            "docker failed; recent logs: password=hunter2 /var/lib/private".to_string(),
        );

        assert_eq!(error.public_message(), "internal server error");
        assert_eq!(error.code(), "internal_error");
    }

    #[test]
    fn accepted_at_uses_the_shared_async_contract() {
        let response = ApiResponse::accepted_at(serde_json::json!({"queued": true}), "/jobs/1")
            .into_response();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()[header::LOCATION], "/jobs/1");
    }

    #[tokio::test]
    async fn runtime_response_contains_only_an_opaque_error_id() {
        let response = ApiError::Runtime(
            "docker failed; recent logs: password=hunter2 /var/lib/private".to_string(),
        )
        .into_response();
        let error_id = response.headers()["x-error-id"]
            .to_str()
            .unwrap()
            .to_string();
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["error"], "internal server error");
        assert_eq!(body["code"], "internal_error");
        assert_eq!(body["error_id"], error_id);
        assert!(!body.to_string().contains("hunter2"));
        assert!(!body.to_string().contains("/var/lib/private"));
    }

    #[tokio::test]
    async fn optional_json_rejects_a_declared_body_without_content_type() {
        let request = Request::builder()
            .header(header::CONTENT_LENGTH, "2")
            .body(Body::from("{}"))
            .unwrap();

        let error = ApiOptionalJson::<serde_json::Value>::from_request(request, &())
            .await
            .unwrap_err();

        assert_eq!(error.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
}
