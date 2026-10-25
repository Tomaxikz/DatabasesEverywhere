//! Minimal ClickHouse HTTP client over the instance's always-on HTTP socket.

use std::{path::Path, time::Duration};

use reqwest::{Client, header::HeaderValue, redirect::Policy};
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;

use crate::subsystems::backups::strategy::StrategyError;

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ERROR_CHARS: usize = 300;

/// A failed query, with ClickHouse's error code when the server sent one.
#[derive(Debug)]
pub(super) struct QueryError {
    pub code: Option<u32>,
    pub message: String,
}

impl From<QueryError> for StrategyError {
    fn from(error: QueryError) -> Self {
        Self::Failed(format!("clickhouse: {}", error.message))
    }
}

pub(super) struct ClickhouseHttp {
    client: Client,
    user: HeaderValue,
    key: HeaderValue,
}

impl ClickhouseHttp {
    pub(super) fn new(
        socket: &Path,
        user: &str,
        password: &SecretString,
        timeout: Duration,
    ) -> Result<Self, StrategyError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(timeout)
            .unix_socket(socket)
            .build()
            .map_err(|error| StrategyError::failed("build the clickhouse client", error))?;
        let user = HeaderValue::from_str(user).map_err(|_| {
            StrategyError::Unsupported(
                "the clickhouse username is not a valid HTTP header".to_string(),
            )
        })?;
        let mut key = HeaderValue::from_str(password.expose_secret()).map_err(|_| {
            StrategyError::Unsupported(
                "the clickhouse password is not a valid HTTP header".to_string(),
            )
        })?;
        key.set_sensitive(true);
        Ok(Self { client, user, key })
    }

    /// Runs one statement and returns the whole response body.
    pub(super) async fn query(&self, sql: &str) -> Result<String, QueryError> {
        let mut response = self
            .client
            .post("http://clickhouse.internal/?wait_end_of_query=1")
            .header("X-ClickHouse-User", self.user.clone())
            .header("X-ClickHouse-Key", self.key.clone())
            .body(sql.to_string())
            .send()
            .await
            .map_err(transport_error)?;
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(QueryError {
                    code: None,
                    message: "the response was too large".to_string(),
                });
            }
            body.extend_from_slice(&chunk);
        }
        let text = String::from_utf8_lossy(&body).into_owned();
        if status.is_success() {
            return Ok(text);
        }
        Err(QueryError {
            code: error_code(&text),
            message: format!("HTTP {}: {}", status.as_u16(), summarize(&text)),
        })
    }

    /// Runs a `FORMAT JSONEachRow` query and decodes every row.
    pub(super) async fn rows<T: DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>, QueryError> {
        self.query(sql)
            .await?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line).map_err(|error| QueryError {
                    code: None,
                    message: format!("unexpected row: {error}"),
                })
            })
            .collect()
    }
}

fn transport_error(error: reqwest::Error) -> QueryError {
    let reason = if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "could not connect to the instance's HTTP socket"
    } else {
        "request failed"
    };
    QueryError {
        code: None,
        message: reason.to_string(),
    }
}

/// `Code: 60. DB::Exception: ...` → 60.
pub(super) fn error_code(body: &str) -> Option<u32> {
    let rest = body.trim_start().strip_prefix("Code: ")?;
    rest.split(|byte: char| !byte.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

fn summarize(body: &str) -> String {
    body.lines()
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_ERROR_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_come_from_the_exception_prefix() {
        assert_eq!(
            error_code("Code: 60. DB::Exception: Table db.t does not exist. (UNKNOWN_TABLE)"),
            Some(60)
        );
        assert_eq!(error_code("Code: 81."), Some(81));
        assert_eq!(error_code("something else"), None);
        assert_eq!(summarize("first\u{7}line\nsecond"), "firstline");
    }
}
