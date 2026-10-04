use std::{collections::BTreeMap, path::Path, time::Duration};

use reqwest::{
    Client, Method, StatusCode,
    header::{CONTENT_TYPE, HeaderValue},
    multipart::{Form, Part},
    redirect::Policy,
};

use secrecy::ExposeSecret;

use serde_json::{Value, json};

use tokio::io::AsyncWriteExt;

use crate::{
    databases::protocol::Protocol,
    routes::http::{response::ApiError, router::AppState},
    server::paths::InstancePaths,
};

use super::{
    super::super::RemoteImportSource,
    HOST_BRIDGE_SOCKET_NAME, MAX_JSON_RESPONSE_BYTES, MAX_QDRANT_ALIASES, MAX_QDRANT_COLLECTIONS,
    compat::topology_is_standalone,
    selection::{QdrantAlias, valid_qdrant_name},
};

pub(super) struct QdrantHttp {
    pub(super) client: Client,
    pub(super) base_url: String,
    pub(super) api_key: Option<HeaderValue>,
    pub(super) source: bool,
}

impl QdrantHttp {
    pub(super) fn source(
        source: &RemoteImportSource,
        policy: &crate::config::RemoteImportSecurityConfig,
    ) -> Result<Self, ApiError> {
        let mut builder = Client::builder()
            .tls_certs_only(crate::utils::tls::mozilla_root_certificates())
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(policy.connect_timeout_seconds))
            .timeout(Duration::from_secs(policy.operation_timeout_seconds))
            .https_only(source.endpoint.tls);
        builder =
            builder.resolve_to_addrs(&source.endpoint.host, source.endpoint.addresses.as_slice());
        let client = builder
            .build()
            .map_err(|_| ApiError::Runtime("failed to build qdrant source client".to_string()))?;
        let host = if source.endpoint.host.contains(':') {
            format!("[{}]", source.endpoint.host)
        } else {
            source.endpoint.host.clone()
        };
        let scheme = if source.endpoint.tls { "https" } else { "http" };
        Ok(Self {
            client,
            base_url: format!("{scheme}://{host}:{}", source.endpoint.port),
            api_key: secret_header(source.api_key.as_ref())?,
            source: true,
        })
    }

    pub(super) fn target(
        paths: &InstancePaths,
        api_key: &secrecy::SecretString,
        timeout: Duration,
    ) -> Result<Self, ApiError> {
        let client = Client::builder()
            .tls_certs_only(crate::utils::tls::mozilla_root_certificates())
            .no_proxy()
            .redirect(Policy::none())
            .timeout(timeout)
            .unix_socket(paths.sockets.join(HOST_BRIDGE_SOCKET_NAME))
            .build()
            .map_err(|_| ApiError::Runtime("failed to build managed qdrant client".to_string()))?;
        let mut header = HeaderValue::from_str(api_key.expose_secret()).map_err(|_| {
            ApiError::Runtime("managed qdrant API key is not a valid HTTP header".to_string())
        })?;
        header.set_sensitive(true);
        Ok(Self {
            client,
            base_url: "http://qdrant.internal".to_string(),
            api_key: Some(header),
            source: false,
        })
    }

    pub(super) async fn version(&self) -> Result<String, ApiError> {
        let json = self.json(Method::GET, "/", None).await?;
        json.get("version")
            .and_then(Value::as_str)
            .or_else(|| json.pointer("/result/version").and_then(Value::as_str))
            .map(ToString::to_string)
            .ok_or_else(|| self.bad_response("qdrant did not report its version"))
    }

    pub(super) async fn check_standalone(&self) -> Result<(), ApiError> {
        let json = self.json(Method::GET, "/cluster", None).await?;
        match topology_is_standalone(&json) {
            Some(true) => Ok(()),
            Some(false) if self.source => Err(ApiError::BadRequest(
                "remote qdrant distributed mode is unsupported because a snapshot from one endpoint can omit shards held by other nodes; use a standalone source or Qdrant's distributed migration tooling"
                    .to_string(),
            )),
            Some(false) => Err(ApiError::Runtime(
                "managed qdrant target unexpectedly has distributed mode enabled; remote snapshot import requires a standalone target"
                    .to_string(),
            )),
            None => Err(self.bad_response(
                "qdrant returned an invalid cluster topology response",
            )),
        }
    }

    pub(super) async fn collections(&self) -> Result<Vec<String>, ApiError> {
        let json = self.json(Method::GET, "/collections", None).await?;
        let collections = json
            .pointer("/result/collections")
            .and_then(Value::as_array)
            .ok_or_else(|| self.bad_response("qdrant returned an invalid collection list"))?;
        if collections.len() > MAX_QDRANT_COLLECTIONS {
            return Err(
                self.bad_response("qdrant collection count exceeds the supported import limit")
            );
        }
        let mut names = Vec::with_capacity(collections.len());
        for collection in collections {
            let name = collection
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| self.bad_response("qdrant collection response is missing a name"))?;
            if !valid_qdrant_name(name) {
                return Err(self.bad_response("qdrant returned an invalid collection name"));
            }
            names.push(name.to_string());
        }
        Ok(names)
    }

    pub(super) async fn aliases(&self) -> Result<Vec<QdrantAlias>, ApiError> {
        let json = self.json(Method::GET, "/aliases", None).await?;
        let aliases = json
            .pointer("/result/aliases")
            .and_then(Value::as_array)
            .ok_or_else(|| self.bad_response("qdrant returned an invalid alias list"))?;
        if aliases.len() > MAX_QDRANT_ALIASES {
            return Err(self.bad_response("qdrant alias count exceeds the supported import limit"));
        }
        let mut mappings = BTreeMap::new();
        for alias in aliases {
            let alias_name = alias
                .get("alias_name")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    self.bad_response("qdrant alias response is missing an alias name")
                })?;
            let collection_name = alias
                .get("collection_name")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    self.bad_response("qdrant alias response is missing a collection name")
                })?;
            if !valid_qdrant_name(alias_name) || !valid_qdrant_name(collection_name) {
                return Err(self.bad_response("qdrant returned an invalid alias mapping"));
            }
            if mappings
                .insert(alias_name.to_string(), collection_name.to_string())
                .is_some()
            {
                return Err(self.bad_response("qdrant returned duplicate alias names"));
            }
        }
        Ok(mappings
            .into_iter()
            .map(|(alias_name, collection_name)| QdrantAlias {
                alias_name,
                collection_name,
            })
            .collect())
    }

    pub(super) async fn update_aliases(&self, actions: Vec<Value>) -> Result<(), ApiError> {
        if actions.is_empty() {
            return Ok(());
        }
        self.json(
            Method::POST,
            "/collections/aliases?timeout=120",
            Some(json!({ "actions": actions })),
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn create_snapshot(&self, collection: &str) -> Result<String, ApiError> {
        let path = format!(
            "/collections/{}/snapshots?wait=true",
            encode_path_segment(collection)
        );
        let json = self.json(Method::POST, &path, None).await?;
        json.pointer("/result/name")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .ok_or_else(|| self.bad_response("qdrant did not return a snapshot name"))
    }

    pub(super) async fn delete_snapshot(
        &self,
        collection: &str,
        snapshot: &str,
    ) -> Result<(), ApiError> {
        let path = format!(
            "/collections/{}/snapshots/{}?wait=true",
            encode_path_segment(collection),
            encode_path_segment(snapshot)
        );
        self.json(Method::DELETE, &path, None).await.map(|_| ())
    }

    pub(super) async fn delete_collection(&self, collection: &str) -> Result<(), ApiError> {
        let path = format!(
            "/collections/{}?timeout=120",
            encode_path_segment(collection)
        );
        self.json(Method::DELETE, &path, None).await.map(|_| ())
    }

    pub(super) async fn download_snapshot(
        &self,
        collection: &str,
        snapshot: &str,
        path: &Path,
        max_bytes: u64,
    ) -> Result<u64, ApiError> {
        let endpoint = format!(
            "/collections/{}/snapshots/{}",
            encode_path_segment(collection),
            encode_path_segment(snapshot)
        );
        let mut request = self.client.get(self.url(&endpoint));
        if let Some(key) = self.api_key.as_ref() {
            request = request.header("api-key", key.clone());
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| self.request_error("download snapshot", error))?;
        if !response.status().is_success() {
            return Err(self.status_error("download snapshot", response.status()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes)
        {
            return Err(ApiError::BadRequest(format!(
                "qdrant snapshot exceeds the remaining {max_bytes}-byte staging limit"
            )));
        }
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut output = options.open(path).await.map_err(|error| {
            ApiError::Runtime(format!(
                "failed to create qdrant snapshot staging file: {error}"
            ))
        })?;
        let mut total = 0_u64;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| self.request_error("read snapshot", error))?
        {
            total = total.checked_add(chunk.len() as u64).ok_or_else(|| {
                ApiError::BadRequest("qdrant snapshot size overflowed".to_string())
            })?;
            if total > max_bytes {
                let _ = tokio::fs::remove_file(path).await;
                return Err(ApiError::BadRequest(format!(
                    "qdrant snapshot exceeds the remaining {max_bytes}-byte staging limit"
                )));
            }
            output.write_all(&chunk).await.map_err(|error| {
                ApiError::Runtime(format!("failed to stage qdrant snapshot: {error}"))
            })?;
        }
        output.sync_all().await.map_err(|error| {
            ApiError::Runtime(format!("failed to sync qdrant snapshot: {error}"))
        })?;
        if total == 0 {
            drop(output);
            let _ = tokio::fs::remove_file(path).await;
            return Err(self.bad_response("qdrant returned an empty snapshot"));
        }
        Ok(total)
    }

    pub(super) async fn upload_snapshot(
        &self,
        collection: &str,
        path: &Path,
    ) -> Result<(), ApiError> {
        let part = Part::file(path).await.map_err(|error| {
            ApiError::Runtime(format!("failed to open staged qdrant snapshot: {error}"))
        })?;
        let form = Form::new().part("snapshot", part);
        let endpoint = format!(
            "/collections/{}/snapshots/upload?priority=snapshot&wait=true",
            encode_path_segment(collection)
        );
        let mut request = self.client.post(self.url(&endpoint)).multipart(form);
        if let Some(key) = self.api_key.as_ref() {
            request = request.header("api-key", key.clone());
        }
        let response = request
            .send()
            .await
            .map_err(|error| self.request_error("upload snapshot", error))?;
        if !response.status().is_success() {
            return Err(self.status_error("upload snapshot", response.status()));
        }
        Ok(())
    }

    pub(super) async fn json(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, ApiError> {
        let mut request = self.client.request(method, self.url(path));
        if let Some(key) = self.api_key.as_ref() {
            request = request.header("api-key", key.clone());
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").json(&body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| self.request_error("API request", error))?;
        if !response.status().is_success() {
            return Err(self.status_error("API request", response.status()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| self.request_error("read API response", error))?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_JSON_RESPONSE_BYTES {
                return Err(self.bad_response("qdrant API response was too large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| self.bad_response("qdrant returned invalid JSON"))
    }

    pub(super) fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub(super) fn request_error(&self, operation: &str, error: reqwest::Error) -> ApiError {
        if self.source {
            ApiError::BadRequest(format!(
                "remote qdrant {operation} failed: {}",
                safe_reqwest_error(&error)
            ))
        } else {
            ApiError::Runtime(format!(
                "managed qdrant {operation} failed: {}",
                safe_reqwest_error(&error)
            ))
        }
    }

    pub(super) fn status_error(&self, operation: &str, status: StatusCode) -> ApiError {
        if self.source {
            ApiError::BadRequest(format!(
                "remote qdrant {operation} returned HTTP {}",
                status.as_u16()
            ))
        } else {
            ApiError::Runtime(format!(
                "managed qdrant {operation} returned HTTP {}",
                status.as_u16()
            ))
        }
    }

    pub(super) fn bad_response(&self, message: &str) -> ApiError {
        if self.source {
            ApiError::BadRequest(format!("remote {message}"))
        } else {
            ApiError::Runtime(format!("managed {message}"))
        }
    }
}

pub(super) async fn target_api_key(
    state: &AppState,
    instance_id: &str,
) -> Result<secrecy::SecretString, ApiError> {
    let output = state
        .docker
        .exec(
            Protocol::Qdrant,
            instance_id,
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%s' \"$QDRANT__SERVICE__API_KEY\"".to_string(),
            ],
        )
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to access managed qdrant credentials: {error}"
            ))
        })?;
    let key = output.stdout;
    if key.is_empty() || key.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(ApiError::Runtime(
            "managed qdrant API key is unavailable".to_string(),
        ));
    }
    Ok(secrecy::SecretString::from(key))
}

pub(super) fn secret_header(
    secret: Option<&secrecy::SecretString>,
) -> Result<Option<HeaderValue>, ApiError> {
    let Some(secret) = secret else {
        return Ok(None);
    };
    let mut value = HeaderValue::from_str(secret.expose_secret()).map_err(|_| {
        ApiError::BadRequest(
            "source.api_key contains characters that are invalid in an HTTP header".to_string(),
        )
    })?;
    value.set_sensitive(true);
    Ok(Some(value))
}

pub(super) fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

pub(super) fn safe_reqwest_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_decode() {
        "response decoding failed"
    } else {
        "request failed"
    }
}
