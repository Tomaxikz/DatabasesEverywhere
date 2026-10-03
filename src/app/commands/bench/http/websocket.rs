use std::time::Instant;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::{StreamExt, stream};
use reqwest::{
    Method, StatusCode,
    header::{AUTHORIZATION, CONNECTION, HOST, HeaderValue, UPGRADE},
};
use serde_json::json;
use sha1::{Digest, Sha1};

use super::{BenchClient, WEBSOCKET_TARGET, WebSocketRun, duration_micros};
use crate::commands::bench::metrics::{HttpPhaseReport, RequestSample, WebSocketBenchmarkReport};

impl BenchClient {
    pub(in crate::commands::bench) async fn benchmark_websockets(
        &self,
        count: usize,
        concurrency: usize,
        benchmark_id: &str,
    ) -> WebSocketRun {
        let token_started = Instant::now();
        let mut token_samples = Vec::with_capacity(count);
        let mut tokens = Vec::with_capacity(count);
        for index in 0..count {
            let body = json!({
                "subject": format!("dbev-benchmark-{benchmark_id}-{index}"),
                "scopes": ["monitor:read"],
                "instances": [],
                "all_instances": true,
                "ttl_seconds": 60
            });
            let mut response = self
                .request(
                    Method::POST,
                    "/api/ws-token",
                    Some(body),
                    "websocket_token",
                    index,
                )
                .await;
            if response.sample.success {
                match response
                    .json()
                    .ok()
                    .and_then(|value| value["token"].as_str().map(str::to_string))
                {
                    Some(token) => tokens.push((index, token)),
                    None => {
                        response.sample.success = false;
                        response.sample.error =
                            Some("WebSocket token response did not contain token".to_string());
                    }
                }
            }
            token_samples.push(response.sample);
        }
        let token_report = HttpPhaseReport::from_samples(
            "websocket_token",
            token_started.elapsed(),
            &token_samples,
        );

        let handshake_started = Instant::now();
        let handshake_samples = stream::iter(tokens)
            .map(|(index, token)| {
                let client = self.clone();
                async move { client.websocket_handshake(&token, index).await }
            })
            .buffer_unordered(concurrency.max(1))
            .collect::<Vec<_>>()
            .await;
        let handshake_report = HttpPhaseReport::from_samples(
            "websocket_handshake",
            handshake_started.elapsed(),
            &handshake_samples,
        );

        let mut samples = token_samples;
        samples.extend(handshake_samples);
        WebSocketRun {
            report: WebSocketBenchmarkReport {
                token_mint: token_report,
                handshake: handshake_report,
            },
            samples,
        }
    }

    pub(super) async fn websocket_handshake(&self, token: &str, index: usize) -> RequestSample {
        let started = Instant::now();
        let key = STANDARD.encode(uuid::Uuid::new_v4().as_bytes());
        let expected_accept = websocket_accept(&key);
        let mut request = self
            .websocket_client
            .get(self.endpoint(WEBSOCKET_TARGET))
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", key)
            .header("sec-websocket-protocol", "dbe.jwt");
        if let Some(host) = &self.host_header {
            request = request.header(HOST, host.clone());
        }
        let finish_sample =
            |status_code: Option<u16>, success: bool, error: Option<String>| RequestSample {
                phase: "websocket_handshake".to_string(),
                target: WEBSOCKET_TARGET.to_string(),
                index,
                duration_micros: duration_micros(started.elapsed()),
                status_code,
                success,
                error,
            };
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => return finish_sample(None, false, Some(error.to_string())),
        };
        let status = response.status().as_u16();
        let selected_protocol = response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok());
        let accept_matches = response
            .headers()
            .get("sec-websocket-accept")
            .and_then(|value| value.to_str().ok())
            == Some(expected_accept.as_str());
        let upgrade_matches = header_contains_token(response.headers().get(UPGRADE), "websocket");
        let connection_upgraded =
            header_contains_token(response.headers().get(CONNECTION), "upgrade");
        let success = status == StatusCode::SWITCHING_PROTOCOLS.as_u16()
            && selected_protocol == Some("dbe.jwt")
            && accept_matches
            && upgrade_matches
            && connection_upgraded;
        let error = (!success).then(|| {
            format!(
                "WebSocket upgrade returned HTTP {status} (protocol={selected_protocol:?}, valid_accept={accept_matches}, upgrade={upgrade_matches}, connection_upgrade={connection_upgraded})"
            )
        });
        drop(response);
        finish_sample(Some(status), success, error)
    }
}

pub(super) fn websocket_accept(key: &str) -> String {
    const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(WEBSOCKET_GUID.as_bytes());
    STANDARD.encode(digest.finalize())
}

fn header_contains_token(value: Option<&HeaderValue>, expected: &str) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
}
