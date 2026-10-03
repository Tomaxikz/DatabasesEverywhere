use super::*;
use crate::commands::bench::http::{
    accumulator::PhaseAccumulator, jobs::rfc3339_duration_ms, websocket::websocket_accept,
};
use axum::Router;
use serde_json::json;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn rejects_api_urls_that_could_leak_credentials() {
    assert!(validate_base_url("https://user:secret@example.com").is_err());
    assert!(validate_base_url("ftp://example.com").is_err());
    assert!(validate_base_url("https://example.com/api").is_err());
    assert!(validate_base_url("https://example.com").is_ok());
}

#[test]
fn truncates_and_flattens_http_errors() {
    let error = format_http_error(500, b"line one\nline two");

    assert_eq!(error, "HTTP 500: line one line two");
}

#[test]
fn derives_server_job_duration_from_persisted_timestamps() {
    assert_eq!(
        rfc3339_duration_ms("2026-01-01T00:00:00Z", "2026-01-01T00:00:01.250Z"),
        Some(1_250.0)
    );
}

#[test]
fn derives_rfc_websocket_accept_value() {
    assert_eq!(
        websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
}

#[tokio::test]
async fn measures_a_real_http_upgrade_without_waiting_for_socket_close() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0_u8; 8 * 1024];
        let read = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..read]).into_owned();
        let lowercase_request = request.to_ascii_lowercase();
        assert!(lowercase_request.contains("upgrade: websocket"));
        assert!(lowercase_request.contains("authorization: bearer websocket-jwt"));
        let key = request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("sec-websocket-key")
                    .then_some(value.trim())
            })
            .unwrap();
        let accept = websocket_accept(key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             Sec-WebSocket-Protocol: dbe.jwt\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let client =
        BenchClient::new(&format!("http://{address}"), None, "node-token", 1, false).unwrap();

    let sample = tokio::time::timeout(
        Duration::from_secs(1),
        client.websocket_handshake("websocket-jwt", 0),
    )
    .await
    .unwrap();

    assert!(sample.success, "{:?}", sample.error);
    server.abort();
}

#[tokio::test]
async fn runs_a_duration_based_mixed_load() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(|| async { axum::Json(json!({"status": "running"})) }),
        )
        .await
        .unwrap();
    });
    let client =
        BenchClient::new(&format!("http://{address}"), None, "node-token", 4, false).unwrap();

    let run = client
        .benchmark_concurrency(
            Duration::from_millis(50),
            4,
            vec![LoadTarget::instance_status("selected-db")],
            42,
            None,
        )
        .await;

    assert!(run.report.wall_duration_ms >= 40.0);
    assert!(run.report.attempted_requests >= 2);
    assert!(run.report.target_requests.contains_key("/api/heartbeat"));
    assert!(
        run.report
            .target_requests
            .contains_key("/api/instances/selected-db/status")
    );
    assert_eq!(
        run.report.attempted_requests,
        run.report.successful_requests
    );
    server.abort();
}

#[test]
fn concurrent_aggregate_bounds_raw_samples_without_losing_totals() {
    let attempted = MAX_RETAINED_REQUEST_SAMPLES + 17;
    let mut accumulator = PhaseAccumulator::new(7);
    for index in 0..attempted {
        accumulator.record(RequestSample {
            phase: "http_concurrent_timed".to_string(),
            target: "/api/heartbeat".to_string(),
            index,
            duration_micros: 1_000,
            status_code: Some(200),
            success: true,
            error: None,
        });
    }

    let run = accumulator.finish(
        "http_concurrent_timed",
        Duration::from_secs(1),
        Duration::from_secs(1),
    );

    assert_eq!(run.report.attempted_requests, attempted);
    assert_eq!(run.report.successful_requests, attempted);
    assert_eq!(run.samples.len(), MAX_RETAINED_REQUEST_SAMPLES);
    assert_eq!(run.report.dropped_request_samples, 17);
    assert_eq!(run.report.all_latency_ms.unwrap().samples, attempted);
}

#[tokio::test]
async fn fixed_window_pacing_bounds_a_timed_burst() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(|| async { axum::Json(json!({"status": "running"})) }),
        )
        .await
        .unwrap();
    });
    let client =
        BenchClient::new(&format!("http://{address}"), None, "node-token", 4, false).unwrap();

    let run = client
        .benchmark_concurrency(
            Duration::from_millis(50),
            4,
            vec![LoadTarget::heartbeat()],
            42,
            Some(FixedWindowPacing {
                window_started: Instant::now(),
                requests_per_window: 8,
            }),
        )
        .await;

    assert_eq!(run.report.attempted_requests, 8);
    assert!(run.report.active_load_duration_ms < run.report.wall_duration_ms);
    assert!(
        run.report.active_successful_requests_per_second
            > run.report.successful_requests_per_second
    );
    server.abort();
}
