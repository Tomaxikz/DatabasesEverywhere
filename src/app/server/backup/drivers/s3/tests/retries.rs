use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{Method, header};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::*;

#[tokio::test]
async fn retry_crossing_midnight_signs_with_the_new_date() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let seen = Arc::new(Mutex::new(Vec::new()));
    let headers = seen.clone();
    let app = Router::new().fallback(move |req: Request| {
        let mut requests = headers.lock().expect("lock should succeed");
        requests.push(req.headers().clone());
        let status = if requests.len() == 1 {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        };
        async move { status }
    });
    let mut driver = wire::driver(app, 1, 5).await;
    Arc::get_mut(&mut driver.client)
        .context("expected a value from get_mut")?
        .signing_time = || {
        static ATTEMPT: AtomicUsize = AtomicUsize::new(0);
        UNIX_EPOCH
            + Duration::from_secs(1369353599 + ATTEMPT.fetch_add(1, Ordering::Relaxed) as u64)
    };
    driver.delete_object("archive", false).await?;
    let headers = seen
        .lock()
        .map_err(|_| anyhow::anyhow!("test mutex was poisoned"))?;
    assert_eq!(headers.len(), 2);
    for (headers, date) in headers.iter().zip(["20130523T235959Z", "20130524T000000Z"]) {
        assert_eq!(headers["x-amz-date"], date);
        assert!(
            headers[header::AUTHORIZATION]
                .to_str()?
                .contains(&format!("/{}/eu-west-1/", &date[..8]))
        );
    }

    Ok(())
}

#[tokio::test]
async fn http2_peer_refusals_replay_with_no_application_retries() -> anyhow::Result<()> {
    for goaway in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let received = Arc::new(AtomicUsize::new(0));
        let count = received.clone();
        let peer = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.expect("accept should succeed");
                let count = count.clone();
                tokio::spawn(async move {
                    let mut preface = [0; 24];
                    socket
                        .read_exact(&mut preface)
                        .await
                        .expect("read exact should succeed");
                    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
                    socket
                        .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
                        .await
                        .expect("write all should succeed"); // SETTINGS
                    let mut frame = [0; 9];
                    while socket.read_exact(&mut frame).await.is_ok() {
                        let length = u32::from_be_bytes([0, frame[0], frame[1], frame[2]]) as usize;
                        socket
                            .read_exact(&mut vec![0; length])
                            .await
                            .expect("read exact should succeed");
                        if frame[3] == 4 && frame[4] == 0 {
                            socket
                                .write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0])
                                .await
                                .expect("write all should succeed");
                        }
                        if frame[3] != 1 {
                            continue;
                        } // HEADERS
                        if count.fetch_add(1, Ordering::SeqCst) == 0 {
                            if goaway {
                                // No stream processed, GOAWAY(NO_ERROR).
                                socket
                                    .write_all(&[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                                    .await
                                    .expect("write all should succeed");
                            } else {
                                frame[..5].copy_from_slice(&[0, 0, 4, 3, 0]); // RST_STREAM
                                socket
                                    .write_all(&frame)
                                    .await
                                    .expect("write all should succeed");
                                socket
                                    .write_all(&7u32.to_be_bytes())
                                    .await
                                    .expect("to be bytes should succeed"); // REFUSED_STREAM
                            }
                        } else {
                            frame[..5].copy_from_slice(&[0, 0, 1, 1, 5]); // END_HEADERS | END_STREAM
                            socket
                                .write_all(&frame)
                                .await
                                .expect("write all should succeed");
                            socket
                                .write_all(&[0x88])
                                .await
                                .expect("write all should succeed"); // HPACK :status 200
                        }
                    }
                });
            }
        });
        let config = BackupS3Config {
            allow_http: true,
            max_retries: 0,
            request_timeout_seconds: 5,
            ..config()
        };
        let client = S3Client::with_builder(
            &config,
            client::credentials(&config)?,
            endpoint,
            crate::utils::tls::http_client_builder().http2_prior_knowledge(),
        )?;
        let response = client
            .send(Method::GET, "archive", &[], Bytes::new(), "test")
            .await?;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(received.load(Ordering::SeqCst), 2);
        peer.abort();
    }

    Ok(())
}
