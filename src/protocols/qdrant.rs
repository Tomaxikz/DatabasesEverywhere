use bytes::Bytes;
use h2::{
    RecvStream, SendStream,
    client::{SendRequest, SendRequest as H2SendRequest},
    server::SendResponse,
};
use http::{Request, Response};
use sha2::{Digest, Sha256};
use std::{future::Future, future::poll_fn, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

const API_KEY_HEADER: &str = "api-key";
const MAX_CONCURRENT_STREAMS: u32 = 128;
const MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;
const MAX_SEND_BUFFER_SIZE: usize = 64 * 1024;
const STREAM_STALL_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum QdrantProxyError {
    #[error("qdrant grpc handshake failed: {0}")]
    H2(#[from] h2::Error),
    #[error("qdrant grpc request missing api-key metadata")]
    MissingApiKey,
    #[error("qdrant grpc api-key metadata is invalid")]
    InvalidApiKey,
    #[error("qdrant grpc stream admission or outbound flow-control stalled for {timeout_secs}s")]
    InactivityTimeout { timeout_secs: u64 },
    #[error("qdrant grpc outbound stream closed while waiting for flow-control capacity")]
    OutboundStreamClosed,
    #[error("qdrant grpc peer reset the rpc stream: {reason:?}")]
    StreamReset { reason: h2::Reason },
}

impl QdrantProxyError {
    pub(crate) fn is_stream_local(&self) -> bool {
        matches!(
            self,
            Self::InactivityTimeout { .. } | Self::OutboundStreamClosed | Self::StreamReset { .. }
        ) || matches!(self, Self::H2(error) if error.is_reset())
    }

    fn stream_reset_reason(&self) -> Option<h2::Reason> {
        match self {
            Self::InactivityTimeout { .. } | Self::OutboundStreamClosed => Some(h2::Reason::CANCEL),
            Self::StreamReset { reason } => Some(*reason),
            Self::H2(error) if error.is_reset() => {
                Some(error.reason().unwrap_or(h2::Reason::CANCEL))
            }
            _ => None,
        }
    }

    fn is_outbound_stream_reset(&self) -> bool {
        matches!(self, Self::StreamReset { .. })
    }
}

fn outbound_stream_error(error: h2::Error) -> QdrantProxyError {
    if error.is_reset() {
        QdrantProxyError::StreamReset {
            reason: error.reason().unwrap_or(h2::Reason::CANCEL),
        }
    } else {
        QdrantProxyError::H2(error)
    }
}

pub fn route_key_sha256(api_key: &str) -> String {
    let digest = Sha256::digest(api_key.as_bytes());
    format!("{digest:x}")
}

pub fn api_key_from_request(request: &Request<RecvStream>) -> Result<String, QdrantProxyError> {
    request
        .headers()
        .get(API_KEY_HEADER)
        .ok_or(QdrantProxyError::MissingApiKey)?
        .to_str()
        .map(str::to_string)
        .map_err(|_| QdrantProxyError::InvalidApiKey)
}

pub async fn server_handshake<S>(
    stream: S,
) -> Result<h2::server::Connection<S, Bytes>, QdrantProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .max_header_list_size(MAX_HEADER_LIST_SIZE)
        .max_send_buffer_size(MAX_SEND_BUFFER_SIZE);
    Ok(builder.handshake(stream).await?)
}

pub async fn client_handshake<S>(stream: S) -> Result<SendRequest<Bytes>, QdrantProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::client::Builder::new();
    builder
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .initial_max_send_streams(MAX_CONCURRENT_STREAMS as usize)
        .max_header_list_size(MAX_HEADER_LIST_SIZE)
        .max_send_buffer_size(MAX_SEND_BUFFER_SIZE);
    let (send_request, connection) = builder.handshake(stream).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "qdrant backend h2 connection stopped");
        }
    });
    Ok(send_request)
}

pub async fn proxy_request(
    request: Request<RecvStream>,
    respond: SendResponse<Bytes>,
    backend: &mut H2SendRequest<Bytes>,
) -> Result<(), QdrantProxyError> {
    proxy_request_with_stall_timeout(request, respond, backend, STREAM_STALL_TIMEOUT).await
}

async fn proxy_request_with_stall_timeout(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    backend: &mut H2SendRequest<Bytes>,
    stall_timeout: Duration,
) -> Result<(), QdrantProxyError> {
    let result = proxy_request_inner(request, &mut respond, backend, stall_timeout).await;
    if let Err(error) = &result
        && let Some(reason) = error.stream_reset_reason()
    {
        respond.send_reset(reason);
    }
    result
}

async fn proxy_request_inner(
    request: Request<RecvStream>,
    respond: &mut SendResponse<Bytes>,
    backend: &mut H2SendRequest<Bytes>,
    stall_timeout: Duration,
) -> Result<(), QdrantProxyError> {
    let (parts, mut request_body) = request.into_parts();
    let request_without_body = Request::from_parts(parts, ());
    let request_end_stream = request_body.is_end_stream();
    await_bounded_activity(
        stall_timeout,
        poll_fn(|context| backend.poll_ready(context)),
    )
    .await??;
    let (response_future, mut request_send_stream) =
        backend.send_request(request_without_body, request_end_stream)?;

    // An HTTP/2 server may return a final response before the request body is
    // complete (and bidirectional gRPC streams routinely exchange frames in
    // both directions). Keep driving the upload while waiting for response
    // headers instead of serializing the two halves of the RPC.
    let mut request_pump = Box::pin(async move {
        if request_end_stream {
            Ok(())
        } else {
            forward_body(&mut request_body, &mut request_send_stream, stall_timeout).await
        }
    });
    let mut response_wait = Box::pin(response_future);
    let (response, request_finished) = tokio::select! {
        biased;
        result = &mut response_wait => (result?, false),
        result = &mut request_pump => {
            if let Err(error) = result
                && !error.is_outbound_stream_reset()
            {
                return Err(error);
            }
            (response_wait.await?, true)
        }
    };

    let (parts, mut response_body) = response.into_parts();
    let response_without_body: Response<()> = Response::from_parts(parts, ());
    let response_end_stream = response_body.is_end_stream();
    let mut response_send_stream =
        respond.send_response(response_without_body, response_end_stream)?;
    let response_pump = Box::pin(async move {
        if response_end_stream {
            Ok(())
        } else {
            forward_body(&mut response_body, &mut response_send_stream, stall_timeout).await
        }
    });

    if request_finished {
        response_pump.await?;
    } else {
        tokio::try_join!(request_pump, response_pump)?;
    }

    Ok(())
}

async fn forward_body(
    incoming: &mut RecvStream,
    outgoing: &mut SendStream<Bytes>,
    stall_timeout: Duration,
) -> Result<(), QdrantProxyError> {
    let mut sent_end_stream = false;

    // Waiting for application DATA or trailers is deliberately not timed out:
    // valid Qdrant operations and streaming RPCs may be idle for long periods.
    // The bounded timeout applies only after outbound flow control stops making
    // progress or a new backend stream cannot be admitted.
    loop {
        let chunk = tokio::select! {
            biased;
            reset = poll_fn(|context| outgoing.poll_reset(context)) => {
                let reason = match reset {
                    Ok(reason) => reason,
                    Err(error) if error.is_reset() => {
                        error.reason().unwrap_or(h2::Reason::CANCEL)
                    }
                    Err(error) => return Err(error.into()),
                };
                return Err(QdrantProxyError::StreamReset { reason });
            }
            chunk = incoming.data() => chunk,
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = chunk?;
        let received = chunk.len();
        let end_stream = incoming.is_end_stream();
        send_data_with_backpressure(outgoing, chunk, end_stream, stall_timeout).await?;
        incoming.flow_control().release_capacity(received)?;
        sent_end_stream = end_stream;
    }

    let trailers = tokio::select! {
        biased;
        reset = poll_fn(|context| outgoing.poll_reset(context)) => {
            let reason = match reset {
                Ok(reason) => reason,
                Err(error) if error.is_reset() => {
                    error.reason().unwrap_or(h2::Reason::CANCEL)
                }
                Err(error) => return Err(error.into()),
            };
            return Err(QdrantProxyError::StreamReset { reason });
        }
        trailers = incoming.trailers() => trailers?,
    };
    if let Some(trailers) = trailers {
        outgoing
            .send_trailers(trailers)
            .map_err(outbound_stream_error)?;
        sent_end_stream = true;
    }

    if !sent_end_stream {
        outgoing
            .send_data(Bytes::new(), true)
            .map_err(outbound_stream_error)?;
    }

    Ok(())
}

async fn send_data_with_backpressure(
    outgoing: &mut SendStream<Bytes>,
    mut chunk: Bytes,
    end_stream: bool,
    stall_timeout: Duration,
) -> Result<(), QdrantProxyError> {
    if chunk.is_empty() {
        outgoing
            .send_data(chunk, end_stream)
            .map_err(outbound_stream_error)?;
        return Ok(());
    }

    while !chunk.is_empty() {
        if outgoing.capacity() == 0 {
            outgoing.reserve_capacity(chunk.len());
            let capacity = await_bounded_activity(
                stall_timeout,
                poll_fn(|context| outgoing.poll_capacity(context)),
            )
            .await?;
            match capacity {
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(outbound_stream_error(error)),
                None => return Err(QdrantProxyError::OutboundStreamClosed),
            }
        }

        let frame_len = outgoing.capacity().min(chunk.len());
        if frame_len == 0 {
            continue;
        }
        let frame = chunk.split_to(frame_len);
        outgoing
            .send_data(frame, end_stream && chunk.is_empty())
            .map_err(outbound_stream_error)?;
    }

    Ok(())
}

async fn await_bounded_activity<F, T>(
    stall_timeout: Duration,
    future: F,
) -> Result<T, QdrantProxyError>
where
    F: Future<Output = T>,
{
    timeout(stall_timeout, future)
        .await
        .map_err(|_| QdrantProxyError::InactivityTimeout {
            timeout_secs: stall_timeout.as_secs(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Version;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn hashes_api_key_for_routing() {
        assert_eq!(
            route_key_sha256("secret"),
            "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
        );
    }

    #[tokio::test]
    async fn server_advertises_a_finite_concurrent_stream_limit() {
        let (client_io, server_io) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut server = server_handshake(server_io).await.unwrap();
            let _ = server.accept().await;
        });
        let (client, connection) = h2::client::handshake(client_io).await.unwrap();
        let client_driver = tokio::spawn(connection);
        let client = timeout(TEST_TIMEOUT, client.ready())
            .await
            .unwrap()
            .unwrap();
        timeout(TEST_TIMEOUT, async {
            while client.current_max_send_streams() == usize::MAX {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("client did not receive the server stream limit");

        assert_eq!(
            client.current_max_send_streams(),
            MAX_CONCURRENT_STREAMS as usize
        );

        drop(client);
        client_driver.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn server_rejects_header_lists_over_the_configured_limit() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server_task = tokio::spawn(async move {
            let mut server = server_handshake(server_io).await.unwrap();
            server.accept().await
        });
        let (client, connection) = h2::client::handshake(client_io).await.unwrap();
        let client_driver = tokio::spawn(connection);
        let mut client = client.ready().await.unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("http://qdrant.test/qdrant.Points/Upsert")
            .version(Version::HTTP_2)
            .header(
                "x-oversized-metadata",
                "x".repeat(MAX_HEADER_LIST_SIZE as usize + 1024),
            )
            .body(())
            .unwrap();

        match client.send_request(request, true) {
            Ok((response, _)) => {
                let result = timeout(TEST_TIMEOUT, response)
                    .await
                    .expect("client should observe the oversized header rejection");
                match result {
                    Ok(response) => assert_eq!(
                        response.status(),
                        http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                    ),
                    Err(error) => assert!(error.is_reset() || error.is_go_away()),
                }
                server_task.abort();
            }
            Err(_) => server_task.abort(),
        }

        client_driver.abort();
    }

    #[tokio::test]
    async fn proxy_releases_flow_control_for_large_request_and_response_bodies() {
        let request_body = vec![0x51; 4 * 65_535];
        let response_body = vec![0x52; 4 * 65_535];
        let (client_io, proxy_client_io) = tokio::io::duplex(8 * 1024);
        let (proxy_backend_io, backend_io) = tokio::io::duplex(8 * 1024);

        let backend_expected = request_body.clone();
        let backend_response = response_body.clone();
        let backend_task = tokio::spawn(async move {
            run_backend_once(backend_io, backend_expected, backend_response).await;
        });
        let proxy_task = tokio::spawn(async move {
            run_proxy_once(proxy_client_io, proxy_backend_io).await;
        });

        timeout(TEST_TIMEOUT, async move {
            let (client, connection) = h2::client::handshake(client_io).await.unwrap();
            let client_driver = tokio::spawn(connection);
            let mut client = client.ready().await.unwrap();
            let request = Request::builder()
                .method("POST")
                .uri("http://qdrant.test/qdrant.Points/Upsert")
                .version(Version::HTTP_2)
                .header(API_KEY_HEADER, "secret")
                .body(())
                .unwrap();
            let (response, mut body) = client.send_request(request, false).unwrap();
            send_data_with_backpressure(&mut body, Bytes::from(request_body), true, TEST_TIMEOUT)
                .await
                .unwrap();

            let response = response.await.unwrap();
            assert_eq!(read_body(response.into_body()).await, response_body);

            proxy_task.await.unwrap();
            backend_task.await.unwrap();
            client_driver.abort();
        })
        .await
        .expect("large bidirectional bodies should not stall at the H2 flow-control window");
    }

    #[tokio::test]
    async fn proxy_forwards_an_early_rejection_before_the_request_ends() {
        let (client_io, proxy_client_io) = tokio::io::duplex(8 * 1024);
        let (proxy_backend_io, backend_io) = tokio::io::duplex(8 * 1024);
        let (upload_closed_tx, upload_closed_rx) = tokio::sync::oneshot::channel();

        let backend_task = tokio::spawn(run_backend_handler_once(
            backend_io,
            move |request, mut respond| async move {
                let mut request_body = request.into_body();
                let first = request_body.data().await.unwrap().unwrap();
                let received = first.len();
                assert_eq!(first, Bytes::from_static(b"request-before-response"));
                request_body
                    .flow_control()
                    .release_capacity(received)
                    .unwrap();

                let response = Response::builder()
                    .status(400)
                    .version(Version::HTTP_2)
                    .body(())
                    .unwrap();
                let mut response_body = respond.send_response(response, false).unwrap();
                send_data_with_backpressure(
                    &mut response_body,
                    Bytes::from_static(b"rejected"),
                    true,
                    TEST_TIMEOUT,
                )
                .await
                .unwrap();
                // Keep the backend request handle alive until the client has
                // consumed the early response and closed its upload. Dropping
                // it here would manufacture a stream-wide NO_ERROR reset that
                // can legally race the queued response DATA.
                upload_closed_rx.await.unwrap();
                drop(request_body);
            },
        ));
        let proxy_task = tokio::spawn(run_proxy_once_accepting_stream_local(
            proxy_client_io,
            proxy_backend_io,
        ));

        timeout(TEST_TIMEOUT, async move {
            let (client, connection) = h2::client::handshake(client_io).await.unwrap();
            let client_driver = tokio::spawn(connection);
            let mut client = client.ready().await.unwrap();
            let request = Request::builder()
                .method("POST")
                .uri("http://qdrant.test/qdrant.Points/Upsert")
                .version(Version::HTTP_2)
                .header(API_KEY_HEADER, "secret")
                .body(())
                .unwrap();
            let (response, mut request_body) = client.send_request(request, false).unwrap();
            send_data_with_backpressure(
                &mut request_body,
                Bytes::from_static(b"request-before-response"),
                false,
                TEST_TIMEOUT,
            )
            .await
            .unwrap();

            // Waiting for this response before ending the request deadlocked
            // when the proxy serialized request and response forwarding.
            let response = response.await.unwrap();
            assert_eq!(response.status(), 400);
            assert_eq!(read_body(response.into_body()).await, b"rejected");
            drop(request_body);
            upload_closed_tx.send(()).unwrap();

            proxy_task.await.unwrap();
            backend_task.await.unwrap();
            client_driver.abort();
        })
        .await
        .expect("an early backend response must be delivered before request END_STREAM");
    }

    #[tokio::test]
    async fn proxy_pumps_bidirectional_stream_bodies_concurrently() {
        let (client_io, proxy_client_io) = tokio::io::duplex(8 * 1024);
        let (proxy_backend_io, backend_io) = tokio::io::duplex(8 * 1024);

        let backend_task = tokio::spawn(run_backend_handler_once(
            backend_io,
            |request, mut respond| async move {
                let mut request_body = request.into_body();
                let first = request_body.data().await.unwrap().unwrap();
                let received = first.len();
                assert_eq!(first, Bytes::from_static(b"request-one"));
                request_body
                    .flow_control()
                    .release_capacity(received)
                    .unwrap();

                let response = Response::builder()
                    .status(200)
                    .version(Version::HTTP_2)
                    .body(())
                    .unwrap();
                let mut response_body = respond.send_response(response, false).unwrap();
                send_data_with_backpressure(
                    &mut response_body,
                    Bytes::from_static(b"response-one"),
                    false,
                    TEST_TIMEOUT,
                )
                .await
                .unwrap();

                assert_eq!(read_body(request_body).await, b"request-two");
                send_data_with_backpressure(
                    &mut response_body,
                    Bytes::from_static(b"response-two"),
                    true,
                    TEST_TIMEOUT,
                )
                .await
                .unwrap();
            },
        ));
        let proxy_task = tokio::spawn(run_proxy_once(proxy_client_io, proxy_backend_io));

        timeout(TEST_TIMEOUT, async move {
            let (client, connection) = h2::client::handshake(client_io).await.unwrap();
            let client_driver = tokio::spawn(connection);
            let mut client = client.ready().await.unwrap();
            let request = Request::builder()
                .method("POST")
                .uri("http://qdrant.test/qdrant.Points/Upsert")
                .version(Version::HTTP_2)
                .header(API_KEY_HEADER, "secret")
                .body(())
                .unwrap();
            let (response, mut request_body) = client.send_request(request, false).unwrap();
            send_data_with_backpressure(
                &mut request_body,
                Bytes::from_static(b"request-one"),
                false,
                TEST_TIMEOUT,
            )
            .await
            .unwrap();

            let response = response.await.unwrap();
            let mut response_body = response.into_body();
            let first = response_body.data().await.unwrap().unwrap();
            let received = first.len();
            assert_eq!(first, Bytes::from_static(b"response-one"));
            response_body
                .flow_control()
                .release_capacity(received)
                .unwrap();

            send_data_with_backpressure(
                &mut request_body,
                Bytes::from_static(b"request-two"),
                true,
                TEST_TIMEOUT,
            )
            .await
            .unwrap();
            assert_eq!(read_body(response_body).await, b"response-two");

            proxy_task.await.unwrap();
            backend_task.await.unwrap();
            client_driver.abort();
        })
        .await
        .expect("bidirectional request and response frames must make concurrent progress");
    }

    #[tokio::test]
    async fn idle_application_streams_are_not_given_a_hard_deadline() {
        let (client_io, proxy_client_io) = tokio::io::duplex(1024);
        let (proxy_backend_io, backend_io) = tokio::io::duplex(1024);
        let stall_timeout = Duration::from_millis(25);

        let backend_task = tokio::spawn(async move {
            let mut server = server_handshake(backend_io).await.unwrap();
            let _request = server.accept().await.unwrap().unwrap();
            std::future::pending::<()>().await;
        });
        let proxy_task = tokio::spawn(async move {
            let mut server = server_handshake(proxy_client_io).await.unwrap();
            let (request, respond) = server.accept().await.unwrap().unwrap();
            let mut backend = client_handshake(proxy_backend_io).await.unwrap();
            let proxy =
                proxy_request_with_stall_timeout(request, respond, &mut backend, stall_timeout);
            tokio::pin!(proxy);

            tokio::select! {
                result = &mut proxy => result,
                request = server.accept() => {
                    match request {
                        Some(Ok(_)) => panic!("test proxy received an unexpected second request"),
                        Some(Err(error)) => panic!("test proxy connection failed: {error}"),
                        None => panic!("test client connection closed while the stream was idle"),
                    }
                }
            }
        });

        timeout(TEST_TIMEOUT, async move {
            let (client, connection) = h2::client::handshake(client_io).await.unwrap();
            let client_driver = tokio::spawn(connection);
            let mut client = client.ready().await.unwrap();
            let request = Request::builder()
                .method("POST")
                .uri("http://qdrant.test/qdrant.Points/Upsert")
                .version(Version::HTTP_2)
                .header(API_KEY_HEADER, "secret")
                .body(())
                .unwrap();
            let (response, request_body) = client.send_request(request, false).unwrap();

            tokio::time::sleep(stall_timeout * 3).await;
            assert!(
                !proxy_task.is_finished(),
                "idle application DATA/response waits must outlive the bounded flow-control timeout"
            );

            proxy_task.abort();
            drop(request_body);
            drop(response);
            client_driver.abort();
            backend_task.abort();
        })
        .await
        .expect("idle application streams should remain compatible with long-running RPCs");
    }

    async fn run_proxy_once(
        client_io: tokio::io::DuplexStream,
        backend_io: tokio::io::DuplexStream,
    ) {
        run_proxy_once_with_policy(client_io, backend_io, false).await;
    }

    async fn run_proxy_once_accepting_stream_local(
        client_io: tokio::io::DuplexStream,
        backend_io: tokio::io::DuplexStream,
    ) {
        run_proxy_once_with_policy(client_io, backend_io, true).await;
    }

    async fn run_proxy_once_with_policy(
        client_io: tokio::io::DuplexStream,
        backend_io: tokio::io::DuplexStream,
        allow_stream_local_failure: bool,
    ) {
        let mut server = server_handshake(client_io).await.unwrap();
        let (request, respond) = server.accept().await.unwrap().unwrap();
        let mut backend = client_handshake(backend_io).await.unwrap();
        let proxy = proxy_request_with_stall_timeout(request, respond, &mut backend, TEST_TIMEOUT);
        tokio::pin!(proxy);

        tokio::select! {
            result = &mut proxy => match result {
                Ok(()) => {}
                Err(error) if allow_stream_local_failure && error.is_stream_local() => {}
                Err(error) => panic!("test proxy failed: {error}"),
            },
            request = server.accept() => {
                match request {
                    Some(Ok(_)) => panic!("test proxy received an unexpected second request"),
                    Some(Err(error)) => panic!("test proxy connection failed: {error}"),
                    None => panic!("test client connection closed before proxying completed"),
                }
            }
        }

        server.graceful_shutdown();
        if let Err(error) = timeout(TEST_TIMEOUT, poll_fn(|context| server.poll_closed(context)))
            .await
            .expect("test proxy connection did not shut down")
        {
            assert!(error.is_io(), "unexpected proxy shutdown error: {error}");
        }
    }

    async fn run_backend_once(
        backend_io: tokio::io::DuplexStream,
        expected_request: Vec<u8>,
        response_body: Vec<u8>,
    ) {
        run_backend_handler_once(backend_io, move |request, mut respond| async move {
            assert_eq!(read_body(request.into_body()).await, expected_request);
            let response = Response::builder()
                .status(200)
                .version(Version::HTTP_2)
                .body(())
                .unwrap();
            let mut body = respond.send_response(response, false).unwrap();
            send_data_with_backpressure(&mut body, Bytes::from(response_body), true, TEST_TIMEOUT)
                .await
                .unwrap();
        })
        .await;
    }

    async fn run_backend_handler_once<F, Fut>(backend_io: tokio::io::DuplexStream, handler: F)
    where
        F: FnOnce(Request<RecvStream>, SendResponse<Bytes>) -> Fut,
        Fut: Future<Output = ()>,
    {
        let mut server = server_handshake(backend_io).await.unwrap();
        let (request, respond) = server.accept().await.unwrap().unwrap();
        let handler = handler(request, respond);
        tokio::pin!(handler);

        tokio::select! {
            () = &mut handler => {}
            request = server.accept() => {
                match request {
                    Some(Ok(_)) => panic!("test backend received an unexpected second request"),
                    Some(Err(error)) => panic!("test backend connection failed: {error}"),
                    None => panic!("test proxy connection closed before backend response completed"),
                }
            }
        }

        server.graceful_shutdown();
        if let Err(error) = timeout(TEST_TIMEOUT, poll_fn(|context| server.poll_closed(context)))
            .await
            .expect("test backend connection did not shut down")
        {
            assert!(error.is_io(), "unexpected backend shutdown error: {error}");
        }
    }

    async fn read_body(mut body: RecvStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            let received = chunk.len();
            bytes.extend_from_slice(&chunk);
            body.flow_control().release_capacity(received).unwrap();
        }
        let _ = body.trailers().await.unwrap();
        bytes
    }
}
