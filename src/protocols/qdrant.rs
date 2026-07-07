use bytes::Bytes;
use h2::{
    RecvStream,
    client::{SendRequest, SendRequest as H2SendRequest},
    server::SendResponse,
};
use http::{Request, Response};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};

const API_KEY_HEADER: &str = "api-key";

#[derive(Debug, thiserror::Error)]
pub enum QdrantProxyError {
    #[error("qdrant grpc handshake failed: {0}")]
    H2(#[from] h2::Error),
    #[error("qdrant grpc request missing api-key metadata")]
    MissingApiKey,
    #[error("qdrant grpc api-key metadata is invalid")]
    InvalidApiKey,
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
    Ok(h2::server::handshake(stream).await?)
}

pub async fn client_handshake<S>(stream: S) -> Result<SendRequest<Bytes>, QdrantProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) = h2::client::handshake(stream).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "qdrant backend h2 connection stopped");
        }
    });
    Ok(send_request)
}

pub async fn proxy_request(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    backend: &mut H2SendRequest<Bytes>,
) -> Result<(), QdrantProxyError> {
    let (parts, mut request_body) = request.into_parts();
    let request_without_body = Request::from_parts(parts, ());
    let end_stream = request_body.is_end_stream();
    let (response_future, mut request_send_stream) =
        backend.send_request(request_without_body, end_stream)?;

    while let Some(chunk) = request_body.data().await {
        let chunk = chunk?;
        let end_stream = request_body.is_end_stream();
        request_send_stream.send_data(chunk, end_stream)?;
    }
    if let Some(trailers) = request_body.trailers().await? {
        request_send_stream.send_trailers(trailers)?;
    }

    let response = response_future.await?;
    let (parts, mut response_body) = response.into_parts();
    let response_without_body: Response<()> = Response::from_parts(parts, ());
    let end_stream = response_body.is_end_stream();
    let mut response_send_stream = respond.send_response(response_without_body, end_stream)?;

    while let Some(chunk) = response_body.data().await {
        let chunk = chunk?;
        let end_stream = response_body.is_end_stream();
        response_send_stream.send_data(chunk, end_stream)?;
    }
    if let Some(trailers) = response_body.trailers().await? {
        response_send_stream.send_trailers(trailers)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_api_key_for_routing() {
        assert_eq!(
            route_key_sha256("secret"),
            "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
        );
    }
}
