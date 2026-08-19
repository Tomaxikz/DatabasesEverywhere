use http::Request;

use crate::{protocols::qdrant, shared::backend};

#[test]
fn grpc_and_rest_api_key_headers_share_one_route_hash() {
    for request in [
        Request::builder()
            .method("POST")
            .uri("http://qdrant.test/qdrant.Points/Search")
            .header("api-key", "secret")
            .body(())
            .unwrap(),
        Request::builder()
            .method("GET")
            .uri("http://qdrant.test/collections")
            .header("API-KEY", "secret")
            .body(())
            .unwrap(),
    ] {
        let key = qdrant::api_key_from_request(&request).unwrap();
        assert_eq!(
            qdrant::route_key_sha256(&key),
            "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
        );
    }
}

#[test]
fn qdrant_private_rest_and_grpc_sockets_are_distinct_siblings() {
    let grpc = std::path::Path::new("/run/dbev/qdrant-grpc.sock");
    let http = backend::qdrant_http_socket_path(grpc).unwrap();
    assert_eq!(http, std::path::Path::new("/run/dbev/qdrant-http.sock"));
    assert_ne!(grpc, http);
}

#[test]
fn missing_duplicate_or_non_ascii_api_keys_fail_without_panicking() {
    let missing = Request::builder().uri("/").body(()).unwrap();
    assert!(qdrant::api_key_from_request(&missing).is_err());

    let invalid = Request::builder()
        .uri("/")
        .header("api-key", http::HeaderValue::from_bytes(&[0xff]).unwrap())
        .body(())
        .unwrap();
    assert!(qdrant::api_key_from_request(&invalid).is_err());

    let mut duplicate = Request::builder()
        .uri("/")
        .header("api-key", "one")
        .body(())
        .unwrap();
    duplicate
        .headers_mut()
        .append("api-key", http::HeaderValue::from_static("two"));
    assert!(qdrant::api_key_from_request(&duplicate).is_err());
}
