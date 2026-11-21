use http::Request;

use crate::gateway::protocols::qdrant;

#[test]
fn grpc_and_rest_api_key_headers_share_one_route_hash() -> anyhow::Result<()> {
    let route_key = qdrant::QdrantRouteKey::new(b"test-qdrant-route-key");
    for request in [
        Request::builder()
            .method("POST")
            .uri("http://qdrant.test/qdrant.Points/Search")
            .header("api-key", "secret")
            .body(())?,
        Request::builder()
            .method("GET")
            .uri("http://qdrant.test/collections")
            .header("API-KEY", "secret")
            .body(())?,
    ] {
        let key = qdrant::api_key_from_request(&request)?;
        assert_eq!(route_key.fingerprint(&key), route_key.fingerprint("secret"));
        assert_ne!(
            route_key.fingerprint(&key),
            qdrant::route_key_fingerprint(b"different-daemon", &key)
        );
    }

    Ok(())
}

#[test]
fn missing_duplicate_or_non_ascii_api_keys_fail_without_panicking() -> anyhow::Result<()> {
    let missing = Request::builder().uri("/").body(())?;
    assert!(qdrant::api_key_from_request(&missing).is_err());

    let invalid = Request::builder()
        .uri("/")
        .header("api-key", http::HeaderValue::from_bytes(&[0xff])?)
        .body(())?;
    assert!(qdrant::api_key_from_request(&invalid).is_err());

    let mut duplicate = Request::builder()
        .uri("/")
        .header("api-key", "one")
        .body(())?;
    duplicate
        .headers_mut()
        .append("api-key", http::HeaderValue::from_static("two"));
    assert!(qdrant::api_key_from_request(&duplicate).is_err());

    Ok(())
}
