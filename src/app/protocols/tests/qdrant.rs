use http::Request;

use crate::protocols::qdrant;

#[test]
fn grpc_and_rest_api_key_headers_share_one_route_hash() {
    let route_key = qdrant::QdrantRouteKey::new(b"test-qdrant-route-key");
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
        assert_eq!(route_key.fingerprint(&key), route_key.fingerprint("secret"));
        assert_ne!(
            route_key.fingerprint(&key),
            qdrant::route_key_fingerprint(b"different-daemon", &key)
        );
    }
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
