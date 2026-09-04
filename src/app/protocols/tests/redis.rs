use crate::protocols::redis;

#[test]
fn accepts_resp2_resp3_acl_and_legacy_password_forms() {
    let acl = redis::parse_initial_route(b"*3\r\n$4\r\nAUTH\r\n$6\r\ntenant\r\n$6\r\nsecret\r\n")
        .unwrap();
    assert_eq!(acl.username(), Some("tenant"));

    let hello = redis::parse_initial_route(
        b"*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$6\r\ntenant\r\n$6\r\nsecret\r\n",
    )
    .unwrap();
    assert_eq!(hello.username(), Some("tenant"));

    let legacy = redis::parse_initial_route(b"*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n").unwrap();
    assert_eq!(legacy.username(), None);
    assert_eq!(
        legacy.password_route_sha256(),
        redis::password_route_sha256(b"secret")
    );
}

#[test]
fn fragmented_and_pipelined_frames_have_an_exact_boundary() {
    let full = b"*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n*1\r\n$4\r\nPING\r\n";
    for end in 1..b"*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n".len() {
        assert_eq!(
            redis::parse_initial_frame_route(&full[..end]).unwrap(),
            None
        );
    }
    let (route, consumed) = redis::parse_initial_frame_route(full).unwrap().unwrap();
    let rewritten = route
        .rewrite_with_resolved_username(full, consumed, "tenant")
        .unwrap();
    assert!(rewritten.ends_with(b"*1\r\n$4\r\nPING\r\n"));
    assert!(rewritten.starts_with(b"*3\r\n$4\r\nAUTH\r\n$6\r\ntenant\r\n"));
}

#[test]
fn binary_password_hashing_is_deterministic_without_utf8_assumptions() {
    let password = [0_u8, 0xff, b'\r', b'\n', 1, 2, 3];
    assert_eq!(
        redis::password_route_sha256(&password),
        redis::password_route_sha256(&password)
    );
    assert_ne!(
        redis::password_route_sha256(&password),
        redis::password_route_sha256(b"different")
    );
}

#[test]
fn default_acl_aliases_are_rewritten_without_changing_hello_semantics() {
    let original =
        b"*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$6\r\nsecret\r\n";
    let (route, consumed) = redis::parse_initial_frame_route(original).unwrap().unwrap();
    assert_eq!(route.username(), Some("default"));
    let rewritten = route
        .rewrite_with_resolved_username(original, consumed, "tenant")
        .unwrap();
    assert!(
        rewritten.starts_with(b"*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$6\r\ntenant\r\n")
    );
    assert!(rewritten.ends_with(b"$6\r\nsecret\r\n"));
}
