use rcgen::SanType;

use super::*;

#[test]
fn peer_node_id_reads_the_single_name() {
    assert_eq!(names_of(&["node-1"]).expect("one name"), node("node-1"));
}

#[test]
fn peer_node_id_refuses_anything_but_one_valid_name() {
    for names in [
        &["a", "b"][..],
        &[][..],
        &["*.example"][..],
        &["127.0.0.1"][..],
        &["Node"][..],
        &["a.b"][..],
        &["-a"][..],
    ] {
        assert!(
            matches!(names_of(names), Err(IdentityError::NoNodeName)),
            "{names:?}"
        );
    }
    assert!(matches!(peer_node_id(&[]), Err(IdentityError::NoNodeName)));
}

#[test]
fn peer_node_id_refuses_certificates_with_more_than_the_one_dns_entry() {
    let ip = SanType::IpAddress("10.0.0.1".parse().expect("ip"));
    let uri = SanType::URI("spiffe://cluster/other".try_into().expect("uri"));
    let email = SanType::Rfc822Name("ops@example.com".try_into().expect("email"));
    let cases = [
        ("dns and ip", vec![dns("a"), ip.clone()]),
        ("dns and uri", vec![dns("a"), uri.clone()]),
        ("dns and email", vec![dns("a"), email]),
        ("ip before dns", vec![ip, dns("a")]),
        // webpki's own name iterator skips this entry, so it cannot see the ambiguity.
        (
            "dns and an invalid dns name",
            vec![dns("a"), dns("Not A Name")],
        ),
        ("only a uri", vec![uri]),
    ];
    for (name, sans) in cases {
        assert!(
            matches!(sans_of(sans), Err(IdentityError::NoNodeName)),
            "{name}"
        );
    }
    assert_eq!(sans_of(vec![dns("a")]).expect("exactly one"), node("a"));
}

#[test]
fn peer_node_id_refuses_trailing_bytes_after_the_certificate() {
    let issued = issue(&authority(), &["a"]);
    let mut der = issued.der.as_ref().to_vec();
    der.push(0);
    assert!(matches!(
        peer_node_id(&[CertificateDer::from(der)]),
        Err(IdentityError::NoNodeName)
    ));
}

#[test]
fn peer_node_id_ignores_common_name() {
    let authority = authority();
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "a");
    let key = KeyPair::generate().expect("key");
    let cert = params.signed_by(&key, &authority.issuer).expect("cert");
    assert!(matches!(
        peer_node_id(&[cert.der().clone()]),
        Err(IdentityError::NoNodeName)
    ));
}

/// `SEQUENCE { [2] "a" }` built by hand, then altered one way at a time.
#[test]
fn the_san_value_must_be_exactly_one_primitive_dns_entry() {
    use crate::identity::node_from_san_value as check;

    assert_eq!(check(&[0x30, 3, 0x82, 1, b'a']), Some(node("a")));
    let mut longest = vec![0x30, 65, 0x82, 63];
    longest.extend([b'a'; 63]);
    assert_eq!(check(&longest), Some(node(&"a".repeat(63))));

    let rejected: [(&str, &[u8]); 10] = [
        ("constructed [2]", &[0x30, 3, 0xA2, 1, b'a']),
        ("wrong tag [1]", &[0x30, 3, 0x81, 1, b'a']),
        ("wrong tag [6]", &[0x30, 3, 0x86, 1, b'a']),
        ("universal class", &[0x30, 3, 0x02, 1, b'a']),
        ("long-form inner length", &[0x30, 4, 0x82, 0x81, 1, b'a']),
        ("long-form outer length", &[0x30, 0x81, 3, 0x82, 1, b'a']),
        ("trailing byte", &[0x30, 3, 0x82, 1, b'a', 0]),
        ("two elements", &[0x30, 6, 0x82, 1, b'a', 0x82, 1, b'b']),
        ("empty sequence", &[0x30, 0]),
        ("empty value", &[]),
    ];
    for (name, value) in rejected {
        assert_eq!(check(value), None, "{name}");
    }
    // Lengths that disagree with the bytes, and names that are not node ids.
    assert_eq!(check(&[0x30, 3, 0x82, 2, b'a']), None);
    assert_eq!(check(&[0x30, 5, 0x82, 1, b'a']), None);
    assert_eq!(check(&[0x30, 3, 0x82, 1, b'A']), None);
    assert_eq!(check(&[0x30, 2, 0x82, 0]), None);
}
