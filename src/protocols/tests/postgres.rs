use crate::protocols::postgres;

#[test]
fn recognizes_ssl_gss_and_cancel_startup_packets_without_confusion() {
    let ssl = startup_control(postgres::SSL_REQUEST_CODE, &[]);
    let gss = startup_control(postgres::GSSENC_REQUEST_CODE, &[]);
    let cancel = startup_control(
        postgres::CANCEL_REQUEST_CODE,
        &[123_i32.to_be_bytes(), 456_i32.to_be_bytes()].concat(),
    );
    assert!(postgres::is_ssl_request(&ssl));
    assert!(!postgres::is_gssenc_request(&ssl));
    assert!(postgres::is_gssenc_request(&gss));
    assert_eq!(postgres::cancel_request_key(&cancel), Some((123, 456)));
    assert_eq!(postgres::cancel_request_key(&ssl), None);
}

#[test]
fn libpq_jdbc_and_hikari_startup_parameters_survive_database_inference() {
    for fields in [
        vec![("user", "tenant"), ("application_name", "psql")],
        vec![
            ("user", "tenant"),
            ("database", "tenant"),
            ("application_name", "PostgreSQL JDBC Driver"),
            ("client_encoding", "UTF8"),
        ],
        vec![
            ("user", "tenant"),
            ("application_name", "HikariPool-1"),
            ("DateStyle", "ISO"),
        ],
    ] {
        let packet = startup_packet(&fields);
        let rewritten = postgres::startup_packet_with_database(&packet, "tenant_database").unwrap();
        let route = postgres::parse_startup_route(&rewritten).unwrap();
        assert_eq!(route.user, "tenant");
        assert_eq!(route.database.as_deref(), Some("tenant_database"));
        for (key, value) in fields {
            if key != "database" {
                let needle = format!("{key}\0{value}\0");
                assert!(
                    rewritten
                        .windows(needle.len())
                        .any(|part| part == needle.as_bytes())
                );
            }
        }
    }
}

#[test]
fn malformed_control_packets_do_not_become_cancel_routes() {
    let mut packet = startup_control(postgres::CANCEL_REQUEST_CODE, &[0_u8; 8]);
    packet[0..4].copy_from_slice(&15_u32.to_be_bytes());
    assert_eq!(postgres::cancel_request_key(&packet), None);
    packet.truncate(15);
    assert_eq!(postgres::cancel_request_key(&packet), None);
}

fn startup_control(code: i32, body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
    packet.extend_from_slice(&code.to_be_bytes());
    packet.extend_from_slice(body);
    packet
}

fn startup_packet(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 0];
    packet.extend_from_slice(&196_608_i32.to_be_bytes());
    for (key, value) in fields {
        packet.extend_from_slice(key.as_bytes());
        packet.push(0);
        packet.extend_from_slice(value.as_bytes());
        packet.push(0);
    }
    packet.push(0);
    let length = packet.len() as u32;
    packet[..4].copy_from_slice(&length.to_be_bytes());
    packet
}
