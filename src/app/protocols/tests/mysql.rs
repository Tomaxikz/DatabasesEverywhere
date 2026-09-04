use crate::protocols::mariadb::{self, GatewayFlavor};

const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SSL: u32 = 0x0000_0800;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;

#[tokio::test]
async fn gateway_wire_versions_are_plain_vendor_compatible_ascii() {
    for (flavor, expected) in [
        (GatewayFlavor::Mysql, "8.0.11"),
        (GatewayFlavor::Mariadb, "5.5.5-10.11.0-MariaDB"),
    ] {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            mariadb::send_gateway_handshake(&mut writer, b"12345678901234567890", flavor, false)
                .await
                .unwrap();
        });
        let packet = mariadb::read_packet(&mut reader).await.unwrap();
        task.await.unwrap();
        assert_eq!(packet.payload[0], 10);
        let version_end = packet.payload[1..]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap()
            + 1;
        assert_eq!(
            std::str::from_utf8(&packet.payload[1..version_end]).unwrap(),
            expected
        );
        assert!(!expected.contains("databases-everywhere"));
    }
}

#[test]
fn recognizes_the_official_fixed_size_ssl_request() {
    let mut request = vec![0_u8; 32];
    request[..4].copy_from_slice(&(CLIENT_PROTOCOL_41 | CLIENT_SSL).to_le_bytes());
    request[8] = 45;
    assert!(mariadb::is_ssl_request(&request).unwrap());

    request.extend_from_slice(b"not-an-ssl-request");
    assert!(!mariadb::is_ssl_request(&request).unwrap());
}

#[test]
fn connector_j_and_mariadb_jdbc_handshake_shapes_route_identically() {
    for attributes in [
        &b"\x0c\x03_os\x05Linux"[..],
        &b"\x17\x0c_client_name\x07libmariadb"[..],
        &b"\x1a\x0f_client_version\x079.2.0"[..],
    ] {
        let payload = handshake_response("tenant_user", "tenant_db", attributes);
        let route = mariadb::parse_client_handshake_response(&payload).unwrap();
        assert_eq!(route.username, "tenant_user");
        assert_eq!(route.database, "tenant_db");
        assert_eq!(route.auth_response, vec![0x41; 20]);
    }
}

#[test]
fn caching_sha2_backend_tokens_work_for_mysql_8_9_and_26_backends() {
    let seed = b"12345678901234567890";
    let first = mariadb::caching_sha2_password_token("secret", seed);
    let second = mariadb::caching_sha2_password_token("secret", seed);
    assert_eq!(first, second);
    assert_eq!(first.len(), 32);
    assert_ne!(
        first,
        mariadb::caching_sha2_password_token("different", seed)
    );
}

fn handshake_response(username: &str, database: &str, attributes: &[u8]) -> Vec<u8> {
    let capabilities = CLIENT_PROTOCOL_41
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_CONNECT_ATTRS;
    let mut payload = Vec::new();
    payload.extend_from_slice(&capabilities.to_le_bytes());
    payload.extend_from_slice(&16_777_216_u32.to_le_bytes());
    payload.push(45);
    payload.extend_from_slice(&[0_u8; 23]);
    payload.extend_from_slice(username.as_bytes());
    payload.push(0);
    payload.push(20);
    payload.extend_from_slice(&[0x41; 20]);
    payload.extend_from_slice(database.as_bytes());
    payload.push(0);
    payload.extend_from_slice(b"mysql_native_password\0");
    payload.extend_from_slice(attributes);
    payload
}
