use super::*;

#[tokio::test(start_paused = true)]
async fn shared_query_deadline_releases_buffer_without_timing_out_idle_clients() {
    let (mut client, gateway_client) = tokio::io::duplex(64);
    let (gateway_backend, mut backend) = tokio::io::duplex(64);
    let budget = crate::gateway::buffers::QueryBudget::default();
    let proxy = tokio::spawn(proxy_mysql_session(
        gateway_client,
        gateway_backend,
        Protocol::Mysql,
        true,
        activity(),
        budget.clone(),
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(QUERY_BODY_TIMEOUT * 2).await;
    assert!(!proxy.is_finished(), "an idle pooled connection is valid");
    let packet = mysql_packet(0, b"\x03SELECT 1");
    client.write_all(&packet[..6]).await.unwrap();
    tokio::task::yield_now().await;
    assert!(budget.reserve(32 * 1024 * 1024).is_err());
    tokio::time::advance(QUERY_BODY_TIMEOUT).await;
    assert!(
        matches!(proxy.await.unwrap(), Err(ListenerError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert!(budget.reserve(32 * 1024 * 1024).is_ok());
    assert_eq!(
        backend.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn mongodb_wire_limit_matches_advertised_limit_without_large_allocations() {
    let mut message = mongodb_message(bson::doc! { "insert": "items", "$db": "tenant" });
    let limit = crate::gateway::protocols::mongodb::MAX_WIRE_MESSAGE_BYTES;
    for size in [16 * 1024 * 1024 + 128, limit] {
        message[..4].copy_from_slice(&(size as i32).to_le_bytes());
        let (prefix, declared, command) = read_mongodb_prefix(&mut message.as_slice())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(declared, size);
        assert!(prefix.len() < 64);
        assert_eq!(command.as_deref(), Some(b"insert".as_slice()));
    }
    message[..4].copy_from_slice(&((limit + 1) as i32).to_le_bytes());
    assert!(read_mongodb_prefix(&mut message.as_slice()).await.is_err());
}

fn activity() -> Arc<ActivityCounter> {
    Arc::new(ActivityCounter::default())
}

#[test]
fn sql_kind_uses_the_first_real_keyword() {
    assert_eq!(
        classify_sql(b" ; /* trace */ -- note\n SELECT 1"),
        OperationKind::Read
    );
    assert_eq!(
        classify_sql(b"INSERT INTO items VALUES (1)"),
        OperationKind::Write
    );
    assert_eq!(classify_sql(b"DROP TABLE items"), OperationKind::Ddl);
    assert_eq!(
        classify_sql(b"WITH rows AS (SELECT 1) SELECT * FROM rows"),
        OperationKind::Other
    );
}

#[test]
fn mongodb_kind_is_case_insensitive_and_conservative() {
    assert_eq!(classify_mongodb(b"FiNd"), OperationKind::Read);
    assert_eq!(classify_mongodb(b"bulkWrite"), OperationKind::Write);
    assert_eq!(classify_mongodb(b"createIndexes"), OperationKind::Ddl);
    assert_eq!(classify_mongodb(b"serverStatus"), OperationKind::Other);
}

#[tokio::test]
async fn postgres_proxy_forwards_complete_frontend_frames() {
    let (mut client, gateway_client) = tokio::io::duplex(128);
    let (gateway_backend, mut backend) = tokio::io::duplex(128);
    let activity = activity();
    let proxy = tokio::spawn(proxy_postgres_session(
        gateway_client,
        gateway_backend,
        Arc::clone(&activity),
    ));
    let mut frames = postgres_frame(b'Q', b"SELECT 1\0");
    frames.extend_from_slice(&postgres_frame(b'E', b"\0\0\0\0\0"));
    client.write_all(&frames).await.unwrap();
    client.shutdown().await.unwrap();

    let mut forwarded = vec![0_u8; frames.len()];
    backend.read_exact(&mut forwarded).await.unwrap();
    backend.shutdown().await.unwrap();
    proxy.await.unwrap().unwrap();
    assert_eq!(forwarded, frames);
    let snapshot = activity.snapshot();
    assert_eq!(snapshot.accepted.read, 1);
    assert_eq!(snapshot.accepted.other, 1);
    assert_eq!(snapshot.gateway.opened_connections, 1);
    assert_eq!(snapshot.gateway.active_connections, 0);
}

#[tokio::test]
async fn postgres_proxy_rejects_invalid_frame_lengths() {
    let (mut client, gateway_client) = tokio::io::duplex(32);
    let (gateway_backend, mut backend) = tokio::io::duplex(32);
    let proxy = tokio::spawn(proxy_postgres_session(
        gateway_client,
        gateway_backend,
        activity(),
    ));
    client.write_all(&[b'Q', 0, 0, 0, 3]).await.unwrap();
    let error = proxy.await.unwrap().unwrap_err();
    assert!(
        matches!(error, ListenerError::Io(error) if error.kind() == std::io::ErrorKind::InvalidData)
    );
    let mut byte = [0_u8; 1];
    assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn mysql_proxy_forwards_commands_but_rejects_change_user() {
    let (mut client, gateway_client) = tokio::io::duplex(256);
    let (gateway_backend, mut backend) = tokio::io::duplex(256);
    let activity = activity();
    let proxy = tokio::spawn(proxy_mysql_session(
        gateway_client,
        gateway_backend,
        Protocol::Mysql,
        false,
        Arc::clone(&activity),
        Default::default(),
    ));

    let query = mysql_packet(
        0,
        &[
            MYSQL_COM_QUERY,
            b'S',
            b'E',
            b'L',
            b'E',
            b'C',
            b'T',
            b' ',
            b'1',
        ],
    );
    client.write_all(&query).await.unwrap();
    let mut forwarded = vec![0_u8; query.len()];
    backend.read_exact(&mut forwarded).await.unwrap();
    assert_eq!(forwarded, query);

    client
        .write_all(&mysql_packet(0, &[MYSQL_COM_CHANGE_USER, b'x']))
        .await
        .unwrap();
    let error = proxy.await.unwrap().unwrap_err();
    assert!(matches!(
        error,
        ListenerError::IdentitySwitchRejected { protocol: "mysql" }
    ));
    let snapshot = activity.snapshot();
    assert_eq!(snapshot.accepted.read, 1);
    assert_eq!(snapshot.rejected.other, 1);
    assert_eq!(snapshot.gateway.opened_connections, 1);
    assert_eq!(snapshot.gateway.active_connections, 0);
}

#[tokio::test]
async fn mysql_continuation_payload_cannot_be_misread_as_change_user() {
    let (mut client, gateway_client) = tokio::io::duplex(256);
    let (gateway_backend, mut backend) = tokio::io::duplex(256);
    let proxy = tokio::spawn(proxy_mysql_session(
        gateway_client,
        gateway_backend,
        Protocol::Mariadb,
        false,
        activity(),
        Default::default(),
    ));
    let continuation = mysql_packet(1, &[MYSQL_COM_CHANGE_USER, b'x']);
    client.write_all(&continuation).await.unwrap();
    client.shutdown().await.unwrap();
    let mut forwarded = vec![0_u8; continuation.len()];
    backend.read_exact(&mut forwarded).await.unwrap();
    backend.shutdown().await.unwrap();
    proxy.await.unwrap().unwrap();
    assert_eq!(forwarded, continuation);
}

#[tokio::test]
async fn shared_mysql_nonzero_payload_is_not_misread_as_a_database_command() {
    for protocol in [Protocol::Mysql, Protocol::Mariadb] {
        for command in [MYSQL_COM_CREATE_DB, MYSQL_COM_DROP_DB] {
            let (mut client, gateway_client) = tokio::io::duplex(128);
            let (gateway_backend, mut backend) = tokio::io::duplex(128);
            let proxy = tokio::spawn(proxy_mysql_session(
                gateway_client,
                gateway_backend,
                protocol,
                true,
                activity(),
                Default::default(),
            ));
            let continuation = mysql_packet(1, &[command, b'x']);

            client.write_all(&continuation).await.unwrap();
            client.shutdown().await.unwrap();
            let mut forwarded = vec![0_u8; continuation.len()];
            backend.read_exact(&mut forwarded).await.unwrap();
            backend.shutdown().await.unwrap();
            proxy.await.unwrap().unwrap();
            assert_eq!(forwarded, continuation);
        }
    }
}

#[tokio::test]
async fn shared_mysql_rejects_raw_database_commands_before_forwarding() {
    for protocol in [Protocol::Mysql, Protocol::Mariadb] {
        for command in [MYSQL_COM_CREATE_DB, MYSQL_COM_DROP_DB] {
            let (mut client, gateway_client) = tokio::io::duplex(128);
            let (gateway_backend, mut backend) = tokio::io::duplex(128);
            let proxy = tokio::spawn(proxy_mysql_session(
                gateway_client,
                gateway_backend,
                protocol,
                true,
                activity(),
                Default::default(),
            ));
            let packet = mysql_packet(0, &[command, b't', b'e', b'n', b'a', b'n', b't']);

            client.write_all(&packet).await.unwrap();

            let error = proxy.await.unwrap().unwrap_err();
            assert!(matches!(
                error,
                ListenerError::Mariadb(mariadb::MariadbProxyError::SharedStorageCommandRejected(_))
            ));
            let mut byte = [0_u8; 1];
            assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
        }
    }
}

#[tokio::test]
async fn fragmented_shared_mysql_raw_database_commands_are_rejected() {
    for protocol in [Protocol::Mysql, Protocol::Mariadb] {
        for command in [MYSQL_COM_CREATE_DB, MYSQL_COM_DROP_DB] {
            let (mut client, gateway_client) = tokio::io::duplex(32);
            let (gateway_backend, mut backend) = tokio::io::duplex(32);
            let proxy = tokio::spawn(proxy_mysql_session(
                gateway_client,
                gateway_backend,
                protocol,
                true,
                activity(),
                Default::default(),
            ));
            // The command is the last byte so the proxy cannot close the
            // in-memory client while the test still has bytes to write.
            let packet = mysql_packet(0, &[command]);

            for byte in packet {
                client.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }

            let error = proxy.await.unwrap().unwrap_err();
            assert!(matches!(
                error,
                ListenerError::Mariadb(mariadb::MariadbProxyError::SharedStorageCommandRejected(_))
            ));
            let mut byte = [0_u8; 1];
            assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
        }
    }
}

#[tokio::test]
async fn dedicated_mysql_forwards_raw_database_commands() {
    for protocol in [Protocol::Mysql, Protocol::Mariadb] {
        for command in [MYSQL_COM_CREATE_DB, MYSQL_COM_DROP_DB] {
            let (mut client, gateway_client) = tokio::io::duplex(128);
            let (gateway_backend, mut backend) = tokio::io::duplex(128);
            let proxy = tokio::spawn(proxy_mysql_session(
                gateway_client,
                gateway_backend,
                protocol,
                false,
                activity(),
                Default::default(),
            ));
            let packet = mysql_packet(0, &[command, b't', b'e', b'n', b'a', b'n', b't']);

            client.write_all(&packet).await.unwrap();
            client.shutdown().await.unwrap();
            let mut forwarded = vec![0_u8; packet.len()];
            backend.read_exact(&mut forwarded).await.unwrap();
            assert_eq!(forwarded, packet);
            backend.shutdown().await.unwrap();
            proxy.await.unwrap().unwrap();
        }
    }
}

#[tokio::test]
async fn shared_mysql_proxy_blocks_storage_escape_before_backend_forwarding() {
    for (protocol, command) in [
        (Protocol::Mysql, MYSQL_COM_QUERY),
        (Protocol::Mariadb, MYSQL_COM_STMT_PREPARE),
    ] {
        let (mut client, gateway_client) = tokio::io::duplex(512);
        let (gateway_backend, mut backend) = tokio::io::duplex(512);
        let proxy = tokio::spawn(proxy_mysql_session(
            gateway_client,
            gateway_backend,
            protocol,
            true,
            activity(),
            Default::default(),
        ));
        let mut payload = vec![command];
        payload.extend_from_slice(b"CREATE TABLE items(id BIGINT) TABLESPACE=innodb_system");
        client.write_all(&mysql_packet(0, &payload)).await.unwrap();

        let error = proxy.await.unwrap().unwrap_err();
        assert!(matches!(
            error,
            ListenerError::Mariadb(mariadb::MariadbProxyError::SharedStorageCommandRejected(_))
        ));
        let mut byte = [0_u8; 1];
        assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn fragmented_shared_mysql_commands_are_checked_before_forwarding() {
    for (protocol, command) in [
        (Protocol::Mysql, MYSQL_COM_QUERY),
        (Protocol::Mariadb, MYSQL_COM_STMT_PREPARE),
    ] {
        let (mut client, gateway_client) = tokio::io::duplex(64);
        let (gateway_backend, mut backend) = tokio::io::duplex(64);
        let proxy = tokio::spawn(proxy_mysql_session(
            gateway_client,
            gateway_backend,
            protocol,
            true,
            activity(),
            Default::default(),
        ));
        let mut payload = vec![command];
        payload.extend_from_slice(b"DROP DATABASE tenant_db");
        let packet = mysql_packet(0, &payload);

        for byte in packet {
            client.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }

        let error = proxy.await.unwrap().unwrap_err();
        assert!(matches!(
            error,
            ListenerError::Mariadb(mariadb::MariadbProxyError::SharedStorageCommandRejected(_))
        ));
        let mut byte = [0_u8; 1];
        assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn shared_mysql_rejects_multi_packet_text_before_forwarding() {
    for command in [MYSQL_COM_QUERY, MYSQL_COM_STMT_PREPARE] {
        let (mut client, gateway_client) = tokio::io::duplex(64);
        let (gateway_backend, mut backend) = tokio::io::duplex(64);
        let proxy = tokio::spawn(proxy_mysql_session(
            gateway_client,
            gateway_backend,
            Protocol::Mysql,
            true,
            activity(),
            Default::default(),
        ));

        client
            .write_all(&[0xff, 0xff, 0xff, 0, command])
            .await
            .unwrap();

        let error = proxy.await.unwrap().unwrap_err();
        assert!(matches!(
            error,
            ListenerError::Mariadb(mariadb::MariadbProxyError::SharedStorageCommandRejected(_))
        ));
        let mut byte = [0_u8; 1];
        assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn mysql_storage_policy_is_shared_only_and_preserves_table_ddl() {
    for (shared, sql) in [
        (true, "CREATE TABLE items(id BIGINT) ENGINE=InnoDB"),
        (true, "ALTER TABLE items ADD COLUMN note TEXT"),
        (true, "DROP TABLE items"),
        (false, "DROP DATABASE tenant_db"),
    ] {
        let (mut client, gateway_client) = tokio::io::duplex(512);
        let (gateway_backend, mut backend) = tokio::io::duplex(512);
        let proxy = tokio::spawn(proxy_mysql_session(
            gateway_client,
            gateway_backend,
            Protocol::Mysql,
            shared,
            activity(),
            Default::default(),
        ));
        let mut payload = vec![MYSQL_COM_QUERY];
        payload.extend_from_slice(sql.as_bytes());
        let packet = mysql_packet(0, &payload);
        client.write_all(&packet).await.unwrap();
        client.shutdown().await.unwrap();

        let mut forwarded = vec![0_u8; packet.len()];
        backend.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, packet);
        backend.shutdown().await.unwrap();
        proxy.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn binary_execute_payload_is_not_treated_as_sql_text() {
    let (mut client, gateway_client) = tokio::io::duplex(512);
    let (gateway_backend, mut backend) = tokio::io::duplex(512);
    let proxy = tokio::spawn(proxy_mysql_session(
        gateway_client,
        gateway_backend,
        Protocol::Mysql,
        true,
        activity(),
        Default::default(),
    ));
    let mut payload = vec![MYSQL_COM_STMT_EXECUTE];
    payload.extend_from_slice(b"DROP DATABASE tenant_db\0TABLESPACE innodb_system");
    let packet = mysql_packet(0, &payload);
    client.write_all(&packet).await.unwrap();
    client.shutdown().await.unwrap();

    let mut forwarded = vec![0_u8; packet.len()];
    backend.read_exact(&mut forwarded).await.unwrap();
    assert_eq!(forwarded, packet);
    backend.shutdown().await.unwrap();
    proxy.await.unwrap().unwrap();
}

#[tokio::test]
async fn mongodb_proxy_streams_data_but_rejects_post_auth_identity_commands() {
    let (mut client, gateway_client) = tokio::io::duplex(1024);
    let (gateway_backend, mut backend) = tokio::io::duplex(1024);
    let activity = activity();
    let proxy = tokio::spawn(proxy_mongodb_session(
        gateway_client,
        gateway_backend,
        Arc::clone(&activity),
    ));

    let ping = mongodb_message(bson::doc! { "ping": 1_i32, "$db": "tenant_db" });
    client.write_all(&ping).await.unwrap();
    let mut forwarded = vec![0_u8; ping.len()];
    backend.read_exact(&mut forwarded).await.unwrap();
    assert_eq!(forwarded, ping);

    let reauth = mongodb_message(bson::doc! {
        "saslStart": 1_i32,
        "mechanism": "SCRAM-SHA-256",
        "$db": "victim_db",
    });
    client.write_all(&reauth).await.unwrap();
    let error = proxy.await.unwrap().unwrap_err();
    assert!(matches!(
        error,
        ListenerError::IdentitySwitchRejected {
            protocol: "mongodb"
        }
    ));
    let snapshot = activity.snapshot();
    assert_eq!(snapshot.accepted.other, 1);
    assert_eq!(snapshot.rejected.other, 1);
    assert_eq!(snapshot.gateway.opened_connections, 1);
    assert_eq!(snapshot.gateway.active_connections, 0);
}

#[tokio::test]
async fn mongodb_proxy_streams_large_non_auth_messages_without_handshake_cap() {
    let (mut client, gateway_client) = tokio::io::duplex(4096);
    let (gateway_backend, mut backend) = tokio::io::duplex(4096);
    let proxy = tokio::spawn(proxy_mongodb_session(
        gateway_client,
        gateway_backend,
        activity(),
    ));
    let message = mongodb_message(bson::doc! {
        "insert": "tenant_collection",
        "payload": bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: vec![7_u8; 128 * 1024],
        },
        "$db": "tenant_db",
    });
    let expected = message.clone();
    let send = tokio::spawn(async move {
        client.write_all(&message).await.unwrap();
        client.shutdown().await.unwrap();
    });
    let mut forwarded = vec![0_u8; expected.len()];
    backend.read_exact(&mut forwarded).await.unwrap();
    backend.shutdown().await.unwrap();
    send.await.unwrap();
    proxy.await.unwrap().unwrap();
    assert_eq!(forwarded, expected);
}

fn mysql_packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut packet = vec![len as u8, (len >> 8) as u8, (len >> 16) as u8, sequence];
    packet.extend_from_slice(payload);
    packet
}

fn postgres_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(kind);
    frame.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn mongodb_message(body: bson::Document) -> Vec<u8> {
    let body = bson::Document::to_vec(&body).unwrap();
    let len = 16 + 5 + body.len();
    let mut message = Vec::with_capacity(len);
    message.extend_from_slice(&(len as i32).to_le_bytes());
    message.extend_from_slice(&7_i32.to_le_bytes());
    message.extend_from_slice(&0_i32.to_le_bytes());
    message.extend_from_slice(&MONGODB_OP_MSG.to_le_bytes());
    message.extend_from_slice(&0_i32.to_le_bytes());
    message.push(0);
    message.extend_from_slice(&body);
    message
}
