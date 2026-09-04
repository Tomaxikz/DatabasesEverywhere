use secrecy::ExposeSecret;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::{
    GatewayStream, ListenerError, MAX_ROUTING_HANDSHAKE_BYTES, client_handshake,
    listener_io::{MysqlTunnel, proxy_mysql_session},
};
use crate::{
    gateway::{resolver::RouteResolver, tunnel},
    instances::state::DatabaseRouteResolution,
    protocols::mariadb,
    shared::{backend::BackendEndpoint, protocol::Protocol},
};

pub(super) async fn handle_mariadb_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let Some((client, backend, shared, activity)) =
        client_handshake("mariadb", prepare_mariadb_tunnel(client, resolver, tls)).await?
    else {
        return Ok(());
    };
    let buffers = backend.query_budget();
    proxy_mysql_session(
        client,
        backend,
        Protocol::Mariadb,
        shared,
        activity,
        buffers,
    )
    .await
}

pub(super) async fn handle_mysql_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let Some((client, backend, shared, activity)) =
        client_handshake("mysql", prepare_mysql_tunnel(client, resolver, tls)).await?
    else {
        return Ok(());
    };
    let buffers = backend.query_budget();
    proxy_mysql_session(client, backend, Protocol::Mysql, shared, activity, buffers).await
}

async fn prepare_mariadb_tunnel(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<Option<MysqlTunnel>, ListenerError> {
    prepare_mysql_connection(client, resolver, tls, false).await
}

async fn prepare_mysql_tunnel(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<Option<MysqlTunnel>, ListenerError> {
    prepare_mysql_connection(client, resolver, tls, true).await
}

async fn prepare_mysql_connection(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    mysql: bool,
) -> Result<Option<MysqlTunnel>, ListenerError> {
    let protocol = if mysql { "mysql" } else { "mariadb" };
    // MySQL TLS is negotiated *after* the server greeting with CLIENT_SSL.
    // Wrapping the TCP stream before the greeting works only for nonstandard
    // direct-TLS clients and breaks Connector/J, MariaDB JDBC, and the CLIs.
    let mut raw_client = client;
    let tls_available = tls.is_some();
    let gateway_seed = mariadb::new_gateway_auth_seed();
    let flavor = if mysql {
        mariadb::GatewayFlavor::Mysql
    } else {
        mariadb::GatewayFlavor::Mariadb
    };
    mariadb::send_gateway_handshake(&mut raw_client, &gateway_seed, flavor, tls_available).await?;
    let first_response =
        mariadb::read_packet_limited(&mut raw_client, MAX_ROUTING_HANDSHAKE_BYTES).await?;
    let (mut client, client_response) = if mariadb::is_ssl_request(&first_response.payload)? {
        let Some(tls) = tls else {
            let error = mariadb::MariadbProxyError::TlsUnavailable;
            mariadb::write_packet(
                &mut raw_client,
                first_response.sequence.wrapping_add(1),
                &mariadb::error_packet(&error.to_string()),
            )
            .await?;
            return Err(error.into());
        };
        let mut client = GatewayStream::Tls(Box::new(tls.accept(raw_client).await?));
        let response =
            mariadb::read_packet_limited(&mut client, MAX_ROUTING_HANDSHAKE_BYTES).await?;
        (client, response)
    } else {
        if tls_available {
            let error = mariadb::MariadbProxyError::TlsRequired;
            mariadb::write_packet(
                &mut raw_client,
                first_response.sequence.wrapping_add(1),
                &mariadb::error_packet(&error.to_string()),
            )
            .await?;
            return Err(error.into());
        }
        (GatewayStream::Plain(raw_client), first_response)
    };
    let client_reply_sequence = client_response.sequence.wrapping_add(1);
    let mut route = match mariadb::parse_client_handshake_response(&client_response.payload) {
        Ok(route) => route,
        Err(error) => {
            let error_message = error.to_string();
            mariadb::write_packet(
                &mut client,
                client_reply_sequence,
                &mariadb::error_packet(&error_message),
            )
            .await?;
            return Err(error.into());
        }
    };

    let resolution = if mysql {
        resolver
            .resolve_mysql(
                &route.username,
                (!route.database.is_empty()).then_some(route.database.as_str()),
            )
            .await
    } else {
        resolver
            .resolve_mariadb(
                &route.username,
                (!route.database.is_empty()).then_some(route.database.as_str()),
            )
            .await
    };
    let (database, target) = match resolution {
        DatabaseRouteResolution::Found { database, target } => (database, target),
        DatabaseRouteResolution::NotFound => {
            mariadb::write_packet(
                &mut client,
                client_reply_sequence,
                &mariadb::error_packet("Access denied for requested database"),
            )
            .await?;
            return Err(ListenerError::RouteNotFound);
        }
        DatabaseRouteResolution::Ambiguous => {
            mariadb::write_packet(
                &mut client,
                client_reply_sequence,
                &mariadb::error_packet("Database must be included for routing"),
            )
            .await?;
            return Err(ListenerError::AmbiguousDatabaseRoute { protocol });
        }
    };
    route.database = database;
    let Some(native_password_sha1_stage2) = target.native_password_sha1_stage2.as_deref() else {
        let message = mariadb::MariadbProxyError::MissingNativePasswordVerifier.to_string();
        mariadb::write_packet(
            &mut client,
            client_reply_sequence,
            &mariadb::error_packet(&message),
        )
        .await?;
        return Err(mariadb::MariadbProxyError::MissingNativePasswordVerifier.into());
    };
    tracing::debug!(
        user = %route.username,
        database = %route.database,
        protocol,
        "mysql wire route resolved"
    );
    let backend = tunnel::connect_backend(&target.endpoint)
        .await
        .map_err(|source| ListenerError::Backend {
            instance_id: target.instance_id.clone(),
            source,
        })?;
    let mut backend = tunnel::MeteredBackend::new(backend, target.network, target.session);
    let backend_is_unix = matches!(&target.endpoint, BackendEndpoint::UnixSocket { .. });
    let backend_password = target
        .tenant_password
        .as_ref()
        .map(|password| password.expose_secret());
    let backend_handshake_packet = mariadb::read_packet(&mut backend).await?;
    let mut backend_handshake =
        mariadb::parse_backend_handshake(&backend_handshake_packet.payload)?;
    let mut auth_payload = match mariadb::backend_handshake_response(
        &backend_handshake,
        &route,
        &gateway_seed,
        native_password_sha1_stage2,
        backend_password,
    ) {
        Ok(payload) => payload,
        Err(error) => {
            let message = error.to_string();
            mariadb::write_packet(
                &mut client,
                client_reply_sequence,
                &mariadb::error_packet(&message),
            )
            .await?;
            return Err(error.into());
        }
    };
    mariadb::write_packet(&mut backend, 1, &auth_payload).await?;

    let mut backend_response = mariadb::read_packet(&mut backend).await?;
    if let Some(switch) = mariadb::auth_switch_request(&backend_response.payload) {
        backend_handshake = switch;
        auth_payload = match mariadb::backend_auth_switch_response(
            &backend_handshake,
            &route,
            &gateway_seed,
            native_password_sha1_stage2,
            backend_password,
        ) {
            Ok(payload) => payload,
            Err(error) => {
                let message = error.to_string();
                mariadb::write_packet(
                    &mut client,
                    client_reply_sequence,
                    &mariadb::error_packet(&message),
                )
                .await?;
                return Err(error.into());
            }
        };
        mariadb::write_packet(
            &mut backend,
            backend_response.sequence.wrapping_add(1),
            &auth_payload,
        )
        .await?;
        backend_response = mariadb::read_packet(&mut backend).await?;
    }

    if backend_handshake.auth_plugin == "caching_sha2_password"
        && let Some(continuation) = mariadb::caching_sha2_continuation(&backend_response.payload)?
    {
        match continuation {
            mariadb::CachingSha2Continuation::FastAuthenticationComplete => {
                backend_response = mariadb::read_packet(&mut backend).await?;
            }
            mariadb::CachingSha2Continuation::FullAuthenticationRequired => {
                if !backend_is_unix {
                    return Err(
                        mariadb::MariadbProxyError::InsecureBackendFullAuthentication.into(),
                    );
                }
                let password =
                    backend_password.ok_or(mariadb::MariadbProxyError::MissingBackendPassword)?;
                let payload = mariadb::caching_sha2_plaintext_password(password)?;
                mariadb::write_packet(
                    &mut backend,
                    backend_response.sequence.wrapping_add(1),
                    &payload,
                )
                .await?;
                backend_response = mariadb::read_packet(&mut backend).await?;
            }
        }
    }

    if mariadb::packet_is_error(&backend_response.payload) {
        mariadb::write_packet(
            &mut client,
            client_reply_sequence,
            &backend_response.payload,
        )
        .await?;
        return Ok(None);
    }
    if !mariadb::packet_is_ok(&backend_response.payload) {
        let message = if mysql {
            "unsupported mysql backend auth response"
        } else {
            "unsupported mariadb backend auth response"
        };
        mariadb::write_packet(
            &mut client,
            client_reply_sequence,
            &mariadb::error_packet(message),
        )
        .await?;
        return Err(mariadb::MariadbProxyError::MalformedPacket.into());
    }

    // Preserve the backend's negotiated status flags and warnings. Only the
    // sequence number belongs to the public handshake; synthesizing a fresh
    // OK packet here needlessly discarded real server state.
    mariadb::write_packet(
        &mut client,
        client_reply_sequence,
        &backend_response.payload,
    )
    .await?;
    Ok(Some((client, backend, target.shared, target.activity)))
}
