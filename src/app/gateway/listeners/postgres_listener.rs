use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;

use super::{
    GatewayStream, ListenerError, MAX_ROUTING_HANDSHAKE_BYTES, client_handshake,
    listener_io::proxy_postgres_session,
};
use crate::{
    gateway::{postgres_sessions, resolver::RouteResolver, tunnel},
    instances::state::DatabaseRouteResolution,
    protocols::postgres,
};

pub(super) async fn handle_postgres_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let initial = client_handshake("postgres", async {
        let direct_tls = tls.is_some() && postgres_wants_direct_tls(&client).await?;
        let (mut client, mut packet, encrypted) = if direct_tls {
            let tls = tls
                .clone()
                .ok_or(postgres::PostgresParseError::UnsupportedStartupRequest)?;
            let tls_stream = tls.accept(client).await?;
            if tls_stream.get_ref().1.alpn_protocol() != Some(b"postgresql") {
                return Err(postgres::PostgresParseError::DirectTlsAlpnRequired.into());
            }
            let mut client = GatewayStream::Tls(Box::new(tls_stream));
            let packet = read_postgres_startup(&mut client).await?;
            (client, packet, true)
        } else {
            let mut client = GatewayStream::Plain(client);
            let packet = read_postgres_startup(&mut client).await?;
            (client, packet, false)
        };

        // libpq may try GSS encryption before SSL. DBEV deliberately does not
        // terminate GSS, so reply N and continue the same startup negotiation.
        while postgres::is_gssenc_request(&packet) {
            client.write_all(b"N").await?;
            packet = read_postgres_startup(&mut client).await?;
        }

        if postgres::is_ssl_request(&packet) {
            if encrypted {
                return Err(postgres::PostgresParseError::UnsupportedStartupRequest.into());
            }
            let GatewayStream::Plain(mut raw_client) = client else {
                return Err(postgres::PostgresParseError::UnsupportedStartupRequest.into());
            };
            if let Some(tls) = tls {
                raw_client.write_all(b"S").await?;
                let mut upgraded = GatewayStream::Tls(Box::new(tls.accept(raw_client).await?));
                packet = read_postgres_startup(&mut upgraded).await?;
                client = upgraded;
            } else {
                raw_client.write_all(b"N").await?;
                client = GatewayStream::Plain(raw_client);
                packet = read_postgres_startup(&mut client).await?;
            }
        } else if tls.is_some() && !encrypted {
            return Err(postgres::PostgresParseError::UnsupportedStartupRequest.into());
        }

        if let Some(key) = postgres::cancel_request_key(&packet) {
            let _ = postgres_sessions::forward_cancel(key, &packet)
                .await
                .map_err(|error| ListenerError::PostgresSession(error.to_string()))?;
            return Ok(None);
        }

        let route = postgres::parse_startup_route(&packet)?;
        let resolution = resolver
            .resolve_postgres(&route.user, route.database.as_deref())
            .await;
        let (database, target) = match resolution {
            DatabaseRouteResolution::Found { database, target } => (database, target),
            DatabaseRouteResolution::NotFound => {
                client.write_all(&postgres::auth_error_packet()).await?;
                client.shutdown().await?;
                return Err(ListenerError::RouteNotFound);
            }
            DatabaseRouteResolution::Ambiguous => {
                client.write_all(&postgres::auth_error_packet()).await?;
                client.shutdown().await?;
                return Err(ListenerError::AmbiguousDatabaseRoute {
                    protocol: "postgres",
                });
            }
        };
        let packet = if route.database.as_deref() == Some(database.as_str()) {
            packet
        } else {
            postgres::startup_packet_with_database(&packet, &database)?
        };
        tracing::debug!(
            user = %route.user,
            database = %database,
            endpoint = ?target.target.endpoint,
            "postgres route resolved"
        );
        Ok(Some((client, target, packet)))
    })
    .await?;

    let Some((mut client, target, packet)) = initial else {
        return Ok(());
    };

    let connection_limit = target.connection_limit;
    let route_revision = target.route_revision;
    let target = target.target;
    let instance_id = target.instance_id.clone();
    let authenticated = client_handshake("postgres", async {
        let backend = tunnel::connect_backend(&target.endpoint)
            .await
            .map_err(|source| ListenerError::Backend {
                instance_id: instance_id.clone(),
                source,
            })?;
        let mut backend =
            tunnel::MeteredBackend::new(backend, target.network.clone(), target.session);
        backend.write_all(&packet).await?;
        let Some(startup) = postgres_sessions::proxy_startup(&mut client, &mut backend)
            .await
            .map_err(|error| ListenerError::PostgresSession(error.to_string()))?
        else {
            return Ok(None);
        };
        if !resolver
            .route_is_current(&instance_id, route_revision)
            .await
        {
            return Err(ListenerError::RouteNotFound);
        }
        backend.authenticate_session(connection_limit)?;
        if !resolver
            .route_is_current(&instance_id, route_revision)
            .await
        {
            return Err(ListenerError::RouteNotFound);
        }
        let registration = startup
            .finish(&mut client, &instance_id, &target.endpoint, &target.network)
            .await
            .map_err(|error| ListenerError::PostgresSession(error.to_string()))?;
        Ok(Some((backend, registration)))
    })
    .await?;
    let Some((backend, _cancel_registration)) = authenticated else {
        return Ok(());
    };
    proxy_postgres_session(client, backend, target.activity)
        .await
        .map_err(|error| match error {
            ListenerError::Io(source) => ListenerError::Backend {
                instance_id,
                source: tunnel::TunnelError::Tunnel(source),
            },
            error => error,
        })
}

async fn postgres_wants_direct_tls(client: &TcpStream) -> Result<bool, std::io::Error> {
    let mut first = [0_u8; 1];
    let read = client.peek(&mut first).await?;
    Ok(read == 1 && first[0] == 0x16)
}

async fn read_postgres_startup<S>(client: &mut S) -> Result<Vec<u8>, ListenerError>
where
    S: AsyncRead + Unpin,
{
    let mut len_bytes = [0_u8; 4];
    client.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if !(8..=MAX_ROUTING_HANDSHAKE_BYTES).contains(&len) {
        return Err(postgres::PostgresParseError::InvalidLength.into());
    }

    let mut packet = Vec::with_capacity(len);
    packet.extend_from_slice(&len_bytes);
    packet.resize(len, 0);
    client.read_exact(&mut packet[4..]).await?;
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_declared_startup_packet_over_routing_limit() {
        let (mut client, mut gateway) = tokio::io::duplex(16);
        tokio::spawn(async move {
            client
                .write_all(&((MAX_ROUTING_HANDSHAKE_BYTES + 1) as u32).to_be_bytes())
                .await
                .unwrap();
        });

        assert!(matches!(
            read_postgres_startup(&mut gateway).await,
            Err(ListenerError::Postgres(
                postgres::PostgresParseError::InvalidLength
            ))
        ));
    }
}
