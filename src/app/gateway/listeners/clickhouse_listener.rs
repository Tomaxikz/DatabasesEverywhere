use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::{
    ListenerError, client_handshake,
    listener_io::{accept_direct_tls, read_clickhouse_hello, read_http_headers},
};
use crate::{
    gateway::{resolver::RouteResolver, tunnel},
    instances::state::DatabaseRouteResolution,
    protocols::clickhouse,
    shared::backend::BackendEndpoint,
};

pub(super) async fn handle_clickhouse_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let (client, target, initial) = client_handshake("clickhouse", async move {
        let mut client = accept_direct_tls(client, tls).await?;
        let initial = read_clickhouse_hello(&mut client).await?;
        let route = clickhouse::parse_native_initial_route(&initial)?;
        let resolution = resolver
            .resolve_clickhouse(
                &route.username,
                (!route.database.is_empty()).then_some(route.database.as_str()),
            )
            .await;
        let (database, target) = match resolution {
            DatabaseRouteResolution::Found { database, target } => (database, target),
            DatabaseRouteResolution::NotFound => return Err(ListenerError::RouteNotFound),
            DatabaseRouteResolution::Ambiguous => {
                return Err(ListenerError::AmbiguousDatabaseRoute {
                    protocol: "clickhouse",
                });
            }
        };
        let initial = if route.database == database {
            initial
        } else {
            clickhouse::native_hello_with_database(&initial, &database)?
        };
        Ok((client, target, initial))
    })
    .await?;

    let instance_id = target.instance_id;
    tunnel::connect_replay_and_tunnel(
        client,
        target.endpoint,
        &initial,
        target.network,
        target.session,
    )
    .await
    .map_err(|source| ListenerError::Backend {
        instance_id,
        source,
    })?;
    Ok(())
}

pub(super) async fn handle_clickhouse_http(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let (client, instance_id, endpoint, network, session, initial) =
        client_handshake("clickhouse_http", async move {
            let mut client = accept_direct_tls(client, tls).await?;
            let initial = read_http_headers(&mut client).await?;
            let route = clickhouse::parse_http_initial_route(&initial)?;
            let resolution = resolver
                .resolve_clickhouse(
                    &route.username,
                    (!route.database.is_empty()).then_some(route.database.as_str()),
                )
                .await;
            let (database, target) = match resolution {
                DatabaseRouteResolution::Found { database, target } => (database, target),
                DatabaseRouteResolution::NotFound => return Err(ListenerError::RouteNotFound),
                DatabaseRouteResolution::Ambiguous => {
                    return Err(ListenerError::AmbiguousDatabaseRoute {
                        protocol: "clickhouse_http",
                    });
                }
            };
            let initial = clickhouse::http_request_for_gateway(&initial, &database)?;
            let endpoint = clickhouse_http_endpoint(target.endpoint)?;
            Ok((
                client,
                target.instance_id,
                endpoint,
                target.network,
                target.session,
                initial,
            ))
        })
        .await?;

    tunnel::connect_replay_and_tunnel(client, endpoint, &initial, network, session)
        .await
        .map_err(|source| ListenerError::Backend {
            instance_id,
            source,
        })?;
    Ok(())
}

fn clickhouse_http_endpoint(endpoint: BackendEndpoint) -> Result<BackendEndpoint, ListenerError> {
    match endpoint {
        BackendEndpoint::UnixSocket { socket_path } => {
            let socket_path = crate::shared::backend::clickhouse_http_socket_path(
                std::path::Path::new(&socket_path),
            )
            .ok_or(ListenerError::InvalidClickhouseBackend)?;
            Ok(BackendEndpoint::UnixSocket {
                socket_path: socket_path.display().to_string(),
            })
        }
        BackendEndpoint::DockerTcp { .. } => Err(ListenerError::InvalidClickhouseBackend),
    }
}
