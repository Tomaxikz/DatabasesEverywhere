use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::{
    GatewayStream, ListenerError, client_handshake,
    listener_io::{accept_direct_tls, read_resp_initial_frame},
};
use crate::gateway::{resolver::RouteResolver, tunnel};

pub(super) async fn handle_redis_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let (client, target, initial) =
        client_handshake("redis", prepare_resp_tunnel(client, resolver, tls, false)).await?;

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

pub(super) async fn handle_valkey_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let (client, target, initial) =
        client_handshake("valkey", prepare_resp_tunnel(client, resolver, tls, true)).await?;

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

async fn prepare_resp_tunnel(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    valkey: bool,
) -> Result<
    (
        GatewayStream,
        crate::gateway::resolver::ResolvedRoute,
        Vec<u8>,
    ),
    ListenerError,
> {
    let mut client = accept_direct_tls(client, tls).await?;
    let (route, initial, consumed) = read_resp_initial_frame(&mut client).await?;
    let explicit_target = if let Some(username) = route.username() {
        if valkey {
            resolver.resolve_valkey(username).await
        } else {
            resolver.resolve_redis(username).await
        }
    } else {
        None
    };
    let (target, initial) = if let Some(target) = explicit_target {
        (target, initial)
    } else if route
        .username()
        .is_none_or(|username| username.eq_ignore_ascii_case("default"))
    {
        let password_sha256 = route.password_route_sha256();
        let (username, target) = if valkey {
            resolver.resolve_valkey_password(&password_sha256).await
        } else {
            resolver.resolve_redis_password(&password_sha256).await
        }
        .ok_or(ListenerError::RouteNotFound)?;
        let rewritten = route.rewrite_with_resolved_username(&initial, consumed, &username)?;
        (target, rewritten)
    } else {
        return Err(ListenerError::RouteNotFound);
    };
    Ok((client, target, initial))
}
