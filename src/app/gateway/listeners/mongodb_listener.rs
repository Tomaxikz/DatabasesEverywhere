use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::TlsAcceptor;

use super::{
    GatewayStream, ListenerError, MAX_ROUTING_HANDSHAKE_BYTES, client_handshake,
    listener_io::{MongodbTunnel, accept_direct_tls, proxy_mongodb_session},
};
use crate::{
    gateway::{resolver::RouteResolver, tunnel},
    protocols::mongodb,
};

const MAX_HELLO_MESSAGES: usize = 8;

pub(super) async fn handle_mongodb_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let Some((client, backend, activity)) = client_handshake("mongodb", async move {
        let mut client = accept_direct_tls(client, tls).await?;
        let mut backend_hello = None;
        for _ in 0..MAX_HELLO_MESSAGES {
            let message =
                mongodb::read_message_limited(&mut client, MAX_ROUTING_HANDSHAKE_BYTES).await?;
            let route = match if mongodb::is_hello(&message) {
                mongodb::parse_hello_speculative_route(&message)
            } else {
                mongodb::parse_sasl_start_route(&message).map(Some)
            } {
                Ok(None) => {
                    backend_hello = Some(message.raw.clone());
                    mongodb::write_response(
                        &mut client,
                        &message,
                        mongodb::hello_response(&message),
                    )
                    .await?;
                    continue;
                }
                Ok(Some(route)) => route,
                Err(error) => {
                    mongodb::write_response(
                        &mut client,
                        &message,
                        mongodb::command_error(&error.to_string(), 18),
                    )
                    .await?;
                    return Err(error.into());
                }
            };
            let Some(pending) = resolver
                .resolve_mongodb_pending(&route.username, &route.database)
                .await
            else {
                mongodb::write_response(
                    &mut client,
                    &message,
                    mongodb::command_error("Authentication failed", 18),
                )
                .await?;
                return Err(ListenerError::RouteNotFound);
            };
            let backend = tunnel::connect_backend(&pending.endpoint)
                .await
                .map_err(|source| ListenerError::Backend {
                    instance_id: pending.instance_id.clone(),
                    source,
                })?;
            return authenticate_mongodb(
                client,
                backend,
                resolver,
                pending,
                route,
                message,
                backend_hello,
            )
            .await;
        }

        Err(ListenerError::HandshakeMessageLimit {
            protocol: "mongodb",
        })
    })
    .await?
    else {
        return Ok(());
    };

    proxy_mongodb_session(client, backend, activity).await
}

async fn authenticate_mongodb(
    mut client: GatewayStream,
    mut backend: tunnel::BackendStream,
    resolver: RouteResolver,
    pending: crate::gateway::resolver::PendingMongodbRoute,
    route: mongodb::MongodbRoute,
    mut request: mongodb::MongoMessage,
    backend_hello: Option<Vec<u8>>,
) -> Result<Option<MongodbTunnel>, ListenerError> {
    let mut speculative = mongodb::is_hello(&request);
    if !speculative {
        let hello = match backend_hello {
            Some(hello) => hello,
            None => mongodb::backend_hello_request()?,
        };
        backend.write_all(&hello).await?;
        let response =
            mongodb::read_message_limited(&mut backend, MAX_ROUTING_HANDSHAKE_BYTES).await?;
        mongodb::validate_hello_reply(&response)?;
    }
    backend.write_all(&request.raw).await?;
    for _ in 0..MAX_HELLO_MESSAGES {
        let response =
            mongodb::read_message_limited(&mut backend, MAX_ROUTING_HANDSHAKE_BYTES).await?;
        match mongodb::auth_reply_state(&response, speculative)? {
            mongodb::AuthReplyState::SpeculativeFallback => {
                mongodb::relay_auth_response(&mut client, &request, &response, speculative).await?;
                let next =
                    mongodb::read_message_limited(&mut client, MAX_ROUTING_HANDSHAKE_BYTES).await?;
                let fallback_route = mongodb::parse_sasl_start_route(&next)?;
                if fallback_route != route {
                    mongodb::write_response(
                        &mut client,
                        &next,
                        mongodb::command_error("Authentication identity changed", 18),
                    )
                    .await?;
                    return Err(mongodb::MongodbProxyError::AuthIdentityChanged.into());
                }
                backend.write_all(&next.raw).await?;
                request = next;
                speculative = false;
            }
            mongodb::AuthReplyState::Rejected => {
                mongodb::relay_auth_response(&mut client, &request, &response, speculative).await?;
                return Ok(None);
            }
            mongodb::AuthReplyState::Authenticated => {
                let Some(target) = resolver.activate_mongodb(pending).await else {
                    mongodb::write_response(
                        &mut client,
                        &request,
                        mongodb::command_error("Authentication route changed", 18),
                    )
                    .await?;
                    return Err(ListenerError::RouteNotFound);
                };
                mongodb::relay_auth_response(&mut client, &request, &response, speculative).await?;
                return Ok(Some((
                    client,
                    tunnel::MeteredBackend::new(backend, target.network, target.session),
                    target.activity,
                )));
            }
            mongodb::AuthReplyState::Continue => {
                mongodb::relay_auth_response(&mut client, &request, &response, speculative).await?;
                let next =
                    mongodb::read_message_limited(&mut client, MAX_ROUTING_HANDSHAKE_BYTES).await?;
                if let Err(error) = mongodb::validate_sasl_continue(&next, &route) {
                    mongodb::write_response(
                        &mut client,
                        &next,
                        mongodb::command_error(&error.to_string(), 18),
                    )
                    .await?;
                    return Err(error.into());
                }
                backend.write_all(&next.raw).await?;
                request = next;
                speculative = false;
            }
        }
    }
    Err(ListenerError::HandshakeMessageLimit {
        protocol: "mongodb",
    })
}

#[cfg(test)]
#[path = "mongodb_tests.rs"]
mod tests;
