use super::*;

pub(crate) fn jwt_expiration_deadline(exp: i64) -> Instant {
    let now_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let expires_since_epoch = Duration::from_secs(u64::try_from(exp).unwrap_or_default());
    Instant::now() + expires_since_epoch.saturating_sub(now_since_epoch)
}

pub(super) async fn instance_generation_is_current(
    state: &AppState,
    instance_id: &str,
    instance_generation: &str,
) -> bool {
    state
        .instances
        .get(instance_id)
        .await
        .is_some_and(|metadata| metadata.created_at == instance_generation)
}

pub(crate) async fn close_expired_socket(socket: &mut WebSocket) {
    close_socket(socket, "JWT expired").await;
}

pub(super) async fn close_unresponsive_socket(socket: &mut WebSocket) {
    close_socket(socket, "heartbeat timeout").await;
}

pub(crate) async fn close_replaced_socket(socket: &mut WebSocket) {
    close_socket(socket, "instance identity changed").await;
}

pub(crate) async fn close_shutdown_socket(socket: &mut WebSocket) {
    close_socket_with_code(socket, close_code::RESTART, "server restarting").await;
}

pub(super) async fn close_socket(socket: &mut WebSocket, reason: &'static str) {
    close_socket_with_code(socket, close_code::POLICY, reason).await;
}

pub(super) async fn close_socket_with_code(
    socket: &mut WebSocket,
    code: u16,
    reason: &'static str,
) {
    let close_deadline = Instant::now() + CLOSE_FRAME_TIMEOUT;
    let _ = send_message_before(
        socket,
        Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })),
        close_deadline,
    )
    .await;
}

pub(crate) async fn wait_for_daemon_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

pub(crate) async fn send_json_before<T: Serialize>(
    socket: &mut WebSocket,
    value: &T,
    deadline: Instant,
) -> Result<(), ()> {
    let payload = serde_json::to_string(value).map_err(|error| {
        tracing::warn!(%error, "failed to serialize websocket payload");
    })?;
    send_message_before(socket, Message::Text(payload.into()), deadline).await
}

pub(crate) async fn send_message_before(
    socket: &mut WebSocket,
    message: Message,
    deadline: Instant,
) -> Result<(), ()> {
    let now = Instant::now();
    if now >= deadline {
        return Err(());
    }
    let send_deadline = deadline.min(now + SEND_TIMEOUT);
    timeout_at(send_deadline, socket.send(message))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

pub(crate) async fn complete_before<F>(deadline: Instant, future: F) -> Result<F::Output, ()>
where
    F: Future,
{
    let now = Instant::now();
    if now >= deadline {
        return Err(());
    }
    let operation_deadline = deadline.min(now + OPERATION_TIMEOUT);
    timeout_at(operation_deadline, future).await.map_err(|_| ())
}
