use super::*;
use crate::shared::logs::LogRedactor;
#[cfg(test)]
use crate::shared::logs::{INCOMPLETE_RECORD, LOG_RECORD_LIMIT, TRUNCATED_RECORD};
use futures::StreamExt;

// A JSON control character expands to six bytes; leave room for the envelope.
const LOG_CHUNK_BYTES: usize = 1536;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum LogStream {
    Stdout,
    Stderr,
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum LogChange<'a> {
    Reset,
    Append {
        stream: LogStream,
        data: &'a str,
    },
    End {
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<PublicDiagnostic>,
    },
}

#[derive(Serialize)]
struct LogEvent<'a> {
    r#type: &'static str,
    #[serde(flatten)]
    identity: LogIdentity<'a>,
    sequence: u64,
    #[serde(flatten)]
    change: LogChange<'a>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum LogIdentity<'a> {
    Instance { instance_id: &'a str },
    Pool { runtime_id: &'a str },
}

pub(crate) enum LogTarget {
    Instance {
        instance_id: String,
        created_at: String,
        protocol: crate::shared::protocol::Protocol,
    },
    Pool {
        grant: crate::auth::jwt::PoolGrant,
        protocol: crate::shared::protocol::Protocol,
    },
}

impl LogTarget {
    fn id(&self) -> &str {
        match self {
            Self::Instance { instance_id, .. } => instance_id,
            Self::Pool { grant, .. } => &grant.runtime_id,
        }
    }
    fn protocol(&self) -> crate::shared::protocol::Protocol {
        match self {
            Self::Instance { protocol, .. } => *protocol,
            Self::Pool { protocol, .. } => *protocol,
        }
    }
    fn identity(&self) -> LogIdentity<'_> {
        match self {
            Self::Instance { .. } => LogIdentity::Instance {
                instance_id: self.id(),
            },
            Self::Pool { .. } => LogIdentity::Pool {
                runtime_id: self.id(),
            },
        }
    }
    async fn is_current(&self, state: &AppState) -> bool {
        match self {
            Self::Instance {
                instance_id,
                created_at,
                ..
            } => instance_generation_is_current(state, instance_id, created_at).await,
            Self::Pool { grant, .. } => crate::api::pools::load(state, &grant.runtime_id)
                .await
                .is_ok_and(|pool| grant.matches(&pool)),
        }
    }
}

pub(crate) async fn stream_logs(
    mut socket: WebSocket,
    state: AppState,
    target: LogTarget,
    tail: Option<usize>,
    jwt_exp: i64,
    _connection: WebSocketConnectionPermit,
) {
    let mut shutdown = state.daemon_shutdown.subscribe();
    let deadline = jwt_expiration_deadline(jwt_exp);
    if !target.is_current(&state).await {
        close_replaced_socket(&mut socket).await;
        return;
    }
    let mut sequence = 0;
    let reset = LogEvent {
        r#type: "logs",
        identity: target.identity(),
        sequence,
        change: LogChange::Reset,
    };
    if send_json_before(&mut socket, &reset, deadline)
        .await
        .is_err()
    {
        return;
    }
    // One Docker follow request delivers the requested tail and then live
    // output. A separate history request would create a loss/duplication gap.
    let logs = tokio::select! {
        _ = wait_for_daemon_shutdown(&mut shutdown) => {
            close_shutdown_socket(&mut socket).await;
            return;
        }
        result = complete_before(deadline, state.docker.follow_logs(target.protocol(), target.id(), tail)) => result,
    };
    let mut logs = match logs {
        Ok(Ok(logs)) => logs,
        result => {
            if Instant::now() >= deadline {
                close_expired_socket(&mut socket).await;
                return;
            }
            let cause = match result {
                Ok(Err(error)) => error.to_string(),
                _ => "timed out opening container log stream".into(),
            };
            if target.is_current(&state).await {
                finish_stream(
                    &mut socket,
                    &target,
                    1,
                    Some(PublicDiagnostic::internal("container log stream", cause)),
                    deadline,
                )
                .await;
            }
            return;
        }
    };
    let mut stdout = LogRedactor::default();
    let mut stderr = LogRedactor::default();
    let mut heartbeat = interval_at(
        Instant::now() + Duration::from_secs(30),
        Duration::from_secs(30),
    );
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut awaiting_pong = false;
    let expiration = sleep_until(deadline);
    tokio::pin!(expiration);
    loop {
        let output = tokio::select! {
            _ = wait_for_daemon_shutdown(&mut shutdown) => {
                close_shutdown_socket(&mut socket).await;
                break;
            }
            _ = &mut expiration => {
                close_expired_socket(&mut socket).await;
                break;
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(Message::Pong(_))) => awaiting_pong = false,
                    _ => {},
                }
                continue;
            }
            _ = heartbeat.tick() => {
                if !target.is_current(&state).await {
                    close_replaced_socket(&mut socket).await;
                    break;
                }
                if awaiting_pong {
                    close_unresponsive_socket(&mut socket).await;
                    break;
                }
                if send_message_before(&mut socket, Message::Ping(b"dbe-heartbeat".as_slice().into()), deadline).await.is_err() { break; }
                awaiting_pong = true;
                continue;
            }
            output = logs.next() => output,
        };
        if !target.is_current(&state).await {
            close_replaced_socket(&mut socket).await;
            break;
        }
        let (out, err, mut ended, mut diagnostic) = match output {
            Some(Ok(output)) => (
                stdout.push(&output.stdout),
                stderr.push(&output.stderr),
                false,
                None,
            ),
            terminal => (
                stdout.finish(),
                stderr.finish(),
                true,
                terminal
                    .and_then(Result::err)
                    .map(|error| PublicDiagnostic::internal("container log stream", error)),
            ),
        };
        if stdout.failed || stderr.failed {
            ended = true;
            diagnostic = Some(PublicDiagnostic::public(
                "log_record_limit",
                "a log record exceeded the safe redaction limit; reconnect with a smaller tail",
            ));
        }
        if send_text(
            &mut socket,
            &state,
            &target,
            &mut sequence,
            LogStream::Stdout,
            &out,
            deadline,
        )
        .await
        .is_err()
            || send_text(
                &mut socket,
                &state,
                &target,
                &mut sequence,
                LogStream::Stderr,
                &err,
                deadline,
            )
            .await
            .is_err()
        {
            break;
        }
        if ended {
            sequence += 1;
            finish_stream(&mut socket, &target, sequence, diagnostic, deadline).await;
            break;
        }
    }
}

async fn finish_stream(
    socket: &mut WebSocket,
    target: &LogTarget,
    sequence: u64,
    error: Option<PublicDiagnostic>,
    deadline: Instant,
) {
    let code = if error.is_some() {
        close_code::ERROR
    } else {
        close_code::NORMAL
    };
    let event = LogEvent {
        r#type: "logs",
        identity: target.identity(),
        sequence,
        change: LogChange::End { error },
    };
    if send_json_before(socket, &event, deadline).await.is_ok() {
        let _ = send_message_before(
            socket,
            Message::Close(Some(CloseFrame {
                code,
                reason: "log stream ended".into(),
            })),
            deadline,
        )
        .await;
    }
}

async fn send_text(
    socket: &mut WebSocket,
    state: &AppState,
    target: &LogTarget,
    sequence: &mut u64,
    stream: LogStream,
    text: &str,
    deadline: Instant,
) -> Result<(), ()> {
    for data in text_chunks(text) {
        if state.daemon_shutdown.is_triggered() || !target.is_current(state).await {
            return Err(());
        }
        *sequence += 1;
        let event = LogEvent {
            r#type: "logs",
            identity: target.identity(),
            sequence: *sequence,
            change: LogChange::Append { stream, data },
        };
        send_json_before(socket, &event, deadline).await?;
    }
    Ok(())
}

fn text_chunks(mut text: &str) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        if text.is_empty() {
            return None;
        }
        let mut end = text.len().min(LOG_CHUNK_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let (head, tail) = text.split_at(end);
        text = tail;
        Some(head)
    })
}

#[cfg(test)]
mod tests;
