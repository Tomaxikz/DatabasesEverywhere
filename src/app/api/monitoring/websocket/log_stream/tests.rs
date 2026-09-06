use super::*;

#[test]
fn history_and_live_data_are_emitted_once_and_reset_on_reconnect() {
    let mut stream = LogRedactor::default();
    assert_eq!(stream.push("old line\n"), "old line\n");
    assert_eq!(stream.push("new"), "");
    assert_eq!(stream.push(" line\n"), "new line\n");
    assert_eq!(stream.push(""), "");
    let reset = serde_json::to_value(LogEvent {
        r#type: "logs",
        identity: LogIdentity::Instance { instance_id: "db" },
        sequence: 0,
        change: LogChange::Reset,
    })
    .unwrap();
    assert_eq!(
        reset,
        serde_json::json!({"type":"logs","instance_id":"db","sequence":0,"event":"reset"})
    );
    let event = serde_json::to_value(LogEvent {
        r#type: "logs",
        identity: LogIdentity::Instance { instance_id: "db" },
        sequence: 1,
        change: LogChange::Append {
            stream: LogStream::Stderr,
            data: "new line\n",
        },
    })
    .unwrap();
    assert_eq!(event["event"], "append");
    assert_eq!(event["stream"], "stderr");
    assert!(event.get("stdout").is_none());
    assert!(!event.to_string().contains("old line"));
    // Reconnect starts with a fresh reset and follows the tail again.
    assert_eq!(LogRedactor::default().push("new line\n"), "new line\n");
}

#[test]
fn split_credentials_and_multiline_secret_values_are_never_published() {
    for input in [
        "postgresql://demo:dummy-secret@db.example/app\n",
        "PASSWORD=\"dummy-secret\"\n",
        "password: 'dummy-\nsecret'\n",
        "token=\n\"dummy-secret\"\n",
    ] {
        for split in 0..=input.len() {
            let mut redactor = LogRedactor::default();
            let output = redactor.push(&input[..split])
                + &redactor.push(&input[split..])
                + &redactor.finish();
            assert!(
                !output.contains("dummy"),
                "secret escaped at boundary {split}"
            );
            assert!(
                output.contains("[redacted]"),
                "credential wasn't recognized at {split}"
            );
        }
    }
}

#[test]
fn partial_final_records_and_redaction_overflow_are_explicit() {
    let mut redactor = LogRedactor::default();
    assert_eq!(redactor.push("ready"), "");
    assert_eq!(redactor.finish(), "ready");
    assert_eq!(redactor.finish(), "");
    assert_eq!(redactor.push("PASSWORD=\"dummy-secret"), "");
    assert_eq!(redactor.finish(), INCOMPLETE_RECORD);
    let huge = format!(
        "password='{}\nsecret after newline\n",
        "x".repeat(LOG_RECORD_LIMIT)
    );
    assert_eq!(redactor.push(&huge), TRUNCATED_RECORD);
    assert!(redactor.failed);
    assert!(redactor.pending.is_empty());
    assert_eq!(redactor.push("unclosed secret suffix\n"), "");
}

#[test]
fn serialized_log_chunks_fit_the_frame_budget_without_splitting_utf8() {
    for data in ["\0".repeat(LOG_RECORD_LIMIT), "😀\\\"\n".repeat(10_000)] {
        let chunks = text_chunks(&data).collect::<Vec<_>>();
        assert_eq!(chunks.concat(), data);
        for (index, chunk) in chunks.iter().enumerate() {
            let event = LogEvent {
                r#type: "logs",
                identity: LogIdentity::Instance {
                    instance_id: &"i".repeat(128),
                },
                sequence: index as u64 + 1,
                change: LogChange::Append {
                    stream: LogStream::Stdout,
                    data: chunk,
                },
            };
            assert!(serde_json::to_vec(&event).unwrap().len() <= WEBSOCKET_MAX_MESSAGE_BYTES);
        }
    }
}
