use super::*;
use bytes::Bytes;
use secrecy::SecretString;

#[test]
fn secret_environment_is_validated_without_echoing_values() -> anyhow::Result<()> {
    let secret = SecretString::from("correct horse battery staple");
    assert_eq!(
        encode_secrets(&[("PGPASSWORD", &secret)])?,
        vec!["PGPASSWORD=correct horse battery staple"]
    );
    assert!(
        encode_secrets(&[("BAD=KEY", &secret)])
            .expect_err("encode secrets should return an error")
            .to_string()
            .contains("environment")
    );
    assert!(encode_secrets(&[("PGPASSWORD", &secret), ("PGPASSWORD", &secret)]).is_err());
    let nul = SecretString::from("secret\0tail");
    let error =
        encode_secrets(&[("PGPASSWORD", &nul)]).expect_err("encode secrets should return an error");
    assert!(!error.to_string().contains("secret"));

    Ok(())
}

#[test]
fn streaming_exec_is_attached_non_tty_and_never_privileged() {
    let options = streaming_exec_options(
        vec!["database-client".to_string()],
        vec!["PASSWORD=redacted".to_string()],
        true,
    );

    assert_eq!(options.attach_stdin, Some(true));
    assert_eq!(options.attach_stdout, Some(true));
    assert_eq!(options.attach_stderr, Some(true));
    assert_eq!(options.tty, Some(false));
    assert_eq!(options.privileged, Some(false));
    assert_eq!(
        options.cmd.as_deref(),
        Some(["database-client".to_string()].as_slice())
    );
    assert!(options.env.is_some());
}

#[tokio::test]
async fn input_pump_obeys_backpressure_and_preserves_bytes() -> anyhow::Result<()> {
    let contents = vec![b'x'; EXEC_STREAM_BUFFER_BYTES * 3 + 17];
    let (writer, mut reader) = tokio::io::duplex(7);
    let expected = contents.clone();
    let consumer = tokio::spawn(async move {
        let mut received = Vec::new();
        reader
            .read_to_end(&mut received)
            .await
            .expect("read to end should succeed");
        received
    });

    let transferred = pump_private_input(
        std::io::Cursor::new(contents),
        writer,
        expected.len() as u64,
        expected.len() as u64,
    )
    .await?;

    assert_eq!(transferred, expected.len() as u64);
    assert_eq!(consumer.await?, expected);

    Ok(())
}

#[tokio::test]
async fn input_pump_rejects_growth_and_truncation() {
    let growth = pump_private_input(std::io::Cursor::new(b"too long"), tokio::io::sink(), 3, 8)
        .await
        .expect_err("sink should return an error");
    assert_eq!(growth.kind(), ErrorKind::InvalidData);

    let truncated = pump_private_input(std::io::Cursor::new(b"short"), tokio::io::sink(), 8, 8)
        .await
        .expect_err("sink should return an error");
    assert_eq!(truncated.kind(), ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn output_drain_writes_only_stdout_and_console() -> anyhow::Result<()> {
    let output = futures::stream::iter(vec![
        Ok(LogOutput::StdOut {
            message: Bytes::from_static(b"dump"),
        }),
        Ok(LogOutput::StdErr {
            message: Bytes::from_static(b"not part of dump"),
        }),
        Ok(LogOutput::Console {
            message: Bytes::from_static(b"-tail"),
        }),
    ]);
    let (mut writer, mut reader) = tokio::io::duplex(64);
    let drain = tokio::spawn(async move {
        let result = drain_exec_output(output, &mut writer, 9, &[])
            .await
            .expect("drain exec output should succeed");
        writer.shutdown().await.expect("shutdown should succeed");
        result
    });
    let mut contents = Vec::new();
    reader.read_to_end(&mut contents).await?;

    let result = drain.await?;
    assert_eq!(result.transferred_bytes, 9);
    assert_eq!(result.failure_output, "not part of dump");
    assert_eq!(contents, b"dump-tail");

    Ok(())
}

#[tokio::test]
async fn stderr_diagnostics_are_bounded_and_redacted() -> anyhow::Result<()> {
    let secret = "PASSWORD=do-not-log postgres://user:secret@localhost/db\n";
    let output = futures::stream::iter(vec![Ok(LogOutput::StdErr {
        message: Bytes::from(secret.repeat(1_000)),
    })]);

    let diagnostic = drain_exec_stderr(output, &["raw-secret-value".to_string()]).await?;

    assert!(diagnostic.len() <= EXEC_STREAM_FAILURE_DIAGNOSTIC_CHARS + 3);
    assert!(diagnostic.contains("PASSWORD=[redacted]"));
    assert!(!diagnostic.contains("do-not-log"));
    assert!(!diagnostic.contains("user:secret"));

    let output = futures::stream::iter(vec![Ok(LogOutput::StdErr {
        message: Bytes::from_static(b"client echoed raw-secret-value"),
    })]);
    let diagnostic = drain_exec_stderr(output, &["raw-secret-value".to_string()]).await?;
    assert_eq!(diagnostic, "client echoed [redacted]");

    Ok(())
}

#[tokio::test]
async fn output_drain_stops_before_writing_past_limit() {
    let output = futures::stream::iter(vec![Ok(LogOutput::StdOut {
        message: Bytes::from_static(b"oversized"),
    })]);
    let error = drain_exec_output(output, &mut tokio::io::sink(), 4, &[])
        .await
        .expect_err("sink should return an error");
    assert!(matches!(error, OutputDrainError::Limit));
}

#[test]
fn private_input_rejects_symlinks_and_oversized_files() -> anyhow::Result<()> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let regular = directory.path().join("dump.sql");
    let linked = directory.path().join("linked.sql");
    std::fs::write(&regular, b"contents")?;
    symlink(&regular, &linked)?;

    assert_eq!(open_private_input(&regular, 8)?.1, 8);
    assert!(matches!(
        open_private_input(&regular, 7).expect_err("open private input should return an error"),
        DockerError::ExecStreamInputTooLarge { .. }
    ));
    assert!(open_private_input(&linked, 8).is_err());

    Ok(())
}

#[tokio::test]
async fn verified_input_stays_bound_to_the_opened_file() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("dump.sql");
    let moved = directory.path().join("inspected.sql");
    let inspected = b"SELECT 1;";
    std::fs::write(&path, inspected)?;
    let expected: [u8; 32] = Sha256::digest(inspected).into();
    let (mut opened, size) = open_private_input(&path, 64)?;

    std::fs::rename(&path, &moved)?;
    std::fs::write(&path, b"SELECT malicious();")?;

    verify_private_input(&mut opened, size, 64, expected).await?;
    let mut contents = Vec::new();
    opened.read_to_end(&mut contents).await?;
    assert_eq!(contents, inspected);

    let (mut replacement, replacement_size) = open_private_input(&path, 64)?;
    let error = verify_private_input(&mut replacement, replacement_size, 64, expected)
        .await
        .expect_err("verify private input should return an error");
    assert_eq!(error.kind(), ErrorKind::InvalidData);

    Ok(())
}

#[tokio::test]
async fn verified_input_rejects_same_length_content_changes() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("dump.sql");
    std::fs::write(&path, b"safe")?;
    let expected: [u8; 32] = Sha256::digest(b"safe").into();
    let (mut opened, size) = open_private_input(&path, 4)?;
    std::fs::write(&path, b"evil")?;

    let error = verify_private_input(&mut opened, size, 4, expected)
        .await
        .expect_err("verify private input should return an error");
    assert_eq!(error.kind(), ErrorKind::InvalidData);

    Ok(())
}

#[tokio::test]
async fn private_output_is_create_new_private_and_durable_on_commit() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir()?;
    let output_path = directory.path().join("dump.sql");
    let mut output = PrivateOutputFile::create(&output_path)?;
    output.file_mut().write_all(b"contents").await?;
    output.commit().await?;

    assert_eq!(std::fs::read(&output_path)?, b"contents");
    assert_eq!(
        std::fs::metadata(&output_path)?.permissions().mode() & 0o777,
        0o600
    );
    assert!(PrivateOutputFile::create(&output_path).is_err());

    Ok(())
}

#[tokio::test]
async fn output_limit_removes_partial_private_file() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let output_path = directory.path().join("partial.sql");
    let output = futures::stream::iter(vec![
        Ok(LogOutput::StdOut {
            message: Bytes::from_static(b"part"),
        }),
        Ok(LogOutput::StdOut {
            message: Bytes::from_static(b"too-much"),
        }),
    ]);
    let mut file = PrivateOutputFile::create(&output_path)?;

    let error = drain_exec_output(output, file.file_mut(), 4, &[])
        .await
        .expect_err("file mut should return an error");
    assert!(matches!(error, OutputDrainError::Limit));
    drop(file);
    assert!(!output_path.exists());

    Ok(())
}

#[test]
fn dropping_uncommitted_output_removes_only_the_created_file() -> anyhow::Result<()> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let output_path = directory.path().join("partial.sql");
    let victim = directory.path().join("victim");
    std::fs::write(&victim, b"safe")?;
    drop(PrivateOutputFile::create(&output_path)?);
    assert!(!output_path.exists());

    symlink(&victim, &output_path)?;
    assert!(PrivateOutputFile::create(&output_path).is_err());
    assert_eq!(std::fs::read(victim)?, b"safe");

    Ok(())
}

#[tokio::test]
async fn cancellation_signal_notifies_the_detached_worker() -> anyhow::Result<()> {
    let (sender, receiver) = oneshot::channel();
    drop(CancellationSignal(Some(sender)));
    receiver.await?;

    Ok(())
}
