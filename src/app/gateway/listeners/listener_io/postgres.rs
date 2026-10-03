use super::*;

/// Proxies authenticated PostgreSQL frontend frames without buffering query
/// bodies. Only complete Query and Execute messages affect activity counters.
pub(in super::super) async fn proxy_postgres_session<C, B>(
    client: C,
    backend: B,
    activity: Arc<ActivityCounter>,
) -> Result<(), ListenerError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let _activity_session = ActivitySession::open(Arc::clone(&activity));
    let (mut client_read, mut client_write) = io::split(client);
    let (mut backend_read, mut backend_write) = io::split(backend);
    let upload = async {
        loop {
            let mut header = [0_u8; 5];
            if client_read.read(&mut header[..1]).await? == 0 {
                backend_write.shutdown().await?;
                return Ok::<(), ListenerError>(());
            }
            client_read.read_exact(&mut header[1..]).await?;
            let len = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
            if len < 4 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "postgres frontend message length is smaller than its header",
                )
                .into());
            }
            backend_write.write_all(&header).await?;
            let remaining = len - 4;
            let prefix_len = remaining.min(SQL_PREFIX_BYTES);
            let mut prefix = [0_u8; SQL_PREFIX_BYTES];
            client_read.read_exact(&mut prefix[..prefix_len]).await?;
            backend_write.write_all(&prefix[..prefix_len]).await?;
            copy_exact(
                &mut client_read,
                &mut backend_write,
                remaining - prefix_len,
                "postgres frontend message ended before its declared length",
            )
            .await?;
            match header[0] {
                b'Q' => activity.accept(classify_sql(&prefix[..prefix_len])),
                b'E' => activity.accept(OperationKind::Other),
                _ => {}
            }
        }
    };
    let download = async {
        io::copy(&mut backend_read, &mut client_write).await?;
        client_write.shutdown().await?;
        Ok::<(), ListenerError>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}
