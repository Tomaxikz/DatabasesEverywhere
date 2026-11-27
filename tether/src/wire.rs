//! The header exchanged at the start of every stream.
//!
//! Opener to responder, all integers big-endian:
//!
//! ```text
//! magic    4 bytes  b"DBTE"
//! version  u16      MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION
//! length   u8       1..=MAX_TARGET_ID_LEN
//! target   length bytes, a valid TargetId
//! context  u16      0..=MAX_CONTEXT_LEN, then that many opaque bytes
//! ```
//!
//! The context is whatever the opening node wants its peer to know about the request, for
//! instance a tenant or the original client's address. It is an assertion by the
//! authenticated peer node: tether bounds and delivers it but does not verify it.
//!
//! Responder to opener: one [`Status`] byte. After `UnsupportedVersion` it is followed by a
//! u16 holding the highest version the responder supports, so a newer opener can tell what
//! to fall back to. After `Ok` the stream carries raw bytes in both directions; after
//! anything else the responder closes it.
//!
//! The readers consume exactly the header and nothing after it, so the payload that follows
//! is left for the caller. They apply no timeout: the caller bounds the whole exchange.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
    id::{MAX_TARGET_ID_LEN, TargetId},
};

pub const MAGIC: [u8; 4] = *b"DBTE";

/// Longest request context in bytes.
pub const MAX_CONTEXT_LEN: usize = 1024;

/// What the opener asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    pub target: TargetId,
    /// Opaque, at most [`MAX_CONTEXT_LEN`] bytes; an assertion by the opening node.
    pub context: Vec<u8>,
}

/// The responder's answer: a status and, for `UnsupportedVersion`, the highest version the
/// responder supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    pub status: Status,
    pub peer_max: Option<u16>,
}

/// The responder's answer. The numeric values are part of the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// The stream is connected to the target.
    Ok = 0,
    /// The responder does not speak the opener's protocol version.
    UnsupportedVersion = 1,
    /// The opener may not reach this target, or the target does not exist. The two are
    /// reported alike so a peer cannot probe for instance names.
    Denied = 2,
    /// The target exists and is allowed but cannot take a connection right now.
    Unavailable = 3,
    /// The header could not be parsed.
    Malformed = 4,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WireError {
    #[error("stream header I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("stream does not start with the tether magic")]
    BadMagic,
    #[error("peer speaks unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("stream header names an invalid target")]
    InvalidTarget,
    #[error("stream header announces a context longer than the maximum")]
    ContextTooLong,
    #[error("peer sent unknown status {0}")]
    UnknownStatus(u8),
}

impl WireError {
    /// The status a responder should send back for a header it could not accept, or `None`
    /// when the stream itself failed and nothing can be sent.
    pub fn status(&self) -> Option<Status> {
        match self {
            Self::BadMagic | Self::InvalidTarget | Self::ContextTooLong => Some(Status::Malformed),
            Self::UnsupportedVersion(_) => Some(Status::UnsupportedVersion),
            Self::Io(_) | Self::UnknownStatus(_) => None,
        }
    }
}

/// Fails with `InvalidInput` when the context exceeds [`MAX_CONTEXT_LEN`].
pub async fn write_open<W>(writer: &mut W, request: &OpenRequest) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let target = request.target.as_str().as_bytes();
    let context = request.context.as_slice();
    if context.len() > MAX_CONTEXT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request context is too long",
        ));
    }
    // One write, so the header leaves in as few packets as possible.
    let mut header = [0u8; 7 + MAX_TARGET_ID_LEN + 2 + MAX_CONTEXT_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    header[6] = target.len() as u8;
    let mut end = 7 + target.len();
    header[7..end].copy_from_slice(target);
    header[end..end + 2].copy_from_slice(&(context.len() as u16).to_be_bytes());
    end += 2;
    header[end..end + context.len()].copy_from_slice(context);
    end += context.len();
    writer.write_all(&header[..end]).await
}

pub async fn read_open<R>(reader: &mut R) -> Result<OpenRequest, WireError>
where
    R: AsyncRead + Unpin,
{
    let mut magic = [0; 4];
    reader.read_exact(&mut magic).await?;
    if magic != MAGIC {
        return Err(WireError::BadMagic);
    }
    let version = reader.read_u16().await?;
    if !(MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&version) {
        return Err(WireError::UnsupportedVersion(version));
    }
    let len = usize::from(reader.read_u8().await?);
    if len == 0 || len > MAX_TARGET_ID_LEN {
        return Err(WireError::InvalidTarget);
    }
    let mut target = [0; MAX_TARGET_ID_LEN];
    reader.read_exact(&mut target[..len]).await?;
    let target = std::str::from_utf8(&target[..len])
        .map_err(|_| WireError::InvalidTarget)?
        .parse()
        .map_err(|_| WireError::InvalidTarget)?;
    // The length is checked before anything is allocated for the bytes.
    let context_len = usize::from(reader.read_u16().await?);
    if context_len > MAX_CONTEXT_LEN {
        return Err(WireError::ContextTooLong);
    }
    let mut context = vec![0; context_len];
    reader.read_exact(&mut context).await?;
    Ok(OpenRequest { target, context })
}

/// Writes the status as one `write_all`. `UnsupportedVersion` carries the highest version
/// this build supports.
pub async fn write_status<W>(writer: &mut W, status: Status) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if status == Status::UnsupportedVersion {
        let version = PROTOCOL_VERSION.to_be_bytes();
        writer
            .write_all(&[status as u8, version[0], version[1]])
            .await
    } else {
        writer.write_all(&[status as u8]).await
    }
}

pub async fn read_status<R>(reader: &mut R) -> Result<Answer, WireError>
where
    R: AsyncRead + Unpin,
{
    let status = Status::try_from(reader.read_u8().await?)?;
    let peer_max = if status == Status::UnsupportedVersion {
        Some(reader.read_u16().await?)
    } else {
        None
    };
    Ok(Answer { status, peer_max })
}

impl TryFrom<u8> for Status {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::UnsupportedVersion),
            2 => Ok(Self::Denied),
            3 => Ok(Self::Unavailable),
            4 => Ok(Self::Malformed),
            other => Err(WireError::UnknownStatus(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> OpenRequest {
        OpenRequest {
            target: "inst_abc.1-2".parse().expect("valid target"),
            context: Vec::new(),
        }
    }

    fn with_context(context: Vec<u8>) -> OpenRequest {
        OpenRequest {
            context,
            ..request()
        }
    }

    const GOLDEN: &[u8] = b"DBTE\x00\x01\x0cinst_abc.1-2\x00\x00";

    #[tokio::test]
    async fn round_trip_preserves_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(2048);
        let sent = with_context(b"tenant=7".to_vec());
        write_open(&mut writer, &sent).await.expect("write header");
        writer.write_all(b"payload").await.expect("write payload");
        assert_eq!(read_open(&mut reader).await.expect("read header"), sent);
        let mut payload = [0; 7];
        reader.read_exact(&mut payload).await.expect("read payload");
        assert_eq!(&payload, b"payload");
    }

    #[tokio::test]
    async fn golden_header() {
        let (mut writer, mut reader) = tokio::io::duplex(2048);
        write_open(&mut writer, &request())
            .await
            .expect("write header");
        let mut bytes = [0; GOLDEN.len()];
        reader
            .read_exact(&mut bytes)
            .await
            .expect("read header bytes");
        assert_eq!(&bytes, GOLDEN);

        write_open(&mut writer, &with_context(b"xy".to_vec()))
            .await
            .expect("write header");
        let mut bytes = [0; GOLDEN.len() + 2];
        reader.read_exact(&mut bytes).await.expect("read bytes");
        assert_eq!(&bytes, b"DBTE\x00\x01\x0cinst_abc.1-2\x00\x02xy");
    }

    #[tokio::test]
    async fn context_may_be_exactly_the_maximum_and_no_longer() {
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let longest = with_context(vec![0xA5; MAX_CONTEXT_LEN]);
        write_open(&mut writer, &longest).await.expect("write");
        assert_eq!(read_open(&mut reader).await.expect("read"), longest);

        let too_long = with_context(vec![0; MAX_CONTEXT_LEN + 1]);
        let error = write_open(&mut writer, &too_long)
            .await
            .expect_err("one over");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        // A hostile header announcing one byte too many is refused before its bytes are
        // read: none follow here, so a reader that tried would fail with EOF instead.
        let mut bytes = GOLDEN[..GOLDEN.len() - 2].to_vec();
        bytes.extend_from_slice(&(MAX_CONTEXT_LEN as u16 + 1).to_be_bytes());
        assert!(matches!(
            read_open(&mut &bytes[..]).await,
            Err(WireError::ContextTooLong)
        ));
        assert_eq!(WireError::ContextTooLong.status(), Some(Status::Malformed));
    }

    #[tokio::test]
    async fn rejects_headers_in_order() {
        assert!(matches!(
            read_open(&mut &b"BAD!"[..]).await,
            Err(WireError::BadMagic)
        ));
        for version in [0u8, 2] {
            let bytes = [b'D', b'B', b'T', b'E', 0, version];
            assert!(matches!(
                read_open(&mut &bytes[..]).await,
                Err(WireError::UnsupportedVersion(v)) if v == u16::from(version)
            ));
        }
        for len in [0, 129] {
            let bytes = [b'D', b'B', b'T', b'E', 0, 1, len];
            assert!(matches!(
                read_open(&mut &bytes[..]).await,
                Err(WireError::InvalidTarget)
            ));
        }
        for byte in [0xff, b'/', b' '] {
            let bytes = [b'D', b'B', b'T', b'E', 0, 1, 1, byte];
            assert!(matches!(
                read_open(&mut &bytes[..]).await,
                Err(WireError::InvalidTarget)
            ));
        }
    }

    #[tokio::test]
    async fn every_truncated_prefix_is_unexpected_eof() {
        let mut bytes = GOLDEN[..GOLDEN.len() - 2].to_vec();
        bytes.extend_from_slice(b"\x00\x03abc");
        for end in 0..bytes.len() {
            match read_open(&mut &bytes[..end]).await {
                Err(WireError::Io(error)) => {
                    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "prefix {end}")
                }
                other => panic!("prefix {end}: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn reading_the_header_consumes_nothing_after_it() {
        let mut bytes = GOLDEN.to_vec();
        bytes.extend_from_slice(b"rest");
        let mut reader = &bytes[..];
        read_open(&mut reader).await.expect("header");
        assert_eq!(reader, b"rest");
    }

    #[tokio::test]
    async fn status_values_round_trip() {
        let statuses = [
            Status::Ok,
            Status::UnsupportedVersion,
            Status::Denied,
            Status::Unavailable,
            Status::Malformed,
        ];
        for (byte, status) in (0u8..).zip(statuses) {
            let (mut writer, mut reader) = tokio::io::duplex(8);
            write_status(&mut writer, status)
                .await
                .expect("write status");
            assert_eq!(reader.read_u8().await.expect("read byte"), byte);
            let trailer = [0u8, PROTOCOL_VERSION as u8];
            let wire = [&[byte][..], &trailer].concat();
            let answer = read_status(&mut &wire[..]).await.expect("read status");
            assert_eq!(answer.status, status);
            assert_eq!(
                answer.peer_max,
                (status == Status::UnsupportedVersion).then_some(PROTOCOL_VERSION)
            );
        }
        assert!(matches!(
            read_status(&mut &[255][..]).await,
            Err(WireError::UnknownStatus(255))
        ));
    }

    #[tokio::test]
    async fn unsupported_version_carries_the_highest_supported_version() {
        let (mut writer, mut reader) = tokio::io::duplex(8);
        write_status(&mut writer, Status::UnsupportedVersion)
            .await
            .expect("write");
        let mut bytes = [0; 3];
        reader.read_exact(&mut bytes).await.expect("read");
        assert_eq!(bytes, [1, 0, PROTOCOL_VERSION as u8]);
        // A status that stops short of its version is a failed stream, not a status.
        assert!(matches!(
            read_status(&mut &[1u8, 0][..]).await,
            Err(WireError::Io(_))
        ));
    }

    #[test]
    fn error_status_mapping() {
        assert_eq!(WireError::BadMagic.status(), Some(Status::Malformed));
        assert_eq!(WireError::InvalidTarget.status(), Some(Status::Malformed));
        assert_eq!(
            WireError::UnsupportedVersion(2).status(),
            Some(Status::UnsupportedVersion)
        );
        assert_eq!(WireError::UnknownStatus(255).status(), None);
        assert_eq!(
            WireError::Io(io::Error::from(io::ErrorKind::UnexpectedEof)).status(),
            None
        );
    }
}
