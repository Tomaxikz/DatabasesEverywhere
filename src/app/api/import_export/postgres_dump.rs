//! PostgreSQL `pg_dump` safety-wrapper discovery.

use std::{
    io::{Error, ErrorKind, Read, Seek, SeekFrom},
    path::Path,
};

use super::ApiError;

const WRAPPER_SCAN_BYTES: u64 = 64 * 1024;
const RESTRICT_TOKEN_MAX_BYTES: usize = 256;

pub(super) async fn wrapper_lines(
    path: &Path,
    expected_bytes: u64,
) -> Result<Option<(u64, u64)>, ApiError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || wrapper_lines_blocking(&path, expected_bytes))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to join PostgreSQL dump wrapper inspection: {error}"
            ))
        })?
        .map_err(|error| {
            if error.kind() == ErrorKind::InvalidData {
                ApiError::BadRequest(format!(
                    "PostgreSQL dump has an invalid psql safety wrapper: {error}"
                ))
            } else {
                ApiError::Runtime(format!(
                    "failed to inspect PostgreSQL dump safety wrapper: {error}"
                ))
            }
        })
}

fn wrapper_lines_blocking(path: &Path, expected_bytes: u64) -> Result<Option<(u64, u64)>, Error> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(invalid_wrapper("the prepared source is not a regular file"));
    }
    let mut file = std::fs::File::open(path)?;
    let initial_bytes = file.metadata()?.len();
    if initial_bytes != expected_bytes {
        return Err(invalid_wrapper(
            "the prepared source size changed before inspection",
        ));
    }

    let prefix_bytes = initial_bytes.min(WRAPPER_SCAN_BYTES) as usize;
    let mut prefix = vec![0_u8; prefix_bytes];
    file.read_exact(&mut prefix)?;
    let Some((restrict_line, token)) =
        find_restrict_line(&prefix, initial_bytes <= WRAPPER_SCAN_BYTES)?
    else {
        return Ok(None);
    };

    let suffix_start = initial_bytes.saturating_sub(WRAPPER_SCAN_BYTES);
    let read_start = suffix_start.saturating_sub(1);
    file.seek(SeekFrom::Start(read_start))?;
    let suffix_len = usize::try_from(initial_bytes.saturating_sub(read_start))
        .map_err(|_| invalid_wrapper("the PostgreSQL dump suffix length overflowed"))?;
    let mut suffix = vec![0_u8; suffix_len];
    file.read_exact(&mut suffix)?;
    let unrestrict_offset = find_unrestrict_offset(&suffix, read_start, &token)?;
    let unrestrict_line = line_number_at_offset(&mut file, unrestrict_offset)?;
    if unrestrict_line <= restrict_line {
        return Err(invalid_wrapper(
            "the matching unrestrict command precedes the restrict command",
        ));
    }
    if file.metadata()?.len() != initial_bytes {
        return Err(invalid_wrapper(
            "the prepared source size changed during inspection",
        ));
    }
    Ok(Some((restrict_line, unrestrict_line)))
}

fn find_restrict_line(
    prefix: &[u8],
    prefix_reaches_eof: bool,
) -> Result<Option<(u64, Vec<u8>)>, Error> {
    let mut found = None;
    let mut start = 0_usize;
    let mut line_number = 1_u64;
    while start < prefix.len() {
        let newline = prefix[start..].iter().position(|byte| *byte == b'\n');
        let end = match newline {
            Some(relative) => start + relative + 1,
            None if prefix_reaches_eof => prefix.len(),
            None => break,
        };
        let line = normalized_line(&prefix[start..end]);
        if let Some(token) = line.strip_prefix(b"\\restrict ") {
            if token.is_empty()
                || token.len() > RESTRICT_TOKEN_MAX_BYTES
                || !token.iter().all(u8::is_ascii_graphic)
            {
                return Err(invalid_wrapper(
                    "the restrict key is empty, oversized, or contains whitespace",
                ));
            }
            if found.is_some() {
                return Err(invalid_wrapper(
                    "multiple restrict commands occur in the dump header",
                ));
            }
            found = Some((line_number, token.to_vec()));
        }
        start = end;
        line_number = line_number.saturating_add(1);
    }
    Ok(found)
}

fn find_unrestrict_offset(suffix: &[u8], absolute_start: u64, token: &[u8]) -> Result<u64, Error> {
    let mut expected = b"\\unrestrict ".to_vec();
    expected.extend_from_slice(token);
    let mut found = None;
    let mut start = if absolute_start == 0 {
        0
    } else {
        suffix
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|position| position + 1)
            .ok_or_else(|| invalid_wrapper("the dump footer is not line-delimited"))?
    };
    while start < suffix.len() {
        let end = suffix[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(suffix.len(), |relative| start + relative + 1);
        let line = normalized_line(&suffix[start..end]);
        if line.starts_with(b"\\unrestrict ") {
            if line != expected {
                return Err(invalid_wrapper(
                    "the dump footer uses a different unrestrict key",
                ));
            }
            if found.is_some() {
                return Err(invalid_wrapper(
                    "multiple matching unrestrict commands occur in the dump footer",
                ));
            }
            found = Some(absolute_start.saturating_add(start as u64));
        }
        start = end;
    }
    found.ok_or_else(|| invalid_wrapper("the dump header restrict command has no matching footer"))
}

fn normalized_line(mut line: &[u8]) -> &[u8] {
    if line.ends_with(b"\n") {
        line = &line[..line.len() - 1];
    }
    if line.ends_with(b"\r") {
        line = &line[..line.len() - 1];
    }
    line
}

fn line_number_at_offset(file: &mut std::fs::File, offset: u64) -> Result<u64, Error> {
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = offset;
    let mut line = 1_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = file.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(invalid_wrapper(
                "the dump ended while locating its safety footer",
            ));
        }
        line = line
            .checked_add(buffer[..read].iter().filter(|byte| **byte == b'\n').count() as u64)
            .ok_or_else(|| invalid_wrapper("the dump line count overflowed"))?;
        remaining -= read as u64;
    }
    Ok(line)
}

fn invalid_wrapper(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_matched_wrapper_across_a_large_dump() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dump.sql");
        let mut dump = String::from("-- PostgreSQL database dump\n\\restrict officialKey123\n");
        for _ in 0..8_000 {
            dump.push_str("SELECT 1;\n");
        }
        dump.push_str("\\unrestrict officialKey123\n-- PostgreSQL database dump complete\n");
        std::fs::write(&path, dump.as_bytes()).unwrap();

        assert_eq!(
            wrapper_lines_blocking(&path, dump.len() as u64).unwrap(),
            Some((2, 8_003))
        );
    }

    #[test]
    fn accepts_older_plain_dumps_without_a_wrapper() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dump.sql");
        let dump = b"-- PostgreSQL database dump\nSELECT 1;\n";
        std::fs::write(&path, dump).unwrap();

        assert_eq!(
            wrapper_lines_blocking(&path, dump.len() as u64).unwrap(),
            None
        );
    }

    #[test]
    fn rejects_mismatched_or_incomplete_wrappers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dump.sql");
        let mismatch = b"\\restrict first\nSELECT 1;\n\\unrestrict second\n";
        std::fs::write(&path, mismatch).unwrap();
        assert_eq!(
            wrapper_lines_blocking(&path, mismatch.len() as u64)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        let incomplete = b"\\restrict first\nSELECT 1;\n";
        std::fs::write(&path, incomplete).unwrap();
        assert_eq!(
            wrapper_lines_blocking(&path, incomplete.len() as u64)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }
}
