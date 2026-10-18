//! SHA-256 helpers shared by artifacts, backups and helper verification.

use std::io::Read;

use sha2::{Digest, Sha256};

const READ_BUFFER_BYTES: usize = 64 * 1024;

/// Lowercase hex SHA-256 of everything `reader` yields.
pub(crate) fn sha256_reader(mut reader: impl Read) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; READ_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn hashes_streams_like_the_one_shot_digest() {
        let data = vec![7_u8; 200_000];
        assert_eq!(
            super::sha256_reader(&data[..]).unwrap(),
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&data))
        );
    }
}
