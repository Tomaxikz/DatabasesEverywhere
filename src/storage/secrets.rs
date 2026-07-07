use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const PREFIX: &str = "dbev1";
const KEY_FILE_NAME: &str = "metadata.key";

#[derive(Debug, Clone)]
pub struct SecretStore {
    key: LessSafeKey,
}

impl SecretStore {
    pub fn open_or_create(metadata_root: &Path) -> Result<Self, SecretStoreError> {
        fs::create_dir_all(metadata_root).map_err(|source| SecretStoreError::CreateDir {
            path: metadata_root.to_path_buf(),
            source,
        })?;
        harden_dir(metadata_root)?;

        let key_path = metadata_root.join(KEY_FILE_NAME);
        let key_bytes = if key_path.exists() {
            read_key(&key_path)?
        } else {
            create_key(&key_path)?
        };
        let unbound = UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
            .map_err(|_| SecretStoreError::Crypto("failed to initialize metadata key".into()))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
        })
    }

    pub fn encrypt(
        &self,
        field: &str,
        instance_id: &str,
        value: &str,
    ) -> Result<String, SecretStoreError> {
        if value.starts_with(PREFIX) {
            return Ok(value.to_string());
        }

        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| SecretStoreError::Crypto("failed to generate metadata nonce".into()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut bytes = value.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aad(field, instance_id), &mut bytes)
            .map_err(|_| SecretStoreError::Crypto("failed to encrypt metadata secret".into()))?;
        Ok(format!(
            "{PREFIX}:{}:{}",
            URL_SAFE_NO_PAD.encode(nonce_bytes),
            URL_SAFE_NO_PAD.encode(bytes)
        ))
    }

    pub fn decrypt(
        &self,
        field: &str,
        instance_id: &str,
        value: &str,
    ) -> Result<String, SecretStoreError> {
        let Some(rest) = value
            .strip_prefix(PREFIX)
            .and_then(|value| value.strip_prefix(':'))
        else {
            return Ok(value.to_string());
        };
        let (nonce, ciphertext) = rest
            .split_once(':')
            .ok_or(SecretStoreError::InvalidCiphertext)?;
        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(nonce)
            .map_err(|_| SecretStoreError::InvalidCiphertext)?;
        let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| SecretStoreError::InvalidCiphertext)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut bytes = URL_SAFE_NO_PAD
            .decode(ciphertext)
            .map_err(|_| SecretStoreError::InvalidCiphertext)?;
        let plaintext = self
            .key
            .open_in_place(nonce, aad(field, instance_id), &mut bytes)
            .map_err(|_| SecretStoreError::InvalidCiphertext)?;
        String::from_utf8(plaintext.to_vec()).map_err(|_| SecretStoreError::InvalidCiphertext)
    }
}

pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(PREFIX) && value.as_bytes().get(PREFIX.len()) == Some(&b':')
}

fn aad(field: &str, instance_id: &str) -> Aad<Vec<u8>> {
    Aad::from(format!("{instance_id}:{field}").into_bytes())
}

fn read_key(path: &Path) -> Result<[u8; KEY_LEN], SecretStoreError> {
    harden_file(path)?;
    let contents = fs::read_to_string(path).map_err(|source| SecretStoreError::ReadKey {
        path: path.to_path_buf(),
        source,
    })?;
    decode_key(path, contents.trim())
}

fn create_key(path: &Path) -> Result<[u8; KEY_LEN], SecretStoreError> {
    let rng = SystemRandom::new();
    let mut key = [0u8; KEY_LEN];
    rng.fill(&mut key)
        .map_err(|_| SecretStoreError::Crypto("failed to generate metadata key".into()))?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| SecretStoreError::WriteKey {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(URL_SAFE_NO_PAD.encode(key).as_bytes())
        .map_err(|source| SecretStoreError::WriteKey {
            path: path.to_path_buf(),
            source,
        })?;
    file.sync_all()
        .map_err(|source| SecretStoreError::WriteKey {
            path: path.to_path_buf(),
            source,
        })?;
    harden_file(path)?;
    Ok(key)
}

fn decode_key(path: &Path, encoded: &str) -> Result<[u8; KEY_LEN], SecretStoreError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SecretStoreError::InvalidKey {
            path: path.to_path_buf(),
        })?;
    bytes.try_into().map_err(|_| SecretStoreError::InvalidKey {
        path: path.to_path_buf(),
    })
}

fn harden_dir(path: &Path) -> Result<(), SecretStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            SecretStoreError::SetPermissions {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    Ok(())
}

fn harden_file(path: &Path) -> Result<(), SecretStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            SecretStoreError::SetPermissions {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("failed to create metadata directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read metadata encryption key {path}: {source}")]
    ReadKey {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write metadata encryption key {path}: {source}")]
    WriteKey {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to set permissions on {path}: {source}")]
    SetPermissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("metadata encryption key {path} is invalid")]
    InvalidKey { path: PathBuf },
    #[error("encrypted metadata secret is invalid or was encrypted with a different key")]
    InvalidCiphertext,
    #[error("{0}")]
    Crypto(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_secret_and_binds_aad() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open_or_create(dir.path()).unwrap();

        let encrypted = store
            .encrypt("mongodb_root_password", "inst_1", "secret")
            .unwrap();

        assert!(is_encrypted(&encrypted));
        assert!(!encrypted.contains("secret"));
        assert_eq!(
            store
                .decrypt("mongodb_root_password", "inst_1", &encrypted)
                .unwrap(),
            "secret"
        );
        assert!(
            store
                .decrypt("mongodb_root_password", "inst_2", &encrypted)
                .is_err()
        );
    }
}
