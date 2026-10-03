use std::collections::BTreeSet;

use sha2::{Digest, Sha256, digest::Output};
use uuid::Uuid;

use super::{MAX_OBJECTS, MAX_SCHEMA_BYTES, ManifestError};
use crate::{databases::protocol::Protocol, utils::hex::encode_lower};

const MANIFEST_VERSION: &[u8] = b"dbev-tenant-integrity-v2";
const SCHEMA_VERSION: &[u8] = b"dbev-tenant-schema-v2";
const DATA_VERSION: &[u8] = b"dbev-tenant-data-v2";
const ROW_VERSION: &[u8] = b"dbev-tenant-row-v2";
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_OBJECT_KEY_BYTES: usize = 4_096;
const DIGEST_WORDS: usize = 4;
const DIGEST_TSV_FIELDS: usize = 1 + 2 * DIGEST_WORDS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManifestChallenge(pub [u8; 32]);

impl ManifestChallenge {
    pub(crate) fn random() -> Self {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut bytes = [0_u8; 32];
        bytes[..16].copy_from_slice(first.as_bytes());
        bytes[16..].copy_from_slice(second.as_bytes());
        Self(bytes)
    }

    pub(super) fn hex(self) -> String {
        encode_lower(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantManifest {
    pub challenge: ManifestChallenge,
    pub object_count: u64,
    pub counted_object_count: u64,
    pub row_count: u64,
    pub schema_sha256: String,
    pub data_sha256: String,
    pub fingerprint_sha256: String,
}

#[derive(Debug, Default)]
pub(super) struct CollectedManifest {
    pub schema: Vec<SchemaRecord>,
    pub data: Vec<DataRecord>,
}

impl CollectedManifest {
    pub(super) fn push_schema(&mut self, record: SchemaRecord) -> Result<(), ManifestError> {
        if self.schema.len() >= MAX_OBJECTS {
            return Err(ManifestError::ObjectLimit(MAX_OBJECTS));
        }
        self.schema.push(record);
        Ok(())
    }

    pub(super) fn push_data(&mut self, record: DataRecord) -> Result<(), ManifestError> {
        if self.data.len() >= MAX_OBJECTS {
            return Err(ManifestError::ObjectLimit(MAX_OBJECTS));
        }
        self.data.push(record);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SchemaRecord {
    key: Vec<u8>,
    value: Vec<u8>,
}

impl SchemaRecord {
    pub(super) fn new(
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<Self, ManifestError> {
        let key = key.into();
        let value = value.into();
        validate_record(&key, &value)?;
        Ok(Self { key, value })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct DataRecord {
    key: Vec<u8>,
    digest: MultisetDigest,
}

impl DataRecord {
    pub(super) fn new(
        key: impl Into<Vec<u8>>,
        digest: MultisetDigest,
    ) -> Result<Self, ManifestError> {
        let key = key.into();
        validate_record(&key, &[])?;
        Ok(Self { key, digest })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct MultisetDigest {
    pub count: u64,
    pub sums: [u64; 4],
    pub xors: [u64; 4],
}

impl MultisetDigest {
    pub(super) fn parse_tsv(output: &str) -> Result<Self, ManifestError> {
        let mut lines = output.lines().filter(|line| !line.trim().is_empty());
        let line = lines
            .next()
            .ok_or(ManifestError::InvalidCatalog("missing content digest"))?;
        if lines.next().is_some() {
            return Err(ManifestError::InvalidCatalog(
                "multiple content digests returned",
            ));
        }
        let fields = line.trim().split('\t').collect::<Vec<_>>();
        if fields.len() != DIGEST_TSV_FIELDS {
            return Err(ManifestError::InvalidCatalog(
                "invalid content digest shape",
            ));
        }
        let count = parse_u64(fields[0], "invalid content row count")?;
        let sum_fields = &fields[1..=DIGEST_WORDS];
        let xor_fields = &fields[1 + DIGEST_WORDS..];
        let mut sums = [0_u64; DIGEST_WORDS];
        let mut xors = [0_u64; DIGEST_WORDS];
        for index in 0..DIGEST_WORDS {
            sums[index] = parse_u64(sum_fields[index], "invalid content digest sum")?;
            xors[index] = parse_word(xor_fields[index])?;
        }
        Ok(Self { count, sums, xors })
    }
}

#[derive(Debug)]
pub(super) struct MultisetAccumulator {
    count: u64,
    sums: [u64; 4],
    xors: [u64; 4],
}

pub(super) fn object_key(kind: &str, parts: &[&str]) -> Vec<u8> {
    let mut key = Vec::new();
    push_key_part(&mut key, kind.as_bytes());
    for part in parts {
        push_key_part(&mut key, part.as_bytes());
    }
    key
}

impl MultisetAccumulator {
    pub(super) fn new() -> Self {
        Self {
            count: 0,
            sums: [0; 4],
            xors: [0; 4],
        }
    }

    pub(super) fn add(
        &mut self,
        challenge: ManifestChallenge,
        object_key: &[u8],
        value: &[u8],
    ) -> Result<(), ManifestError> {
        let mut hasher = Sha256::new();
        hasher.update(ROW_VERSION);
        hasher.update(challenge.0);
        hash_field(&mut hasher, object_key);
        hash_field(&mut hasher, value);
        let digest = hasher.finalize();
        self.count = self
            .count
            .checked_add(1)
            .ok_or(ManifestError::RowCountOverflow)?;
        for (index, chunk) in digest.as_chunks::<8>().0.iter().enumerate() {
            let word = u64::from_be_bytes(*chunk);
            self.sums[index] = self.sums[index].wrapping_add(word);
            self.xors[index] ^= word;
        }
        Ok(())
    }

    pub(super) fn finish(self) -> MultisetDigest {
        MultisetDigest {
            count: self.count,
            sums: self.sums,
            xors: self.xors,
        }
    }
}

pub(super) fn finish(
    protocol: Protocol,
    challenge: ManifestChallenge,
    mut collected: CollectedManifest,
) -> Result<TenantManifest, ManifestError> {
    collected.schema.sort();
    collected.data.sort();
    reject_duplicate_keys(collected.schema.iter().map(|record| record.key.as_slice()))?;
    reject_duplicate_keys(collected.data.iter().map(|record| record.key.as_slice()))?;

    check_schema_size(&collected.schema)?;
    let schema_digest = schema_digest(protocol, &collected.schema);
    let (row_count, data_digest) = data_digest(protocol, challenge, &collected.data)?;

    let mut manifest_hasher = Sha256::new();
    manifest_hasher.update(MANIFEST_VERSION);
    hash_field(&mut manifest_hasher, protocol.as_str().as_bytes());
    manifest_hasher.update(challenge.0);
    manifest_hasher.update(schema_digest);
    manifest_hasher.update(data_digest);

    Ok(TenantManifest {
        challenge,
        object_count: collected.schema.len() as u64,
        counted_object_count: collected.data.len() as u64,
        row_count,
        schema_sha256: encode_lower(&schema_digest),
        data_sha256: encode_lower(&data_digest),
        fingerprint_sha256: encode_lower(&manifest_hasher.finalize()),
    })
}

fn check_schema_size(schema: &[SchemaRecord]) -> Result<(), ManifestError> {
    let schema_bytes = schema.iter().try_fold(0_usize, |total, record| {
        total
            .checked_add(record.key.len())
            .and_then(|value| value.checked_add(record.value.len()))
            .ok_or(ManifestError::SchemaLimit(MAX_SCHEMA_BYTES))
    })?;
    if schema_bytes > MAX_SCHEMA_BYTES {
        return Err(ManifestError::SchemaLimit(MAX_SCHEMA_BYTES));
    }
    Ok(())
}

fn schema_digest(protocol: Protocol, schema: &[SchemaRecord]) -> Output<Sha256> {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION);
    hash_field(&mut hasher, protocol.as_str().as_bytes());
    hasher.update((schema.len() as u64).to_be_bytes());
    for record in schema {
        hash_field(&mut hasher, &record.key);
        hash_field(&mut hasher, &record.value);
    }
    hasher.finalize()
}

fn data_digest(
    protocol: Protocol,
    challenge: ManifestChallenge,
    data: &[DataRecord],
) -> Result<(u64, Output<Sha256>), ManifestError> {
    let mut row_count = 0_u64;
    let mut hasher = Sha256::new();
    hasher.update(DATA_VERSION);
    hash_field(&mut hasher, protocol.as_str().as_bytes());
    hasher.update(challenge.0);
    hasher.update((data.len() as u64).to_be_bytes());
    for record in data {
        row_count = row_count
            .checked_add(record.digest.count)
            .ok_or(ManifestError::RowCountOverflow)?;
        hash_field(&mut hasher, &record.key);
        hasher.update(record.digest.count.to_be_bytes());
        for word in record.digest.sums {
            hasher.update(word.to_be_bytes());
        }
        for word in record.digest.xors {
            hasher.update(word.to_be_bytes());
        }
    }
    Ok((row_count, hasher.finalize()))
}

fn validate_record(key: &[u8], value: &[u8]) -> Result<(), ManifestError> {
    if key.is_empty() || key.len() > MAX_OBJECT_KEY_BYTES {
        return Err(ManifestError::InvalidCatalog("invalid manifest object key"));
    }
    if value.len() > MAX_RECORD_BYTES {
        return Err(ManifestError::SchemaLimit(MAX_RECORD_BYTES));
    }
    Ok(())
}

fn push_key_part(key: &mut Vec<u8>, value: &[u8]) {
    key.extend_from_slice(&(value.len() as u64).to_be_bytes());
    key.extend_from_slice(value);
}

fn reject_duplicate_keys<'a>(keys: impl Iterator<Item = &'a [u8]>) -> Result<(), ManifestError> {
    let mut seen = BTreeSet::new();
    for key in keys {
        if !seen.insert(key) {
            return Err(ManifestError::InvalidCatalog(
                "duplicate manifest object key",
            ));
        }
    }
    Ok(())
}

fn parse_u64(value: &str, error: &'static str) -> Result<u64, ManifestError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ManifestError::InvalidCatalog(error));
    }
    value
        .parse()
        .map_err(|_| ManifestError::InvalidCatalog(error))
}

fn parse_word(value: &str) -> Result<u64, ManifestError> {
    if value.starts_with('-') {
        value
            .parse::<i64>()
            .map(|word| word as u64)
            .map_err(|_| ManifestError::InvalidCatalog("invalid signed content digest word"))
    } else {
        parse_u64(value, "invalid content digest word")
    }
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge() -> ManifestChallenge {
        ManifestChallenge([7; 32])
    }

    fn schema(key: &str, value: &str) -> SchemaRecord {
        SchemaRecord::new(key, value).unwrap()
    }

    fn data(key: &str, values: &[&[u8]]) -> DataRecord {
        let mut digest = MultisetAccumulator::new();
        for value in values {
            digest.add(challenge(), key.as_bytes(), value).unwrap();
        }
        DataRecord::new(key, digest.finish()).unwrap()
    }

    #[test]
    fn manifest_is_independent_of_object_and_row_order() {
        let first = CollectedManifest {
            schema: vec![schema("table/b", "two"), schema("table/a", "one")],
            data: vec![data("table/a", &[b"one", b"two", b"one"])],
        };
        let second = CollectedManifest {
            schema: vec![schema("table/a", "one"), schema("table/b", "two")],
            data: vec![data("table/a", &[b"one", b"one", b"two"])],
        };
        assert_eq!(
            finish(Protocol::Postgres, challenge(), first).unwrap(),
            finish(Protocol::Postgres, challenge(), second).unwrap()
        );
    }

    #[test]
    fn duplicate_rows_do_not_cancel_and_same_count_value_changes_are_detected() {
        let duplicate = finish(
            Protocol::Postgres,
            challenge(),
            CollectedManifest {
                schema: vec![schema("table/a", "ddl")],
                data: vec![data("table/a", &[b"same", b"same"])],
            },
        )
        .unwrap();
        let changed = finish(
            Protocol::Postgres,
            challenge(),
            CollectedManifest {
                schema: vec![schema("table/a", "ddl")],
                data: vec![data("table/a", &[b"same", b"other"])],
            },
        )
        .unwrap();
        assert_eq!(duplicate.row_count, changed.row_count);
        assert_ne!(duplicate.data_sha256, changed.data_sha256);
        assert_ne!(duplicate.fingerprint_sha256, changed.fingerprint_sha256);
    }

    #[test]
    fn ddl_and_index_definition_changes_are_detected() {
        let before = finish(
            Protocol::Mysql,
            challenge(),
            CollectedManifest {
                schema: vec![schema("table/a", "INDEX i (a)")],
                data: vec![],
            },
        )
        .unwrap();
        let after = finish(
            Protocol::Mysql,
            challenge(),
            CollectedManifest {
                schema: vec![schema("table/a", "UNIQUE INDEX i (a,b)")],
                data: vec![],
            },
        )
        .unwrap();
        assert_ne!(before.schema_sha256, after.schema_sha256);
        assert_ne!(before.fingerprint_sha256, after.fingerprint_sha256);
    }

    #[test]
    fn signed_database_words_preserve_all_64_bits() {
        assert_eq!(parse_word("-9223372036854775808").unwrap(), 1_u64 << 63);
        assert_eq!(parse_word("18446744073709551615").unwrap(), u64::MAX);
        assert!(parse_word("-9223372036854775809").is_err());
    }
}
