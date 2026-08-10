use std::{
    collections::BTreeSet,
    io::{self, Read},
    time::Instant,
};

use bson::raw::{RawBsonRef, RawDocument};

use super::{BoundedReader, InspectionError, MAX_INSPECTED_BYTES, MAX_NAMESPACES, ensure_deadline};

// Literal on-disk bytes from the mongo-tools archive specification. Keeping
// these as bytes avoids accidentally reversing the documented representation.
const ARCHIVE_MAGIC: [u8; 4] = [0x6d, 0xe2, 0x99, 0x81];
const ARCHIVE_TERMINATOR: u32 = u32::MAX;
const ARCHIVE_FORMAT_VERSION: &str = "0.1";
const MAX_BSON_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_BSON_NESTING_DEPTH: usize = 128;
const MAX_METADATA_DOCUMENTS: usize = 4_096;
const MAX_PRELUDE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct MongoArchiveCatalog {
    pub(super) databases: Vec<String>,
    pub(super) complete: bool,
}

pub(super) fn inspect_native_gzip<R: Read>(
    reader: R,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    // mongo-tools uses Go's multistream gzip reader, so valid concatenated
    // members are accepted. Unlike GzDecoder, MultiGzDecoder also reaches the
    // underlying EOF and therefore rejects truncated members and trailing junk.
    let decoder = flate2::read::MultiGzDecoder::new(reader);
    let mut bounded = BoundedReader::new(decoder, MAX_INSPECTED_BYTES, deadline);
    let catalog = inspect_native_archive(&mut bounded, deadline)?;
    io::copy(&mut bounded, &mut io::sink()).map_err(|error| {
        super::map_mongodb_read_error(
            error,
            "MongoDB upload contains a malformed native gzip archive",
        )
    })?;
    Ok(catalog)
}

fn inspect_native_archive<R: Read>(
    reader: &mut R,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    ensure_deadline(deadline)?;
    let mut magic = [0_u8; 4];
    read_exact_archive(reader, &mut magic)?;
    if magic != ARCHIVE_MAGIC {
        return Err(InspectionError::Invalid(
            "MongoDB upload is not a native mongodump archive",
        ));
    }

    let mut prelude_bytes = 4_usize;
    let header = read_bson_document(reader, deadline, &mut prelude_bytes)?.ok_or(
        InspectionError::Invalid("MongoDB archive is missing its prelude header"),
    )?;
    validate_header(&header)?;

    let mut databases = BTreeSet::new();
    let mut complete = true;
    let mut metadata_count = 0_usize;
    loop {
        ensure_deadline(deadline)?;
        let Some(metadata) = read_bson_document(reader, deadline, &mut prelude_bytes)? else {
            break;
        };
        metadata_count = metadata_count.saturating_add(1);
        if metadata_count > MAX_METADATA_DOCUMENTS {
            return Err(InspectionError::Limit(
                "MongoDB archive prelude contains too many collection records",
            ));
        }
        let database = parse_metadata(&metadata)?;
        if database.is_empty() || is_system_database(database) {
            continue;
        }
        if !safe_source_database(database) {
            complete = false;
            continue;
        }
        databases.insert(database.to_string());
        if databases.len() > MAX_NAMESPACES {
            databases.pop_last();
            complete = false;
        }
    }

    Ok(MongoArchiveCatalog {
        databases: databases.into_iter().collect(),
        complete,
    })
}

fn read_bson_document<R: Read>(
    reader: &mut R,
    deadline: Instant,
    prelude_bytes: &mut usize,
) -> Result<Option<Vec<u8>>, InspectionError> {
    ensure_deadline(deadline)?;
    let mut prefix = [0_u8; 4];
    read_exact_archive(reader, &mut prefix)?;
    let declared = u32::from_le_bytes(prefix);
    if declared == ARCHIVE_TERMINATOR {
        return Ok(None);
    }
    let length = usize::try_from(declared).map_err(|_| {
        InspectionError::Invalid("MongoDB archive contains an invalid BSON document length")
    })?;
    if !(5..=MAX_BSON_DOCUMENT_BYTES).contains(&length) {
        return Err(InspectionError::Invalid(
            "MongoDB archive contains an invalid BSON document length",
        ));
    }
    *prelude_bytes = prelude_bytes
        .checked_add(length)
        .ok_or(InspectionError::Limit(
            "MongoDB archive prelude exceeds its size limit",
        ))?;
    if *prelude_bytes > MAX_PRELUDE_BYTES {
        return Err(InspectionError::Limit(
            "MongoDB archive prelude exceeds its size limit",
        ));
    }

    let mut bytes = vec![0_u8; length];
    bytes[..4].copy_from_slice(&prefix);
    read_exact_archive(reader, &mut bytes[4..])?;
    if bytes.last() != Some(&0) {
        return Err(InspectionError::Invalid(
            "MongoDB archive contains malformed BSON metadata",
        ));
    }
    Ok(Some(bytes))
}

fn read_exact_archive<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), InspectionError> {
    reader.read_exact(buffer).map_err(|error| {
        super::map_mongodb_read_error(
            error,
            "MongoDB native archive ended before its prelude was complete",
        )
    })
}

fn validate_header(bytes: &[u8]) -> Result<(), InspectionError> {
    const MALFORMED: &str = "MongoDB archive contains a malformed prelude header";
    let header = raw_document(bytes, MALFORMED)?;
    validate_bson_structure(header, MALFORMED)?;

    let mut concurrent_collections = None;
    let mut version = None;
    let mut server_version = None;
    let mut tool_version = None;
    for element in header.iter_elements() {
        let element = element.map_err(|_| InspectionError::Invalid(MALFORMED))?;
        let value = element
            .value()
            .map_err(|_| InspectionError::Invalid(MALFORMED))?;
        match element.key() {
            "concurrent_collections" => {
                set_required_once(&mut concurrent_collections, value.as_i32(), MALFORMED)?;
            }
            "version" => set_required_once(&mut version, value.as_str(), MALFORMED)?,
            "server_version" => {
                set_required_once(&mut server_version, value.as_str(), MALFORMED)?;
            }
            "tool_version" => {
                set_required_once(&mut tool_version, value.as_str(), MALFORMED)?;
            }
            _ => {}
        }
    }

    concurrent_collections.ok_or(InspectionError::Invalid(MALFORMED))?;
    let version = version.ok_or(InspectionError::Invalid(MALFORMED))?;
    if version != ARCHIVE_FORMAT_VERSION {
        return Err(InspectionError::Invalid(
            "MongoDB archive uses an unsupported format version",
        ));
    }
    for value in [server_version, tool_version] {
        let value = value.ok_or(InspectionError::Invalid(MALFORMED))?;
        if value.len() > 256 || value.chars().any(char::is_control) {
            return Err(InspectionError::Invalid(MALFORMED));
        }
    }
    Ok(())
}

fn parse_metadata(bytes: &[u8]) -> Result<&str, InspectionError> {
    const MALFORMED: &str = "MongoDB archive contains malformed collection metadata";
    let metadata = raw_document(bytes, MALFORMED)?;
    validate_bson_structure(metadata, MALFORMED)?;

    let mut database = None;
    let mut collection = None;
    for element in metadata.iter_elements() {
        let element = element.map_err(|_| InspectionError::Invalid(MALFORMED))?;
        let value = element
            .value()
            .map_err(|_| InspectionError::Invalid(MALFORMED))?;
        match element.key() {
            "db" => set_required_once(&mut database, value.as_str(), MALFORMED)?,
            "collection" => set_required_once(&mut collection, value.as_str(), MALFORMED)?,
            _ => {}
        }
    }
    collection.ok_or(InspectionError::Invalid(MALFORMED))?;
    database.ok_or(InspectionError::Invalid(MALFORMED))
}

fn raw_document<'a>(
    bytes: &'a [u8],
    malformed: &'static str,
) -> Result<&'a RawDocument, InspectionError> {
    RawDocument::from_bytes(bytes).map_err(|_| InspectionError::Invalid(malformed))
}

fn set_required_once<T>(
    slot: &mut Option<T>,
    value: Option<T>,
    malformed: &'static str,
) -> Result<(), InspectionError> {
    if slot.is_some() {
        return Err(InspectionError::Invalid(malformed));
    }
    *slot = Some(value.ok_or(InspectionError::Invalid(malformed))?);
    Ok(())
}

fn validate_bson_structure(
    root: &RawDocument,
    malformed: &'static str,
) -> Result<(), InspectionError> {
    let mut pending = vec![(root.iter_elements(), 0_usize)];
    while let Some((iterator, depth)) = pending.last_mut() {
        let next = iterator.next();
        let depth = *depth;
        let Some(element) = next else {
            pending.pop();
            continue;
        };
        let value = element
            .map_err(|_| InspectionError::Invalid(malformed))?
            .value()
            .map_err(|_| InspectionError::Invalid(malformed))?;
        let nested = match value {
            RawBsonRef::Document(document) => Some(document),
            RawBsonRef::Array(array) => Some(raw_document(array.as_bytes(), malformed)?),
            RawBsonRef::JavaScriptCodeWithScope(code) => Some(code.scope),
            _ => None,
        };
        if let Some(document) = nested {
            let nested_depth = depth.saturating_add(1);
            if nested_depth > MAX_BSON_NESTING_DEPTH {
                return Err(InspectionError::Limit(
                    "MongoDB archive BSON nesting exceeds its depth limit",
                ));
            }
            pending.push((document.iter_elements(), nested_depth));
        }
    }
    Ok(())
}

fn safe_source_database(database: &str) -> bool {
    crate::api::remote_import::validate_mongodb_database_name(
        "source.source_database",
        database,
        false,
    )
    .is_ok()
}

fn is_system_database(database: &str) -> bool {
    matches!(database, "admin" | "config" | "local")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Cursor, time::Duration};

    fn archive(metadata: &[(&str, &str)]) -> Vec<u8> {
        let mut bytes = ARCHIVE_MAGIC.to_vec();
        bytes.extend(header());
        for (database, collection) in metadata {
            bytes.extend(
                bson::to_vec(&bson::doc! {
                    "db": database,
                    "collection": collection,
                    "metadata": "{}",
                    "size": 0_i32,
                    "type": "collection",
                })
                .unwrap(),
            );
        }
        bytes.extend(ARCHIVE_TERMINATOR.to_le_bytes());
        bytes
    }

    fn header() -> Vec<u8> {
        bson::to_vec(&bson::doc! {
            "concurrent_collections": 4_i32,
            "version": ARCHIVE_FORMAT_VERSION,
            "server_version": "8.0.0",
            "tool_version": "100.12.2",
        })
        .unwrap()
    }

    fn archive_with_metadata(metadata: Vec<u8>) -> Vec<u8> {
        let mut bytes = ARCHIVE_MAGIC.to_vec();
        bytes.extend(header());
        bytes.extend(metadata);
        bytes.extend(ARCHIVE_TERMINATOR.to_le_bytes());
        bytes
    }

    fn append_string(body: &mut Vec<u8>, key: &str, value: &str) {
        body.push(0x02);
        body.extend(key.as_bytes());
        body.push(0);
        body.extend(i32::try_from(value.len() + 1).unwrap().to_le_bytes());
        body.extend(value.as_bytes());
        body.push(0);
    }

    fn append_i32(body: &mut Vec<u8>, key: &str, value: i32) {
        body.push(0x10);
        body.extend(key.as_bytes());
        body.push(0);
        body.extend(value.to_le_bytes());
    }

    fn test_document(body: Vec<u8>) -> Vec<u8> {
        let length = i32::try_from(body.len() + 5).unwrap();
        let mut bytes = Vec::with_capacity(length as usize);
        bytes.extend(length.to_le_bytes());
        bytes.extend(body);
        bytes.push(0);
        bytes
    }

    fn deeply_nested_document(depth: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(5 + 8 * depth);
        for remaining in (1..=depth).rev() {
            bytes.extend(i32::try_from(5 + 8 * remaining).unwrap().to_le_bytes());
            bytes.extend([0x03, b'x', 0]);
        }
        bytes.extend(5_i32.to_le_bytes());
        bytes.push(0);
        bytes.resize(bytes.len() + depth, 0);
        bytes
    }

    #[test]
    fn accepts_the_official_literal_magic_bytes() {
        let bytes = archive(&[("tenant", "users")]);
        assert_eq!(&bytes[..4], &[0x6d, 0xe2, 0x99, 0x81]);
        assert_eq!(inspect(&bytes).unwrap().databases, ["tenant"]);
    }

    fn inspect(bytes: &[u8]) -> Result<MongoArchiveCatalog, InspectionError> {
        inspect_native_archive(
            &mut Cursor::new(bytes),
            Instant::now() + Duration::from_secs(2),
        )
    }

    #[test]
    fn prelude_reports_sorted_unique_source_databases() {
        let result = inspect(&archive(&[
            ("zeta", "events"),
            ("alpha", "users"),
            ("zeta", "users"),
        ]))
        .unwrap();
        assert_eq!(result.databases, ["alpha", "zeta"]);
        assert!(result.complete);
    }

    #[test]
    fn prelude_excludes_system_and_database_less_metadata() {
        let result = inspect(&archive(&[
            ("admin", "system.users"),
            ("config", "settings"),
            ("local", "oplog.rs"),
            ("", "oplog.bson"),
        ]))
        .unwrap();
        assert!(result.databases.is_empty());
        assert!(result.complete);
    }

    #[test]
    fn unsafe_source_names_are_omitted_and_make_catalog_incomplete() {
        let result = inspect(&archive(&[("safe", "users"), ("bad.name", "secrets")])).unwrap();
        assert_eq!(result.databases, ["safe"]);
        assert!(!result.complete);
    }

    #[test]
    fn malformed_magic_version_and_metadata_fail_closed() {
        let mut invalid_magic = archive(&[("tenant", "users")]);
        invalid_magic[0] ^= 0xff;
        assert!(
            inspect(&invalid_magic)
                .unwrap_err()
                .to_string()
                .contains("native")
        );

        let mut unsupported = ARCHIVE_MAGIC.to_vec();
        unsupported.extend(
            bson::to_vec(&bson::doc! {
                "concurrent_collections": 1_i32,
                "version": "999",
                "server_version": "8.0",
                "tool_version": "100",
            })
            .unwrap(),
        );
        unsupported.extend(ARCHIVE_TERMINATOR.to_le_bytes());
        assert!(
            inspect(&unsupported)
                .unwrap_err()
                .to_string()
                .contains("unsupported")
        );

        let mut missing_collection = ARCHIVE_MAGIC.to_vec();
        missing_collection.extend(&archive(&[])[4..archive(&[]).len() - 4]);
        missing_collection.extend(bson::to_vec(&bson::doc! { "db": "tenant" }).unwrap());
        missing_collection.extend(ARCHIVE_TERMINATOR.to_le_bytes());
        assert!(
            inspect(&missing_collection)
                .unwrap_err()
                .to_string()
                .contains("collection metadata")
        );
    }

    #[test]
    fn duplicate_required_fields_fail_closed() {
        let mut metadata = Vec::new();
        append_string(&mut metadata, "db", "tenant");
        append_string(&mut metadata, "db", "other");
        append_string(&mut metadata, "collection", "users");
        let error = inspect(&archive_with_metadata(test_document(metadata))).unwrap_err();
        assert!(matches!(error, InspectionError::Invalid(_)));

        let mut duplicate_header = Vec::new();
        append_i32(&mut duplicate_header, "concurrent_collections", 1);
        append_string(&mut duplicate_header, "version", ARCHIVE_FORMAT_VERSION);
        append_string(&mut duplicate_header, "version", ARCHIVE_FORMAT_VERSION);
        append_string(&mut duplicate_header, "server_version", "8.0");
        append_string(&mut duplicate_header, "tool_version", "100.12");
        let mut bytes = ARCHIVE_MAGIC.to_vec();
        bytes.extend(test_document(duplicate_header));
        bytes.extend(ARCHIVE_TERMINATOR.to_le_bytes());
        assert!(matches!(inspect(&bytes), Err(InspectionError::Invalid(_))));
    }

    #[test]
    fn raw_iterator_errors_fail_closed() {
        let mut metadata = Vec::new();
        append_string(&mut metadata, "db", "tenant");
        append_string(&mut metadata, "collection", "users");
        metadata.extend([0x42, b'x', 0]);
        let error = inspect(&archive_with_metadata(test_document(metadata))).unwrap_err();
        assert!(matches!(error, InspectionError::Invalid(_)));
    }

    #[test]
    fn deeply_nested_unknown_bson_is_rejected_iteratively() {
        let mut metadata = Vec::new();
        append_string(&mut metadata, "db", "tenant");
        append_string(&mut metadata, "collection", "users");
        metadata.push(0x03);
        metadata.extend(b"payload\0");
        metadata.extend(deeply_nested_document(20_000));
        let error = inspect(&archive_with_metadata(test_document(metadata))).unwrap_err();
        assert!(matches!(error, InspectionError::Limit(_)));
    }

    #[test]
    fn excessive_metadata_count_is_bounded() {
        let metadata = (0..=MAX_METADATA_DOCUMENTS)
            .map(|index| ("tenant".to_string(), format!("c{index}")))
            .collect::<Vec<_>>();
        let borrowed = metadata
            .iter()
            .map(|(database, collection)| (database.as_str(), collection.as_str()))
            .collect::<Vec<_>>();
        let error = inspect(&archive(&borrowed)).unwrap_err();
        assert!(matches!(error, InspectionError::Limit(_)));
    }
}
