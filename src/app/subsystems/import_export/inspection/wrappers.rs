use super::*;

pub(super) fn validate_physical_wrapper(
    source: &mut File,
    format: DumpArchiveFormat,
    deadline: Instant,
) -> Result<(), InspectionError> {
    match format {
        DumpArchiveFormat::TarGzip => validate_tar_container(source, true, deadline),
        _ => Err(InspectionError::Invalid(
            "physical database uploads must be gzip-compressed tar archives",
        )),
    }
}

pub(super) fn inspect_mongodb_wrapper(
    source: &mut File,
    format: DumpArchiveFormat,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    match format {
        DumpArchiveFormat::Gzip => {
            source.seek(SeekFrom::Start(0))?;
            inspect_native_gzip(source, deadline)
        }
        DumpArchiveFormat::Tar => inspect_mongodb_tar_container(source, false, deadline),
        DumpArchiveFormat::TarGzip => inspect_mongodb_tar_container(source, true, deadline),
        DumpArchiveFormat::Zip => inspect_mongodb_zip_container(source, deadline),
        DumpArchiveFormat::Bzip2 => inspect_bzip2_wrapped_mongodb(source, deadline),
        DumpArchiveFormat::Plain => Err(InspectionError::Invalid(
            "MongoDB uploads must be native gzip archives or wrappers containing exactly one .archive.gz file",
        )),
    }
}

pub(super) fn inspect_bzip2_wrapped_mongodb(
    source: &mut File,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    source.seek(SeekFrom::Start(0))?;
    let bzip2 = bzip2::read::MultiBzDecoder::new(source);
    let bounded = BoundedReader::new(bzip2, MAX_INSPECTED_BYTES, deadline);
    inspect_native_gzip(bounded, deadline).map_err(|error| match error {
        InspectionError::Limit(_) => error,
        _ => InspectionError::Invalid(
            "MongoDB bzip2 wrapper does not contain a valid native gzip archive",
        ),
    })
}

pub(super) fn inspect_mongodb_tar_container(
    source: &mut File,
    gzipped: bool,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    source.seek(SeekFrom::Start(0))?;
    if gzipped {
        inspect_mongodb_tar_entries(flate2::read::MultiGzDecoder::new(source), deadline)
    } else {
        inspect_mongodb_tar_entries(source, deadline)
    }
}

pub(super) fn inspect_mongodb_tar_entries<R: Read>(
    reader: R,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    let bounded = BoundedReader::new(reader, MAX_INSPECTED_BYTES, deadline);
    let mut archive = tar::Archive::new(bounded);
    let mut count = 0_usize;
    let mut total = 0_u64;
    let mut catalog = None;
    let entries = archive
        .entries()
        .map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
    for entry in entries {
        ensure_deadline(deadline)?;
        count_archive_entry(&mut count)?;
        let mut entry =
            entry.map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
        let kind = entry.header().entry_type();
        ensure_supported_tar_entry(kind)?;
        let path = entry
            .path()
            .map_err(|_| InspectionError::Invalid("archive contains an invalid entry path"))?;
        validate_archive_path(&path)?;
        let candidate = kind.is_file() && is_mongodb_archive_candidate(&path)?;
        add_expanded_bytes(&mut total, tar_entry_size(&entry)?)?;
        if candidate {
            ensure_no_mongodb_catalog_yet(&catalog)?;
            catalog = Some(inspect_native_gzip(&mut entry, deadline)?);
        }
    }
    let mut remainder = archive.into_inner();
    io::copy(&mut remainder, &mut io::sink())
        .map_err(|error| map_mongodb_read_error(error, "MongoDB tar wrapper is malformed"))?;
    catalog.ok_or(InspectionError::Invalid(
        "MongoDB wrapper does not contain a .archive.gz dump",
    ))
}

pub(super) fn inspect_mongodb_zip_container(
    source: &mut File,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    source.seek(SeekFrom::Start(0))?;
    let mut archive = zip::ZipArchive::new(source.try_clone()?)
        .map_err(|_| InspectionError::Invalid("uploaded zip archive is malformed"))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(InspectionError::Limit("archive contains too many entries"));
    }
    let mut total = 0_u64;
    let mut catalog = None;
    for index in 0..archive.len() {
        ensure_deadline(deadline)?;
        let mut entry = archive
            .by_index(index)
            .map_err(|_| InspectionError::Invalid("uploaded zip archive is malformed"))?;
        let path = entry.enclosed_name().ok_or(InspectionError::Invalid(
            "archive contains an unsafe entry path",
        ))?;
        validate_archive_path(&path)?;
        validate_zip_entry_type(&entry)?;
        let candidate = !entry.is_dir() && is_mongodb_archive_candidate(&path)?;
        add_expanded_bytes(&mut total, entry.size())?;
        if candidate {
            ensure_no_mongodb_catalog_yet(&catalog)?;
            catalog = Some(inspect_native_gzip(&mut entry, deadline)?);
        } else if !entry.is_dir() {
            drain_zip_entry(&mut entry, deadline)?;
        }
    }
    catalog.ok_or(InspectionError::Invalid(
        "MongoDB wrapper does not contain a .archive.gz dump",
    ))
}

pub(super) fn ensure_no_mongodb_catalog_yet(
    catalog: &Option<MongoArchiveCatalog>,
) -> Result<(), InspectionError> {
    if catalog.is_some() {
        return Err(InspectionError::Invalid(
            "MongoDB wrapper contains multiple .archive.gz dumps",
        ));
    }
    Ok(())
}

pub(super) fn validate_tar_container(
    source: &mut File,
    gzipped: bool,
    deadline: Instant,
) -> Result<(), InspectionError> {
    source.seek(SeekFrom::Start(0))?;
    if gzipped {
        validate_tar_entries(flate2::read::GzDecoder::new(source), deadline)
    } else {
        validate_tar_entries(source, deadline)
    }
}

pub(super) fn validate_tar_entries<R: Read>(
    reader: R,
    deadline: Instant,
) -> Result<(), InspectionError> {
    let bounded = BoundedReader::new(reader, MAX_INSPECTED_BYTES, deadline);
    let mut archive = tar::Archive::new(bounded);
    let mut count = 0_usize;
    let mut total = 0_u64;
    let entries = archive
        .entries()
        .map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
    for entry in entries {
        ensure_deadline(deadline)?;
        count_archive_entry(&mut count)?;
        let entry =
            entry.map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
        ensure_supported_tar_entry(entry.header().entry_type())?;
        let path = entry
            .path()
            .map_err(|_| InspectionError::Invalid("archive contains an invalid entry path"))?;
        validate_archive_path(&path)?;
        add_expanded_bytes(&mut total, tar_entry_size(&entry)?)?;
    }
    Ok(())
}

pub(super) fn is_mongodb_archive_candidate(path: &Path) -> Result<bool, InspectionError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(InspectionError::Invalid(
            "archive contains a non-UTF-8 entry name",
        ))?
        .to_ascii_lowercase();
    Ok(name.ends_with(".mongodb.archive.gz") || name.ends_with(".archive.gz"))
}

pub(super) fn map_mongodb_read_error(
    error: io::Error,
    malformed_message: &'static str,
) -> InspectionError {
    if error.kind() == io::ErrorKind::TimedOut {
        return InspectionError::Limit("dump inspection exceeded its time limit");
    }
    if error.kind() == io::ErrorKind::InvalidData
        && error
            .to_string()
            .contains("decompressed dump exceeds inspection limit")
    {
        return InspectionError::Limit("MongoDB archive expansion exceeds the size limit");
    }
    InspectionError::Invalid(malformed_message)
}
