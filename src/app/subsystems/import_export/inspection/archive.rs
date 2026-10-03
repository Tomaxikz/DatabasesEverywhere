use super::*;

pub(super) fn inspect_sql_source(
    source: &mut File,
    format: DumpArchiveFormat,
    protocol: Protocol,
    deadline: Instant,
    catalog: &mut CatalogBuilder,
) -> Result<(), InspectionError> {
    let mut inspect = |reader: &mut dyn Read| inspect_sql_reader(reader, protocol, catalog);
    scan_sql_source(source, format, deadline, &mut inspect)
}

pub(super) fn scan_sql_source<E, F>(
    source: &mut File,
    format: DumpArchiveFormat,
    deadline: Instant,
    scan: &mut F,
) -> Result<(), E>
where
    E: From<InspectionError>,
    F: FnMut(&mut dyn Read) -> Result<(), E>,
{
    source
        .seek(SeekFrom::Start(0))
        .map_err(InspectionError::from)?;
    match format {
        DumpArchiveFormat::Plain => {
            let mut bounded = BoundedReader::new(source, MAX_INSPECTED_BYTES, deadline);
            scan(&mut bounded)
        }
        DumpArchiveFormat::Gzip => {
            // Import tools consume concatenated streams. Inspect every member too,
            // otherwise a safe first member could conceal unvalidated SQL later.
            let decoder = flate2::read::MultiGzDecoder::new(source);
            let mut bounded = BoundedReader::new(decoder, MAX_INSPECTED_BYTES, deadline);
            scan(&mut bounded)
        }
        DumpArchiveFormat::Bzip2 => {
            let decoder = bzip2::read::MultiBzDecoder::new(source);
            let mut bounded = BoundedReader::new(decoder, MAX_INSPECTED_BYTES, deadline);
            scan(&mut bounded)
        }
        DumpArchiveFormat::Tar => scan_sql_tar(source, false, deadline, scan),
        DumpArchiveFormat::TarGzip => scan_sql_tar(source, true, deadline, scan),
        DumpArchiveFormat::Zip => scan_sql_zip(source, deadline, scan),
    }
}

pub(super) fn scan_sql_tar<E, F>(
    source: &mut File,
    gzipped: bool,
    deadline: Instant,
    scan: &mut F,
) -> Result<(), E>
where
    E: From<InspectionError>,
    F: FnMut(&mut dyn Read) -> Result<(), E>,
{
    if gzipped {
        let decoder = flate2::read::MultiGzDecoder::new(source);
        scan_sql_tar_reader(decoder, deadline, scan)
    } else {
        scan_sql_tar_reader(source, deadline, scan)
    }
}

pub(super) fn scan_sql_tar_reader<R: Read, E, F>(
    reader: R,
    deadline: Instant,
    scan: &mut F,
) -> Result<(), E>
where
    E: From<InspectionError>,
    F: FnMut(&mut dyn Read) -> Result<(), E>,
{
    let bounded = BoundedReader::new(reader, MAX_INSPECTED_BYTES, deadline);
    let mut archive = tar::Archive::new(bounded);
    let mut entries_seen = 0_usize;
    let mut expanded_bytes = 0_u64;
    let mut candidate_seen = false;
    let entries = archive
        .entries()
        .map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
    for entry in entries {
        ensure_deadline(deadline)?;
        count_archive_entry(&mut entries_seen)?;
        let mut entry =
            entry.map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
        let kind = entry.header().entry_type();
        ensure_supported_tar_entry(kind)?;
        let path = entry
            .path()
            .map_err(|_| InspectionError::Invalid("archive contains an invalid entry path"))?
            .into_owned();
        validate_archive_path(&path)?;
        let size = tar_entry_size(&entry)?;
        add_expanded_bytes(&mut expanded_bytes, size)?;
        if kind.is_file() && is_sql_candidate(&path)? {
            claim_single_sql_candidate(&mut candidate_seen)?;
            let mut bounded =
                BoundedReader::new(&mut entry, size.min(MAX_INSPECTED_BYTES), deadline);
            scan(&mut bounded)?;
        }
    }
    ensure_sql_candidate_found(candidate_seen)?;
    Ok(())
}

pub(super) fn scan_sql_zip<E, F>(
    source: &mut File,
    deadline: Instant,
    scan: &mut F,
) -> Result<(), E>
where
    E: From<InspectionError>,
    F: FnMut(&mut dyn Read) -> Result<(), E>,
{
    let cloned = source.try_clone().map_err(InspectionError::from)?;
    let mut archive = zip::ZipArchive::new(cloned)
        .map_err(|_| InspectionError::Invalid("uploaded zip archive is malformed"))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(InspectionError::Limit("archive contains too many entries").into());
    }
    let mut expanded_bytes = 0_u64;
    let mut candidate_seen = false;
    for index in 0..archive.len() {
        ensure_deadline(deadline)?;
        let mut entry = archive
            .by_index(index)
            .map_err(|_| InspectionError::Invalid("uploaded zip archive is malformed"))?;
        let path = entry
            .enclosed_name()
            .ok_or(InspectionError::Invalid(
                "archive contains an unsafe entry path",
            ))?
            .to_path_buf();
        validate_archive_path(&path)?;
        validate_zip_entry_type(&entry)?;
        add_expanded_bytes(&mut expanded_bytes, entry.size())?;
        if entry.is_dir() {
            continue;
        }
        if is_sql_candidate(&path)? {
            claim_single_sql_candidate(&mut candidate_seen)?;
            let size = entry.size();
            let mut bounded =
                BoundedReader::new(&mut entry, size.min(MAX_INSPECTED_BYTES), deadline);
            scan(&mut bounded)?;
        } else {
            drain_zip_entry(&mut entry, deadline)?;
        }
    }
    ensure_sql_candidate_found(candidate_seen)?;
    Ok(())
}

pub(super) fn claim_single_sql_candidate(candidate_seen: &mut bool) -> Result<(), InspectionError> {
    if *candidate_seen {
        return Err(InspectionError::Invalid(
            "archive contains multiple candidate dump files",
        ));
    }
    *candidate_seen = true;
    Ok(())
}

pub(super) fn ensure_sql_candidate_found(candidate_seen: bool) -> Result<(), InspectionError> {
    if candidate_seen {
        Ok(())
    } else {
        Err(InspectionError::Invalid(
            "archive does not contain one supported SQL dump file",
        ))
    }
}

pub(super) fn count_archive_entry(entries_seen: &mut usize) -> Result<(), InspectionError> {
    *entries_seen += 1;
    if *entries_seen > MAX_ARCHIVE_ENTRIES {
        return Err(InspectionError::Limit("archive contains too many entries"));
    }
    Ok(())
}

pub(super) fn ensure_supported_tar_entry(kind: tar::EntryType) -> Result<(), InspectionError> {
    if kind.is_file() || kind.is_dir() {
        Ok(())
    } else {
        Err(InspectionError::Invalid(
            "archive contains a link, device, or unsupported special entry",
        ))
    }
}

pub(super) fn tar_entry_size<R: Read>(entry: &tar::Entry<'_, R>) -> Result<u64, InspectionError> {
    entry
        .header()
        .size()
        .map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))
}

pub(super) fn add_expanded_bytes(
    expanded_bytes: &mut u64,
    size: u64,
) -> Result<(), InspectionError> {
    *expanded_bytes = expanded_bytes
        .checked_add(size)
        .ok_or(InspectionError::Limit(
            "archive expansion exceeds the size limit",
        ))?;
    if *expanded_bytes > MAX_INSPECTED_BYTES {
        return Err(InspectionError::Limit(
            "archive expansion exceeds the size limit",
        ));
    }
    Ok(())
}

pub(super) fn drain_zip_entry<R: io::Read>(
    entry: &mut zip::read::ZipFile<'_, R>,
    deadline: Instant,
) -> Result<(), InspectionError> {
    let size = entry.size();
    let mut bounded = BoundedReader::new(entry, size, deadline);
    io::copy(&mut bounded, &mut io::sink()).map_err(|_| {
        InspectionError::Invalid("uploaded zip archive contains malformed file data")
    })?;
    Ok(())
}

pub(super) fn validate_zip_entry_type<R: io::Read>(
    entry: &zip::read::ZipFile<'_, R>,
) -> Result<(), InspectionError> {
    let Some(mode) = entry.unix_mode() else {
        return Ok(());
    };
    let kind = mode & UNIX_FILE_TYPE_MASK;
    if kind == 0 || kind == UNIX_REGULAR_FILE || kind == UNIX_DIRECTORY {
        Ok(())
    } else {
        Err(InspectionError::Invalid(
            "archive contains a link, device, or unsupported special entry",
        ))
    }
}

pub(super) fn validate_archive_path(path: &Path) -> Result<(), InspectionError> {
    let mut depth = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                if part.to_str().is_none() {
                    return Err(InspectionError::Invalid(
                        "archive contains a non-UTF-8 entry path",
                    ));
                }
                depth += 1;
                if depth > MAX_ARCHIVE_DEPTH {
                    return Err(InspectionError::Limit("archive entry path is too deep"));
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(InspectionError::Invalid(
                    "archive contains an unsafe entry path",
                ));
            }
        }
    }
    if depth == 0 {
        return Err(InspectionError::Invalid(
            "archive contains an empty entry path",
        ));
    }
    Ok(())
}

pub(super) fn is_sql_candidate(path: &Path) -> Result<bool, InspectionError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(InspectionError::Invalid(
            "archive contains a non-UTF-8 entry name",
        ))?
        .to_ascii_lowercase();
    Ok(name.ends_with(".sql"))
}
