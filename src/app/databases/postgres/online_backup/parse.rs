//! `backup_label`, backup-manifest WAL ranges and staged checksum verification.

use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path},
};

use sha2::{Digest, Sha256};

use crate::{
    server::backup::manifest::{RecoveryCoordinates, is_identifier},
    utils::hex::encode_lower,
};

const MAX_LABEL_BYTES: u64 = 64 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024 * 1024;
const PG_CONTROL_MAX_BYTES: u64 = 8192;
const PG_CONTROL_VERSION_OFFSET: usize = 8;
/// LP64 `offsetof(ControlFileData, xlog_seg_size)` for PostgreSQL 14–18.
///
/// Same offset on x86_64 and aarch64 (GCC/Clang, 4-byte `enum`, `bool` is
/// `char`). `CheckPoint` in 14–16 is 88 bytes: `fullPageWrites` is at 16 and
/// the next `uint64` (`nextXid`) is at 24, leaving a 7-byte hole. PostgreSQL 17
/// puts `wal_level` (`int`) at 20 inside that hole, so `sizeof(CheckPoint)` and
/// every later offset stay put. `default_char_signedness` in 18 is after
/// `data_checksum_version` and does not move this field. Offset 220 is
/// `relseg_size`; 224 is `xlog_blcksz`.
///
/// `system_identifier` 0, `pg_control_version` 8, `catalog_version_no` 12,
/// `state` 16, `time` 24, `checkPoint` 32, `checkPointCopy` 40,
/// `unloggedLSN` 128, `minRecoveryPoint` 136, `minRecoveryPointTLI` 144,
/// `backupStartPoint` 152, `backupEndPoint` 160, `backupEndRequired` 168,
/// `wal_level` 172, `wal_log_hints` 176, `MaxConnections` 180,
/// `max_worker_processes` 184, `max_wal_senders` 188, `max_prepared_xacts` 192,
/// `max_locks_per_xact` 196, `track_commit_timestamp` 200, `maxAlign` 204,
/// `floatFormat` 208, `blcksz` 216, `relseg_size` 220, `xlog_blcksz` 224,
/// `xlog_seg_size` 228.
///
/// The CRC-32C in `controldata_utils.c` covers the bytes before `crc`
/// (`INIT`/`FIN` are the Castagnoli `0xffffffff` xor). That offset is 288 for
/// control versions 1300 (14–16) and 1700 (17). Version 1800 is 292 because
/// `default_char_signedness` shifts the nonce by one byte.
const PG_CONTROL_XLOG_SEG_OFFSET: usize = 228;
const PG_CONTROL_CRC_OFFSET_THROUGH_V17: usize = 288;
const PG_CONTROL_CRC_OFFSET_V18: usize = 292;
/// `WalSegMinSize` and `WalSegMaxSize` from `xlog_internal.h`.
const MIN_WAL_SEGMENT_BYTES: u64 = 1024 * 1024;
const MAX_WAL_SEGMENT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_WAL_SEGMENTS_PER_RANGE: u64 = 4096;
const MANIFEST_CHECKSUM_PREFIX: &[u8] = b"\"Manifest-Checksum\": \"";

pub(crate) fn parse_lsn(value: &str) -> Option<(u32, u32)> {
    let (high, low) = value.split_once('/')?;
    if value.matches('/').count() != 1 || high.is_empty() || low.is_empty() {
        return None;
    }
    if high.len() > 8 || low.len() > 8 {
        return None;
    }
    if !high.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !low.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some((
        u32::from_str_radix(high, 16).ok()?,
        u32::from_str_radix(low, 16).ok()?,
    ))
}

pub(crate) fn format_lsn(lsn: (u32, u32)) -> String {
    format!("{:X}/{:X}", lsn.0, lsn.1)
}

pub(crate) fn read_recovery(
    pgdata: &Path,
    expected_label: &str,
) -> Result<RecoveryCoordinates, String> {
    let label = read_limited(&pgdata.join("backup_label"), MAX_LABEL_BYTES)?;
    let manifest = read_limited(&pgdata.join("backup_manifest"), MAX_MANIFEST_BYTES)?;
    recovery_from_label_and_manifest(&label, &manifest, expected_label)
}

pub(crate) fn recovery_from_label_and_manifest(
    label: &str,
    manifest: &str,
    expected_label: &str,
) -> Result<RecoveryCoordinates, String> {
    if label.contains('\0') || manifest.contains('\0') {
        return Err("backup description contains a NUL byte".to_string());
    }
    let start = unique_field(label, "START WAL LOCATION:")?;
    let start_lsn = parse_lsn(start.split_whitespace().next().unwrap_or(""))
        .ok_or_else(|| "backup_label has no start LSN".to_string())?;
    let timeline: u64 = unique_field(label, "START TIMELINE:")?
        .parse()
        .map_err(|_| "backup_label has no start timeline".to_string())?;
    let method = unique_field(label, "BACKUP METHOD:")?;
    if method != "streamed" {
        return Err(format!("backup method is {method}, not streamed"));
    }
    let recorded = unique_field(label, "LABEL:")?;
    if recorded != expected_label {
        return Err("backup label does not match this job".to_string());
    }
    let parsed: Manifest =
        serde_json::from_str(manifest).map_err(|error| format!("backup manifest: {error}"))?;
    let [range] = parsed.wal_ranges.as_slice() else {
        return Err(format!(
            "backup manifest has {} WAL ranges; a base backup has one",
            parsed.wal_ranges.len()
        ));
    };
    let manifest_start = parse_lsn(&range.start_lsn)
        .ok_or_else(|| "backup manifest start LSN is malformed".to_string())?;
    let manifest_end = parse_lsn(&range.end_lsn)
        .ok_or_else(|| "backup manifest end LSN is malformed".to_string())?;
    if manifest_start != start_lsn {
        return Err("backup_label and backup manifest disagree on the start LSN".to_string());
    }
    if range.timeline != timeline {
        return Err("backup_label and backup manifest disagree on the timeline".to_string());
    }
    if (manifest_end.0, manifest_end.1) < (start_lsn.0, start_lsn.1) {
        return Err("backup end LSN is before the start LSN".to_string());
    }
    let mut coordinates = BTreeMap::new();
    coordinates.insert("start_lsn".to_string(), format_lsn(start_lsn));
    coordinates.insert("end_lsn".to_string(), format_lsn(manifest_end));
    coordinates.insert("timeline".to_string(), timeline.to_string());
    if coordinates.len() > 32
        || coordinates
            .iter()
            .any(|(key, value)| !is_identifier(key) || !bounded_text(value))
    {
        return Err("recovery coordinates do not fit the manifest".to_string());
    }
    Ok(RecoveryCoordinates(coordinates))
}

/// Re-checks the staged tree against `backup_manifest`. `pg_verifybackup` has
/// already accepted the container-visible copy; this checks the bytes that
/// will be packaged.
pub(crate) fn verify_staged_tree(pgdata: &Path) -> Result<usize, String> {
    let manifest_path = pgdata.join("backup_manifest");
    let bytes = read_bytes(&manifest_path, MAX_MANIFEST_BYTES)?;
    verify_manifest_checksum(&bytes)?;
    let text = String::from_utf8(bytes).map_err(|_| "backup manifest is not utf-8".to_string())?;
    let parsed: Manifest =
        serde_json::from_str(&text).map_err(|error| format!("backup manifest: {error}"))?;
    if parsed.wal_ranges.is_empty() {
        return Err("backup manifest has no WAL ranges".to_string());
    }
    let count = parsed.files.len();
    let mut expected = BTreeMap::new();
    for file in parsed.files {
        if !safe_manifest_path(&file.path) {
            return Err(format!("backup manifest path {} is unsafe", file.path));
        }
        if file.path == "pg_wal" || file.path.starts_with("pg_wal/") {
            return Err(format!("backup manifest lists WAL path {}", file.path));
        }
        if expected.insert(file.path.clone(), file).is_some() {
            return Err("backup manifest lists a path twice".to_string());
        }
    }
    let mut staged_wal = StagedWal::default();
    walk_files(pgdata, Path::new(""), &mut expected, &mut staged_wal)?;
    if let Some((path, _)) = expected.iter().next() {
        return Err(format!("staged backup is missing {path}"));
    }
    verify_wal_coverage(&parsed.wal_ranges, &staged_wal, wal_segment_bytes(pgdata)?)?;
    Ok(count)
}

fn walk_files(
    root: &Path,
    relative: &Path,
    expected: &mut BTreeMap<String, ManifestFile>,
    staged_wal: &mut StagedWal,
) -> Result<(), String> {
    let entries = std::fs::read_dir(root.join(relative))
        .map_err(|error| format!("read {}: {error}", relative.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err("staged backup file name is not utf-8".to_string());
        };
        if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
            return Err(format!("staged backup file name {name} is unsafe"));
        }
        let child = relative.join(name);
        let metadata = std::fs::symlink_metadata(root.join(&child))
            .map_err(|error| format!("{}: {error}", child.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("refusing symlink {}", child.display()));
        }
        if metadata.is_dir() {
            walk_files(root, &child, expected, staged_wal)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(format!("refusing special file {}", child.display()));
        }
        let rel = child
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if rel == "backup_manifest" {
            continue;
        }
        match wal_class(&rel)? {
            Some(WalClass::Segment(name)) => {
                staged_wal.segments.insert(name, metadata.len());
            }
            Some(WalClass::Partial(name)) => {
                staged_wal.partials.push((name, metadata.len()));
            }
            Some(WalClass::Auxiliary) => {}
            None => {
                let Some(file) = expected.remove(&rel) else {
                    return Err(format!("staged backup has unexpected file {rel}"));
                };
                check_file(&root.join(&child), &file, metadata.len())?;
            }
        }
    }
    Ok(())
}

fn check_file(path: &Path, file: &ManifestFile, len: u64) -> Result<(), String> {
    if !safe_manifest_path(&file.path) {
        return Err(format!("backup manifest path {} is unsafe", file.path));
    }
    if !file.algorithm.eq_ignore_ascii_case("SHA256") {
        return Err(format!(
            "{} uses checksum {}, not SHA256",
            file.path, file.algorithm
        ));
    }
    if file.size != len {
        return Err(format!(
            "{} is {len} bytes and the manifest says {}",
            file.path, file.size
        ));
    }
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open {}: {error}", file.path))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", file.path))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = encode_lower(&hasher.finalize());
    if !digest.eq_ignore_ascii_case(&file.checksum) {
        return Err(format!(
            "{} checksum does not match the manifest",
            file.path
        ));
    }
    Ok(())
}

/// SHA-256 through the penultimate newline, inclusive. The last line is excluded.
///
/// PostgreSQL 14–18 `SendBackupManifest` sets `still_checksumming = false`
/// after `AddWALInfoToBackupManifest` has written the `\n],\n` that closes
/// `WAL-Ranges`, then appends `"Manifest-Checksum"`. `verify_manifest_checksum`
/// in `src/common/parse_manifest.c` hashes `buffer[0 .. penultimate_newline]`
/// inclusive and requires the file to end on the ultimate newline. The comma
/// before `"Manifest-Checksum"` is inside the hash.
pub(crate) fn verify_manifest_checksum(bytes: &[u8]) -> Result<(), String> {
    if bytes.last() != Some(&b'\n') {
        return Err("backup manifest checksum trailer is malformed".to_string());
    }
    let Some(penultimate) = bytes[..bytes.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
    else {
        return Err("backup manifest is missing its checksum trailer".to_string());
    };
    let hex = manifest_checksum_hex(&bytes[penultimate + 1..])?;
    let digest = encode_lower(Sha256::digest(&bytes[..=penultimate]).as_slice());
    if !digest.eq_ignore_ascii_case(hex) {
        return Err("backup manifest checksum does not match its contents".to_string());
    }
    Ok(())
}

fn manifest_checksum_hex(last_line: &[u8]) -> Result<&str, String> {
    let Some(rest) = last_line.strip_prefix(MANIFEST_CHECKSUM_PREFIX) else {
        return Err("backup manifest checksum trailer is malformed".to_string());
    };
    let Some(hex) = rest.strip_suffix(b"\"}\n") else {
        return Err("backup manifest checksum trailer is malformed".to_string());
    };
    if hex.len() != 64 || !hex.iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("backup manifest checksum is truncated".to_string());
    }
    std::str::from_utf8(hex).map_err(|_| "backup manifest checksum is not utf-8".to_string())
}

#[derive(Default)]
struct StagedWal {
    segments: BTreeMap<String, u64>,
    partials: Vec<(String, u64)>,
}

enum WalClass {
    Segment(String),
    Partial(String),
    Auxiliary,
}

fn wal_class(rel: &str) -> Result<Option<WalClass>, String> {
    let Some(rest) = rel.strip_prefix("pg_wal/") else {
        return Ok(None);
    };
    if let Some(name) = rest.strip_prefix("archive_status/") {
        if !name.is_empty() && !name.contains('/') && archive_status_name(name) {
            return Ok(Some(WalClass::Auxiliary));
        }
        return Err(format!("staged backup has unexpected file {rel}"));
    }
    if rest.is_empty() || rest.contains('/') {
        return Err(format!("staged backup has unexpected file {rel}"));
    }
    if is_wal_segment_name(rest) {
        return Ok(Some(WalClass::Segment(rest.to_string())));
    }
    if is_partial_wal_name(rest) {
        return Ok(Some(WalClass::Partial(rest.to_string())));
    }
    if is_timeline_history_name(rest) || is_backup_history_name(rest) {
        return Ok(Some(WalClass::Auxiliary));
    }
    Err(format!("staged backup has unexpected file {rel}"))
}

fn is_upper_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
}

fn is_wal_segment_name(name: &str) -> bool {
    name.len() == 24 && is_upper_hex(name)
}

fn is_partial_wal_name(name: &str) -> bool {
    name.strip_suffix(".partial")
        .is_some_and(is_wal_segment_name)
}

fn is_timeline_history_name(name: &str) -> bool {
    name.strip_suffix(".history")
        .is_some_and(|stem| stem.len() == 8 && is_upper_hex(stem))
}

fn is_backup_history_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    name.len() > 24
        && name.ends_with(".backup")
        && is_upper_hex(&name[..24])
        && !bytes[24].is_ascii_hexdigit()
}

fn archive_status_name(name: &str) -> bool {
    name.strip_suffix(".done")
        .or_else(|| name.strip_suffix(".ready"))
        .is_some_and(|stem| is_wal_segment_name(stem) || is_timeline_history_name(stem))
}

fn verify_wal_coverage(
    ranges: &[WalRange],
    staged: &StagedWal,
    seg_size: u64,
) -> Result<(), String> {
    if !valid_wal_segment_bytes(seg_size) {
        return Err("WAL segment size is not usable".to_string());
    }
    for (name, len) in &staged.segments {
        if *len != seg_size {
            return Err(format!(
                "pg_wal/{name} is {len} bytes; WAL segment size is {seg_size}"
            ));
        }
    }
    for (name, len) in &staged.partials {
        if *len > seg_size {
            return Err(format!(
                "pg_wal/{name} is {len} bytes; WAL segment size is {seg_size}"
            ));
        }
    }
    for range in ranges {
        let timeline = u32::try_from(range.timeline)
            .ok()
            .filter(|timeline| *timeline != 0)
            .ok_or_else(|| "backup manifest WAL timeline is invalid".to_string())?;
        let start = parse_lsn(&range.start_lsn)
            .ok_or_else(|| "backup manifest start LSN is malformed".to_string())?;
        let end = parse_lsn(&range.end_lsn)
            .ok_or_else(|| "backup manifest end LSN is malformed".to_string())?;
        for name in required_wal_segments(timeline, lsn_offset(start), lsn_offset(end), seg_size)? {
            if !staged.segments.contains_key(&name) {
                return Err(format!("staged backup is missing pg_wal/{name}"));
            }
        }
    }
    Ok(())
}

fn lsn_offset(lsn: (u32, u32)) -> u64 {
    (u64::from(lsn.0) << 32) | u64::from(lsn.1)
}

/// `XLByteToSeg` of the start LSN through `XLByteToPrevSeg` of the end LSN.
/// An end LSN that falls on a segment boundary does not require the next file.
fn required_wal_segments(
    timeline: u32,
    start: u64,
    end: u64,
    seg_size: u64,
) -> Result<Vec<String>, String> {
    if end < start {
        return Err("backup WAL range ends before it starts".to_string());
    }
    if end == 0 {
        return Err("backup WAL range is empty".to_string());
    }
    let start_seg = start / seg_size;
    let end_seg = (end - 1) / seg_size;
    if end_seg < start_seg {
        return Err("backup WAL range does not cover a WAL segment".to_string());
    }
    if end_seg - start_seg >= MAX_WAL_SEGMENTS_PER_RANGE {
        return Err("backup WAL range covers too many segments".to_string());
    }
    let mut names = Vec::new();
    let mut segno = start_seg;
    loop {
        names.push(wal_segment_name(timeline, segno, seg_size)?);
        if segno == end_seg {
            break;
        }
        segno += 1;
    }
    Ok(names)
}

fn wal_segment_name(timeline: u32, segno: u64, seg_size: u64) -> Result<String, String> {
    let segs_per_id = (1u64 << 32) / seg_size;
    let log = segno / segs_per_id;
    let seg = segno % segs_per_id;
    let log = u32::try_from(log)
        .map_err(|_| "WAL segment number does not fit a file name".to_string())?;
    let seg = u32::try_from(seg)
        .map_err(|_| "WAL segment number does not fit a file name".to_string())?;
    Ok(format!("{timeline:08X}{log:08X}{seg:08X}"))
}

fn wal_segment_bytes(pgdata: &Path) -> Result<u64, String> {
    let bytes = read_bytes(&pgdata.join("global/pg_control"), PG_CONTROL_MAX_BYTES)?;
    let version = read_u32_le(&bytes, PG_CONTROL_VERSION_OFFSET)
        .ok_or_else(|| "pg_control is too short to contain pg_control_version".to_string())?;
    let crc_offset = pg_control_crc_offset(version)?;
    let stored = read_u32_le(&bytes, crc_offset)
        .ok_or_else(|| "pg_control is too short to contain its checksum".to_string())?;
    if crc32c(&bytes[..crc_offset]) != stored {
        return Err("pg_control checksum does not match its contents".to_string());
    }
    let size = read_u32_le(&bytes, PG_CONTROL_XLOG_SEG_OFFSET)
        .map(u64::from)
        .ok_or_else(|| "pg_control is too short to contain xlog_seg_size".to_string())?;
    if !valid_wal_segment_bytes(size) {
        return Err(format!(
            "pg_control WAL segment size {size} is not a power of two between 1 MiB and 1 GiB"
        ));
    }
    Ok(size)
}

/// Control versions 1300 (PostgreSQL 14–16), 1700 (17) and 1800 (18).
/// A byte-swapped header matches PostgreSQL's opposite-endian refusal.
fn pg_control_crc_offset(version: u32) -> Result<usize, String> {
    if version.is_multiple_of(65536) && version / 65536 != 0 {
        return Err(format!(
            "pg_control version {version} is opposite-endian and is not supported"
        ));
    }
    match version {
        1300 | 1700 => Ok(PG_CONTROL_CRC_OFFSET_THROUGH_V17),
        1800 => Ok(PG_CONTROL_CRC_OFFSET_V18),
        _ => Err(format!(
            "pg_control version {version} is not a supported PostgreSQL 14-18 layout"
        )),
    }
}

/// CRC-32C (Castagnoli), the `pg_crc32c` value stored in `pg_control`.
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

fn valid_wal_segment_bytes(size: u64) -> bool {
    (MIN_WAL_SEGMENT_BYTES..=MAX_WAL_SEGMENT_BYTES).contains(&size) && size.is_power_of_two()
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    bytes
        .get(offset..end)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
}

fn unique_field<'a>(text: &'a str, prefix: &str) -> Result<&'a str, String> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(value) = line.strip_prefix(prefix) {
            if found.is_some() {
                return Err(format!("backup_label repeats {prefix}"));
            }
            found = Some(value.trim());
        }
    }
    found.ok_or_else(|| format!("backup_label is missing {prefix}"))
}

fn read_limited(path: &Path, max: u64) -> Result<String, String> {
    String::from_utf8(read_bytes(path, max)?)
        .map_err(|_| format!("{} is not utf-8", path.display()))
}

fn read_bytes(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if metadata.len() > max {
        return Err(format!(
            "{} is {} bytes; limit is {max}",
            path.display(),
            metadata.len()
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(buffer)
}

fn safe_manifest_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\0')
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn bounded_text(value: &str) -> bool {
    value.len() <= 512 && !value.chars().any(char::is_control)
}

#[derive(Debug, serde::Deserialize)]
struct Manifest {
    #[serde(rename = "Files", default)]
    files: Vec<ManifestFile>,
    #[serde(rename = "WAL-Ranges")]
    wal_ranges: Vec<WalRange>,
}

#[derive(Debug, serde::Deserialize)]
struct ManifestFile {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Size")]
    size: u64,
    #[serde(rename = "Checksum-Algorithm")]
    algorithm: String,
    #[serde(rename = "Checksum")]
    checksum: String,
}

#[derive(Debug, serde::Deserialize)]
struct WalRange {
    #[serde(rename = "Timeline")]
    timeline: u64,
    #[serde(rename = "Start-LSN")]
    start_lsn: String,
    #[serde(rename = "End-LSN")]
    end_lsn: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const LABEL_NAME: &str = "dbev-0123456789abcdef0123456789abcdef";
    /// `DEFAULT_XLOG_SEG_SIZE` from `xlog.h`.
    const DEFAULT_WAL_SEGMENT_BYTES: u64 = 16 * 1024 * 1024;

    #[test]
    fn lsn_parser_accepts_bounds_and_ignores_padding() {
        assert_eq!(parse_lsn("0/0"), Some((0, 0)));
        assert_eq!(parse_lsn("0/2000028"), Some((0, 0x2000028)));
        assert_eq!(parse_lsn("FFFFFFFF/FFFFFFFF"), Some((u32::MAX, u32::MAX)));
        assert_eq!(parse_lsn("1/0"), Some((1, 0)));
        assert_eq!(parse_lsn("0001/0000000A"), parse_lsn("1/A"));
        assert_eq!(format_lsn((0, 0x2000028)), "0/2000028");
        assert_eq!(format_lsn((1, 0xA)), "1/A");
        for rejected in ["", "0/", "/1", "0/1/2", "g/1", "100000000/1", "0/ ", " 0/1"] {
            assert_eq!(parse_lsn(rejected), None, "{rejected}");
        }
    }

    #[test]
    fn label_and_manifest_must_agree() {
        let label = sample_label("0/2000028", 1);
        let manifest = sample_manifest("0/02000028", "0/2000100", 1, &[]);
        let recovery = recovery_from_label_and_manifest(&label, &manifest, LABEL_NAME).unwrap();
        assert_eq!(
            recovery.0.get("start_lsn").map(String::as_str),
            Some("0/2000028")
        );
        assert_eq!(
            recovery.0.get("end_lsn").map(String::as_str),
            Some("0/2000100")
        );
        assert_eq!(recovery.0.get("timeline").map(String::as_str), Some("1"));
        let drifted = sample_manifest("0/1", "0/2", 1, &[]);
        assert!(recovery_from_label_and_manifest(&label, &drifted, LABEL_NAME).is_err());
        let other_timeline = sample_manifest("0/2000028", "0/2000100", 2, &[]);
        assert!(recovery_from_label_and_manifest(&label, &other_timeline, LABEL_NAME).is_err());
        let fetched = label.replace("streamed", "fetched");
        assert!(recovery_from_label_and_manifest(&fetched, &manifest, LABEL_NAME).is_err());
        assert!(recovery_from_label_and_manifest(&label, &manifest, "dbev-other").is_err());
    }

    #[test]
    fn manifest_checksum_includes_the_wal_ranges_comma() {
        let file_hash = encode_lower(Sha256::digest(b"START\n").as_slice());
        assert_eq!(
            file_hash,
            "c89d6966e9327382a8a6cbafabc0c5c74e288f4fbf09baf4cd5362160d442f71"
        );
        let files = [("backup_label", 6, file_hash.as_str())];
        let ranges = [(1, "0/2000028", "0/2000100")];
        let v2 = postgres_manifest(2, Some(7_251_860_123_456_789_012), &files, &ranges);
        let v1 = postgres_manifest(1, None, &files, &ranges);
        assert!(
            v2.contains("8ab39a073a64bd64fac6432aac9c2e41b4a2b4c884216f092598a70a8952f0fb"),
            "{v2}"
        );
        assert!(
            v1.contains("d58d195a8c4dffa563d10bad6d06ca788e5883081c9ac26211b73b2a3c007388"),
            "{v1}"
        );
        verify_manifest_checksum(v2.as_bytes()).unwrap();
        verify_manifest_checksum(v1.as_bytes()).unwrap();

        let prefix = manifest_prefix(2, Some(7_251_860_123_456_789_012), &files, &ranges);
        assert!(prefix.ends_with(",\n"));
        let excluded =
            encode_lower(Sha256::digest(&prefix.as_bytes()[..prefix.len() - 2]).as_slice());
        let stale = format!("{prefix}\"Manifest-Checksum\": \"{excluded}\"}}\n");
        assert!(verify_manifest_checksum(stale.as_bytes()).is_err());

        let mut flipped = v2.into_bytes();
        let comma = prefix.len() - 2;
        assert_eq!(flipped[comma], b',');
        flipped[comma] = b';';
        assert!(verify_manifest_checksum(&flipped).is_err());
        flipped[comma] = b',';
        flipped[0] = b'x';
        assert!(verify_manifest_checksum(&flipped).is_err());
        assert!(verify_manifest_checksum(b"\"Manifest-Checksum\": \"ab\"}\n").is_err());
    }

    #[test]
    fn wal_segment_names_match_postgresql() {
        let seg = DEFAULT_WAL_SEGMENT_BYTES;
        assert_eq!(
            wal_segment_name(1, 0, seg).unwrap(),
            "000000010000000000000000"
        );
        assert_eq!(
            wal_segment_name(1, 2, seg).unwrap(),
            "000000010000000000000002"
        );
        assert_eq!(
            wal_segment_name(2, 256, seg).unwrap(),
            "000000020000000100000000"
        );
        assert_eq!(
            required_wal_segments(1, 0xFFFF00, 0x1000100, seg).unwrap(),
            vec![
                "000000010000000000000000".to_string(),
                "000000010000000000000001".to_string()
            ]
        );
        assert_eq!(
            required_wal_segments(1, 0, 0x1000000, seg).unwrap(),
            vec!["000000010000000000000000".to_string()]
        );
        assert!(required_wal_segments(1, 0x1000000, 0x1000000, seg).is_err());
        assert!(required_wal_segments(1, 0x20, 0x10, seg).is_err());
        assert_eq!(
            wal_segment_name(1, 32, 1024 * 1024).unwrap(),
            "000000010000000000000020"
        );
    }

    #[test]
    fn staged_tree_accepts_wal_segments_history_and_archive_status() {
        let seg = DEFAULT_WAL_SEGMENT_BYTES;
        let root = stage_tree(
            &[
                ("000000010000000000000000", seg),
                ("000000010000000000000001", seg),
            ],
            &[
                ("000000010000000000000003.partial", 100),
                ("00000002.history", 2),
                ("000000010000000000000002.00000028.backup", 4),
                ("archive_status/000000010000000000000000.done", 0),
                ("archive_status/00000001.history.ready", 0),
            ],
            &[],
            Some(&pg_control_fixture(1300, DEFAULT_WAL_SEGMENT_BYTES as u32)),
            &[(1, "0/FFFF00", "0/1000100")],
        );
        fs::create_dir_all(root.join("pg_wal/summaries")).unwrap();
        let outcome = verify_staged_tree(&root);
        let _ = fs::remove_dir_all(&root);
        assert_eq!(outcome.unwrap(), 2);
    }

    #[test]
    fn staged_tree_rejects_wal_that_postgres_does_not_emit() {
        for extra in [
            "pg_wal/not-wal",
            "pg_wal/00000001000000000000000a",
            "pg_wal/archive_status/notes.txt",
            "pg_wal/summaries/extra",
            "unexpected.txt",
        ] {
            let root = stage_tree(
                &[("000000010000000000000002", DEFAULT_WAL_SEGMENT_BYTES)],
                &[],
                &[(extra, b"x".as_slice())],
                None,
                &[(1, "0/2000028", "0/2000100")],
            );
            let outcome = verify_staged_tree(&root);
            let _ = fs::remove_dir_all(&root);
            let error = outcome.unwrap_err();
            assert!(
                error.contains("unexpected file"),
                "{extra} produced {error}"
            );
        }
    }

    #[test]
    fn staged_tree_requires_each_wal_range_segment_at_the_control_size() {
        let standard = pg_control_fixture(1300, DEFAULT_WAL_SEGMENT_BYTES as u32);
        let missing = stage_tree(
            &[],
            &[],
            &[],
            Some(&standard),
            &[(1, "0/2000028", "0/2000100")],
        );
        let missing_error = verify_staged_tree(&missing).unwrap_err();
        let _ = fs::remove_dir_all(&missing);
        assert!(
            missing_error.contains("missing pg_wal/000000010000000000000002"),
            "{missing_error}"
        );

        let short = stage_tree(
            &[("000000010000000000000002", 4096)],
            &[],
            &[],
            Some(&standard),
            &[(1, "0/2000028", "0/2000100")],
        );
        let short_error = verify_staged_tree(&short).unwrap_err();
        let _ = fs::remove_dir_all(&short);
        assert!(short_error.contains("WAL segment size"), "{short_error}");

        let one_mib: u32 = 1024 * 1024;
        for version in [1300_u32, 1700, 1800] {
            let control = pg_control_fixture(version, one_mib);
            assert_eq!(
                u32::from_le_bytes(control[220..224].try_into().unwrap()),
                131_072,
                "offset 220 is relseg_size, not the WAL segment size"
            );
            assert_eq!(
                u32::from_le_bytes(control[228..232].try_into().unwrap()),
                one_mib
            );
            let sized = stage_tree(
                &[("000000010000000000000020", u64::from(one_mib))],
                &[],
                &[],
                Some(&control),
                &[(1, "0/2000028", "0/2000100")],
            );
            let sized_ok = verify_staged_tree(&sized);
            let _ = fs::remove_dir_all(&sized);
            assert_eq!(sized_ok.unwrap(), 2, "version {version}");
        }
    }

    #[test]
    fn pg_control_rejects_unreadable_layouts_instead_of_assuming_16_mib() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);

        let root = control_dir(&pg_control_fixture(1800, 1024 * 1024));
        assert_eq!(wal_segment_bytes(&root).unwrap(), 1024 * 1024);
        let _ = fs::remove_dir_all(&root);

        let mut tail = pg_control_fixture(1300, DEFAULT_WAL_SEGMENT_BYTES as u32);
        tail[400] ^= 0xff;
        let ignored_tail = control_dir(&tail);
        assert_eq!(
            wal_segment_bytes(&ignored_tail).unwrap(),
            DEFAULT_WAL_SEGMENT_BYTES
        );
        let _ = fs::remove_dir_all(&ignored_tail);

        let mut corrupt = pg_control_fixture(1700, DEFAULT_WAL_SEGMENT_BYTES as u32);
        corrupt[200] ^= 0xff;
        expect_control_error(&corrupt, "checksum");

        let mut swapped = pg_control_fixture(1300, DEFAULT_WAL_SEGMENT_BYTES as u32);
        swapped[8..12].reverse();
        expect_control_error(&swapped, "opposite-endian");

        let mut unknown = pg_control_fixture(1300, DEFAULT_WAL_SEGMENT_BYTES as u32);
        unknown[8..12].copy_from_slice(&999_u32.to_le_bytes());
        expect_control_error(&unknown, "not a supported PostgreSQL 14-18 layout");

        expect_control_error(
            &pg_control_fixture(1300, 4096),
            "not a power of two between 1 MiB and 1 GiB",
        );
        expect_control_error(
            &pg_control_fixture(1800, 1_u32 << 31),
            "not a power of two between 1 MiB and 1 GiB",
        );
        expect_control_error(
            &pg_control_fixture(1300, 16 * 1024 * 1024)[..16],
            "too short",
        );

        let absent = std::env::temp_dir().join(format!("dbev-pg-control-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&absent).unwrap();
        let missing = wal_segment_bytes(&absent).unwrap_err();
        let _ = fs::remove_dir_all(&absent);
        assert!(missing.contains("pg_control"), "{missing}");
    }

    #[test]
    fn manifest_cannot_list_pg_wal_as_a_data_file() {
        let root = stage_tree(
            &[("000000010000000000000002", DEFAULT_WAL_SEGMENT_BYTES)],
            &[],
            &[],
            None,
            &[(1, "0/2000028", "0/2000100")],
        );
        let listed = postgres_manifest(
            2,
            Some(1),
            &[
                ("backup_label", 6, &file_sha(b"START\n")),
                (
                    "pg_wal/000000010000000000000002",
                    DEFAULT_WAL_SEGMENT_BYTES,
                    "ab",
                ),
            ],
            &[(1, "0/2000028", "0/2000100")],
        );
        fs::write(root.join("backup_manifest"), listed).unwrap();
        let error = verify_staged_tree(&root).unwrap_err();
        let _ = fs::remove_dir_all(&root);
        assert!(error.contains("lists WAL path"), "{error}");
    }

    fn sample_label(lsn: &str, timeline: u64) -> String {
        format!(
            "START WAL LOCATION: {lsn} (file 000000010000000000000002)\nCHECKPOINT LOCATION: {lsn}\nBACKUP METHOD: streamed\nBACKUP FROM: primary\nSTART TIME: 2026-01-01 00:00:00 UTC\nLABEL: {LABEL_NAME}\nSTART TIMELINE: {timeline}\n"
        )
    }

    fn sample_manifest(start: &str, end: &str, timeline: u64, files: &[&str]) -> String {
        let _ = files;
        format!(
            "{{\"System-Identifier\": 1, \"Files\": [], \"WAL-Ranges\": [{{\"Timeline\": {timeline}, \"Start-LSN\": \"{start}\", \"End-LSN\": \"{end}\"}}]}}"
        )
    }

    fn file_sha(bytes: &[u8]) -> String {
        encode_lower(Sha256::digest(bytes).as_slice())
    }

    /// Byte layout emitted by `AddFileToBackupManifest` and
    /// `AddWALInfoToBackupManifest` on PostgreSQL 14–18. The returned text ends
    /// with the checksummed `\n],\n` and has no checksum line yet.
    fn manifest_prefix(
        version: u8,
        system_id: Option<u64>,
        files: &[(&str, u64, &str)],
        ranges: &[(u64, &str, &str)],
    ) -> String {
        let mut prefix = String::from("{ \"PostgreSQL-Backup-Manifest-Version\": ");
        prefix.push(if version == 1 { '1' } else { '2' });
        prefix.push_str(",\n");
        if version != 1 {
            prefix.push_str("\"System-Identifier\": ");
            prefix.push_str(&system_id.unwrap().to_string());
            prefix.push_str(",\n");
        }
        prefix.push_str("\"Files\": [");
        for (index, (path, size, checksum)) in files.iter().enumerate() {
            if index == 0 {
                prefix.push('\n');
            } else {
                prefix.push_str(",\n");
            }
            prefix.push_str("{ \"Path\": \"");
            prefix.push_str(path);
            prefix.push_str("\", \"Size\": ");
            prefix.push_str(&size.to_string());
            prefix.push_str(
                ", \"Last-Modified\": \"2026-01-01 00:00:00 GMT\", \"Checksum-Algorithm\": \"SHA256\", \"Checksum\": \"",
            );
            prefix.push_str(checksum);
            prefix.push_str("\" }");
        }
        prefix.push_str("\n],\n\"WAL-Ranges\": [\n");
        for (index, (timeline, start, end)) in ranges.iter().enumerate() {
            if index > 0 {
                prefix.push_str(",\n");
            }
            prefix.push_str("{ \"Timeline\": ");
            prefix.push_str(&timeline.to_string());
            prefix.push_str(", \"Start-LSN\": \"");
            prefix.push_str(start);
            prefix.push_str("\", \"End-LSN\": \"");
            prefix.push_str(end);
            prefix.push_str("\" }");
        }
        prefix.push_str("\n],\n");
        prefix
    }

    fn postgres_manifest(
        version: u8,
        system_id: Option<u64>,
        files: &[(&str, u64, &str)],
        ranges: &[(u64, &str, &str)],
    ) -> String {
        let prefix = manifest_prefix(version, system_id, files, ranges);
        let digest = encode_lower(Sha256::digest(prefix.as_bytes()).as_slice());
        let mut manifest = prefix;
        manifest.push_str("\"Manifest-Checksum\": \"");
        manifest.push_str(&digest);
        manifest.push_str("\"}\n");
        manifest
    }

    /// Zero-filled `pg_control` with the LP64 field placement. `relseg_size`
    /// (220) stays 131072 and `xlog_blcksz` (224) stays 8192 so a reader of the
    /// wrong neighbor cannot accept this as a WAL segment size.
    fn pg_control_fixture(version: u32, wal_segment_bytes: u32) -> Vec<u8> {
        let mut bytes = vec![0_u8; 8192];
        bytes[8..12].copy_from_slice(&version.to_le_bytes());
        bytes[216..220].copy_from_slice(&8192_u32.to_le_bytes());
        bytes[220..224].copy_from_slice(&131_072_u32.to_le_bytes());
        bytes[224..228].copy_from_slice(&8192_u32.to_le_bytes());
        bytes[228..232].copy_from_slice(&wal_segment_bytes.to_le_bytes());
        let crc_offset = pg_control_crc_offset(version).unwrap();
        let crc = crc32c(&bytes[..crc_offset]);
        bytes[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    fn control_dir(bytes: &[u8]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("dbev-pg-control-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("global")).unwrap();
        fs::write(root.join("global/pg_control"), bytes).unwrap();
        root
    }

    fn expect_control_error(bytes: &[u8], needle: &str) {
        let root = control_dir(bytes);
        let error = wal_segment_bytes(&root).unwrap_err();
        let _ = fs::remove_dir_all(&root);
        assert!(error.contains(needle), "{error}");
    }

    fn stage_tree(
        segments: &[(&str, u64)],
        auxiliary: &[(&str, usize)],
        extra: &[(&str, &[u8])],
        control: Option<&[u8]>,
        ranges: &[(u64, &str, &str)],
    ) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("dbev-pg-parse-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let label = b"START\n";
        fs::write(root.join("backup_label"), label).unwrap();
        let mut files = vec![("backup_label", label.len() as u64, file_sha(label))];
        if let Some(control) = control {
            let path = root.join("global/pg_control");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, control).unwrap();
            files.push(("global/pg_control", control.len() as u64, file_sha(control)));
        }
        let file_refs: Vec<(&str, u64, &str)> = files
            .iter()
            .map(|(path, size, checksum)| (*path, *size, checksum.as_str()))
            .collect();
        fs::write(
            root.join("backup_manifest"),
            postgres_manifest(2, Some(7_251_860_123_456_789_012), &file_refs, ranges),
        )
        .unwrap();
        for (name, len) in segments {
            let path = root.join("pg_wal").join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::File::create(path).unwrap().set_len(*len).unwrap();
        }
        for (name, len) in auxiliary {
            let path = root.join("pg_wal").join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::File::create(&path)
                .unwrap()
                .set_len(*len as u64)
                .unwrap();
        }
        for (path, bytes) in extra {
            let full = root.join(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(full, bytes).unwrap();
        }
        root
    }
}
