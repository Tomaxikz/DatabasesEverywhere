//! The multi-part AOF directory a captured snapshot is installed as.
//!
//! Redis 7+ and Valkey load `<appenddirname>/<appendfilename>.manifest` on an
//! `--appendonly yes` start. A manifest naming only an RDB-format base is the
//! same state a completed AOF rewrite leaves behind; the server loads the
//! base and then opens a new incremental file itself. The instance runs with
//! the default `appendonlydir` and `appendonly.aof` names, which the inventory
//! confirms before capture.

use std::{fs, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

use crate::io::files::{require_directory, require_regular_file};

pub(super) const AOF_DIRECTORY: &str = "appendonlydir";
pub(super) const BASE_FILE: &str = "appendonly.aof.1.base.rdb";
pub(super) const MANIFEST_FILE: &str = "appendonly.aof.manifest";
const MANIFEST: &str = "file appendonly.aof.1.base.rdb seq 1 type b\n";
/// `REDIS` plus a four-digit version, or `VALKEY` plus three digits.
const MAGIC_LEN: usize = 9;

/// Reads and validates the RDB header, returning it (e.g. `REDIS0012`).
pub(super) fn read_rdb_format(path: &Path) -> Result<String, String> {
    require_regular_file(path)?;
    let mut header = [0_u8; MAGIC_LEN];
    fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|error| format!("read the RDB header of {}: {error}", path.display()))?;
    let digits = |bytes: &[u8]| bytes.iter().all(u8::is_ascii_digit);
    let valid = (header.starts_with(b"REDIS") && digits(&header[5..]))
        || (header.starts_with(b"VALKEY") && digits(&header[6..]));
    if !valid {
        return Err(format!("{} is not an RDB file", path.display()));
    }
    Ok(String::from_utf8_lossy(&header).into_owned())
}

/// Writes the manifest naming the snapshot as the only AOF part.
pub(super) fn write_manifest(directory: &Path) -> Result<(), String> {
    let path = directory.join(MANIFEST_FILE);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    std::io::Write::write_all(&mut file, MANIFEST.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write {}: {error}", path.display()))
}

/// The directory holds exactly the manifest and an RDB base it names.
pub(super) fn check_layout(directory: &Path) -> Result<(), String> {
    require_directory(directory)?;
    let mut names = fs::read_dir(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(|error| format!("{}: {error}", directory.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    if names != [BASE_FILE, MANIFEST_FILE] {
        return Err(format!(
            "{} must hold exactly {BASE_FILE} and {MANIFEST_FILE}, found {names:?}",
            directory.display()
        ));
    }
    let manifest = directory.join(MANIFEST_FILE);
    require_regular_file(&manifest)?;
    let content = fs::read_to_string(&manifest)
        .map_err(|error| format!("{}: {error}", manifest.display()))?;
    if content != MANIFEST {
        return Err(format!(
            "{} does not name {BASE_FILE} as the only AOF part",
            manifest.display()
        ));
    }
    read_rdb_format(&directory.join(BASE_FILE)).map(|_| ())
}

/// Validates an extracted capture before it replaces the data directory.
/// Nothing needs rewriting: the server loads the base on a normal start.
pub(super) fn prepare_aof_restore(directory: &Path) -> Result<(), String> {
    check_layout(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged(header: &[u8]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join(AOF_DIRECTORY);
        fs::create_dir(&directory).unwrap();
        let mut rdb = header.to_vec();
        rdb.extend_from_slice(&[0xff; 9]);
        fs::write(directory.join(BASE_FILE), rdb).unwrap();
        root
    }

    #[test]
    fn redis_and_valkey_headers_are_recognised() {
        for (header, format) in [
            (&b"REDIS0012"[..], "REDIS0012"),
            (b"VALKEY080", "VALKEY080"),
        ] {
            let root = staged(header);
            let path = root.path().join(AOF_DIRECTORY).join(BASE_FILE);
            assert_eq!(read_rdb_format(&path).unwrap(), format);
        }
        for header in [&b"REDIS00x2"[..], b"SQLite fo", b"REDIS"] {
            let root = staged(header);
            let path = root.path().join(AOF_DIRECTORY).join(BASE_FILE);
            assert!(read_rdb_format(&path).is_err());
        }
    }

    #[test]
    fn a_sealed_directory_restores_and_anything_else_is_refused() {
        let root = staged(b"REDIS0012");
        let directory = root.path().join(AOF_DIRECTORY);
        assert!(check_layout(&directory).is_err(), "manifest is missing");
        write_manifest(&directory).unwrap();
        assert!(
            write_manifest(&directory).is_err(),
            "manifest is written once"
        );
        prepare_aof_restore(&directory).unwrap();
        assert_eq!(
            fs::read_to_string(directory.join(MANIFEST_FILE)).unwrap(),
            "file appendonly.aof.1.base.rdb seq 1 type b\n"
        );

        fs::write(directory.join("appendonly.aof.2.incr.aof"), b"").unwrap();
        assert!(prepare_aof_restore(&directory).is_err(), "stray AOF part");
        fs::remove_file(directory.join("appendonly.aof.2.incr.aof")).unwrap();

        fs::write(directory.join(MANIFEST_FILE), b"file other seq 1 type b\n").unwrap();
        assert!(prepare_aof_restore(&directory).is_err(), "foreign manifest");
    }

    #[test]
    fn linked_parts_are_refused() {
        let root = staged(b"REDIS0012");
        let directory = root.path().join(AOF_DIRECTORY);
        write_manifest(&directory).unwrap();
        fs::remove_file(directory.join(BASE_FILE)).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", directory.join(BASE_FILE)).unwrap();
        assert!(prepare_aof_restore(&directory).is_err());
    }
}
