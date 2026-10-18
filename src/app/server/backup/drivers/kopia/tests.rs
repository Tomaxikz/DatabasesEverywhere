use super::*;

const SOURCE: &str = "/var/lib/dbev/backups/.staging/inst_one/.0d9c.bundle";

/// `kopia snapshot list --json` output (v0.22): user tags are stored
/// under `tag:<key>`, and an untagged checkpoint of the same source is
/// listed alongside the final snapshot.
fn authentic_snapshot_list() -> String {
    format!(
        r#"[
  {{
    "id": "8f3a2c9d0e1b4f5a6b7c8d9e0f1a2b3c",
    "source": {{ "host": "node-a", "userName": "root", "path": "{SOURCE}" }},
    "description": "",
    "startTime": "2026-10-11T09:00:00.123456789Z",
    "endTime": "2026-10-11T09:45:00.123456789Z",
    "stats": {{ "totalSize": 1048576, "excludedTotalSize": 0, "fileCount": 1, "cachedFiles": 0, "nonCachedFiles": 1, "dirCount": 1, "excludedFileCount": 0, "excludedDirCount": 0, "ignoredErrorCount": 0, "errorCount": 0 }},
    "incomplete": "checkpoint",
    "rootEntry": {{ "name": ".0d9c.bundle", "type": "d", "mode": "0700", "mtime": "2026-10-11T09:00:00Z", "obj": "kc0ffee" }},
    "retentionReason": []
  }},
  {{
    "id": "1b2c3d4e5f60718293a4b5c6d7e8f901",
    "source": {{ "host": "node-a", "userName": "root", "path": "{SOURCE}" }},
    "description": "DatabasesEverywhere backup one.physical.tar.gz",
    "startTime": "2026-10-11T09:00:00.123456789Z",
    "endTime": "2026-10-11T10:00:00.123456789Z",
    "stats": {{ "totalSize": 2097152, "excludedTotalSize": 0, "fileCount": 3, "cachedFiles": 0, "nonCachedFiles": 3, "dirCount": 1, "excludedFileCount": 0, "excludedDirCount": 0, "ignoredErrorCount": 0, "errorCount": 0 }},
    "rootEntry": {{ "name": ".0d9c.bundle", "type": "d", "mode": "0700", "mtime": "2026-10-11T09:00:00Z", "obj": "k123", "summ": {{ "size": 2097152, "files": 3, "symlinks": 0, "dirs": 1, "maxTime": "2026-10-11T09:00:00Z", "numFailed": 0 }} }},
    "tags": {{
      "tag:dbev-instance": "inst_one",
      "tag:dbev-backup": "one.physical.tar.gz",
      "tag:dbev-size": "42",
      "tag:dbev-sha256": "{sha}",
      "tag:dbev-created": "1700000000",
      "tag:dbev-created-at": "2023-11-14T22_13_20Z",
      "tag:dbev-protocol": "postgres",
      "tag:dbev-catalog": "true",
      "tag:dbev-layout": "physical"
    }},
    "pins": ["dbev"],
    "retentionReason": ["latest-1", "hourly-1", "daily-1"]
  }}
]"#,
        sha = "a".repeat(64)
    )
}

#[test]
fn authentic_cli_snapshot_lists_are_read_through_stored_tag_keys() {
    let snapshots = parse_snapshot_list(authentic_snapshot_list().as_bytes()).unwrap();
    assert_eq!(snapshots.len(), 2);
    let checkpoint = &snapshots[0];
    assert_eq!(checkpoint.incomplete, "checkpoint");
    assert!(checkpoint.tags.is_empty());
    assert_eq!(checkpoint.source.path, SOURCE);

    let record = record_from_snapshot("inst_one", &snapshots[1]).unwrap();
    assert_eq!(record.backup_id, "one.physical.tar.gz");
    assert_eq!(record.protocol, Protocol::Postgres);
    assert_eq!(record.layout, BackupLayout::Physical);
    assert!(record.catalog_available);
}

#[test]
fn unprefixed_tags_are_accepted_but_conflicting_forms_are_not() {
    let snapshot = |tags: serde_json::Value| -> KopiaManifest {
        serde_json::from_value(serde_json::json!({
            "id": "m1",
            "source": { "host": "h", "userName": "u", "path": SOURCE },
            "rootEntry": { "obj": "k1" },
            "tags": tags,
        }))
        .unwrap()
    };
    let plain = normalize_tags(snapshot(serde_json::json!({ "dbev-backup": "a" }))).unwrap();
    assert_eq!(plain.tags.get(TAG_BACKUP).map(String::as_str), Some("a"));
    let same = serde_json::json!({ "dbev-backup": "a", "tag:dbev-backup": "a" });
    assert!(normalize_tags(snapshot(same)).is_ok());
    let conflict = serde_json::json!({ "dbev-backup": "a", "tag:dbev-backup": "b" });
    assert!(matches!(
        normalize_tags(snapshot(conflict)),
        Err(BackupStoreError::Corrupt(_))
    ));
}

#[tokio::test]
async fn create_passes_unprefixed_tags_and_a_pin_value() {
    let manifest = v2_manifest().await;
    let arguments = create_arguments(SOURCE, &manifest, legacy_manifest_tags(&manifest));
    let position = |flag: &str| arguments.iter().position(|arg| arg == flag).unwrap();
    assert_eq!(arguments[2], SOURCE);
    // kingpin rejects `--pin --tags ...`: the next token must be a value.
    assert_eq!(arguments[position("--pin") + 1], DBEV_PIN);
    let tag = &arguments[position("--tags") + 1];
    assert!(tag.to_str().unwrap().starts_with("dbev-instance:"));
    assert!(
        !arguments
            .iter()
            .any(|arg| arg.to_str().unwrap().starts_with("tag:"))
    );
}

#[test]
fn source_paths_match_kopia_clean_without_resolving_links() {
    assert_eq!(
        snapshot_source_path(Path::new("/var/lib/dbev/./backups//.staging/i/.x.bundle/")).unwrap(),
        "/var/lib/dbev/backups/.staging/i/.x.bundle"
    );
    for path in ["relative/bundle", "/var/../etc", "/"] {
        assert!(snapshot_source_path(Path::new(path)).is_err(), "{path}");
    }
}

#[test]
fn checkpoints_are_found_by_their_source_path_label() {
    let arguments = source_manifest_arguments(SOURCE);
    assert_eq!(
        arguments[..2],
        [OsString::from("manifest"), OsString::from("list")]
    );
    assert!(arguments.contains(&OsString::from("type:snapshot")));
    assert!(arguments.contains(&OsString::from(format!("path:{SOURCE}"))));

    // `kopia manifest list --json` output (v0.22 manifest.EntryMetadata).
    let stdout = format!(
        r#"[
  {{ "id": "8f3a2c9d0e1b4f5a6b7c8d9e0f1a2b3c", "length": 812, "labels": {{ "hostname": "node-a", "path": "{SOURCE}", "type": "snapshot", "username": "root" }}, "mtime": "2026-10-11T09:45:00.1Z" }},
  {{ "id": "1b2c3d4e5f60718293a4b5c6d7e8f901", "length": 1204, "labels": {{ "hostname": "node-a", "path": "{SOURCE}", "tag:dbev-backup": "one.physical.tar.gz", "type": "snapshot", "username": "root" }}, "mtime": "2026-10-11T10:00:00.1Z" }}
]"#
    );
    let ids = parse_manifest_entries(stdout.as_bytes())
        .unwrap()
        .into_iter()
        .map(|entry| source_entry_id(entry, SOURCE))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(ids.len(), 2);

    for labels in [
        serde_json::json!({ "type": "snapshot", "path": "/other" }),
        serde_json::json!({ "type": "policy", "path": SOURCE }),
    ] {
        let entry: KopiaManifestEntry =
            serde_json::from_value(serde_json::json!({ "id": "m", "labels": labels })).unwrap();
        assert!(source_entry_id(entry, SOURCE).is_err());
    }
}

#[test]
fn restore_uses_the_snapshot_restore_command() {
    let arguments = restore_arguments("k123/archive", Path::new("/tmp/archive"));
    assert_eq!(arguments[0], "snapshot");
    assert_eq!(arguments[1], "restore");
    assert_eq!(arguments[2], "k123/archive");
}

/// A snapshot as `snapshot list --json` returns it after `snapshot create
/// --tags <tag>...`: each `key:value` argument stored as `tag:key`.
fn snapshot_with_tags(tags: Vec<String>) -> KopiaManifest {
    normalize_tags(KopiaManifest {
        id: "m456".to_string(),
        source: KopiaSource {
            path: SOURCE.to_string(),
        },
        root_entry: KopiaRootEntry {
            object_id: "k456".to_string(),
        },
        incomplete: String::new(),
        tags: tags
            .into_iter()
            .map(|tag| {
                let (key, value) = tag.split_once(':').unwrap();
                (format!("{STORED_TAG_PREFIX}{key}"), value.to_string())
            })
            .collect(),
    })
    .unwrap()
}

async fn v2_manifest() -> StoredBackup {
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("archive");
    tokio::fs::write(&archive, b"archive").await.unwrap();
    crate::server::backup::build_manifest(
        "two.physical.tar.gz".to_string(),
        "inst_one".to_string(),
        Protocol::Postgres,
        BackupLayout::Physical,
        &archive,
        false,
        crate::server::backup::test_details(BackupLayout::Physical),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn schema_two_tags_bind_the_canonical_manifest_and_starve_legacy_readers() {
    let manifest = v2_manifest().await;
    let bytes = manifest.to_json().unwrap();
    let checksum = crate::server::backup::sha256_bytes(&bytes);
    let snapshot = snapshot_with_tags(v2_manifest_tags(&manifest, &checksum).unwrap());

    let projection = V2Projection::from_snapshot("inst_one", &snapshot).unwrap();
    assert_eq!(projection.manifest_sha256, checksum);
    projection.check(&manifest).unwrap();
    // A schema 1 reader must not reconstruct a manifest from these tags.
    assert!(matches!(
        record_from_snapshot("inst_one", &snapshot),
        Err(BackupStoreError::Corrupt(_))
    ));

    let mut altered = manifest.clone();
    altered.details.as_mut().unwrap().restore_recipe.version = 9;
    assert!(projection.check(&altered).is_err());
}

#[tokio::test]
async fn unknown_kopia_manifest_versions_are_unsupported() {
    let driver = KopiaBackupDriver::new(
        BackupKopiaConfig {
            executable: "/usr/bin/kopia".to_string(),
            ..Default::default()
        },
        PathBuf::from("/var/lib/dbev/backups"),
    )
    .unwrap();
    let mut tags = v2_manifest_tags(&v2_manifest().await, &"a".repeat(64)).unwrap();
    tags.retain(|tag| !tag.starts_with(TAG_MANIFEST_VERSION));
    tags.push(format!("{TAG_MANIFEST_VERSION}:3"));
    assert!(matches!(
        driver
            .load_record("inst_one", &snapshot_with_tags(tags))
            .await,
        Err(BackupStoreError::UnsupportedFormat(_))
    ));
}
