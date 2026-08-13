use std::{fs, os::unix::fs::symlink, time::Duration};

use super::*;

#[test]
fn disk_scan_counts_regular_files_without_following_symlinks() {
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("data");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(data.join("nested")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(data.join("root.bin"), [0_u8; 7]).unwrap();
    fs::write(data.join("nested/child.bin"), [0_u8; 11]).unwrap();
    fs::write(outside.join("secret.bin"), [0_u8; 101]).unwrap();
    symlink(&outside, data.join("outside-link")).unwrap();

    assert_eq!(
        directory_size_blocking(&data, Duration::from_secs(1)).unwrap(),
        18
    );
}

#[test]
fn disk_scan_rejects_a_symlink_root() {
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("data");
    let linked = temporary.path().join("linked");
    fs::create_dir(&data).unwrap();
    symlink(&data, &linked).unwrap();

    assert!(directory_size_blocking(&linked, Duration::from_secs(1)).is_err());
}
