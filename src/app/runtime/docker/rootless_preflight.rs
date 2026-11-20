//! Read-only host checks for a rootless Podman account. They only look at
//! local files, so a host that delegates cgroups or allocates subordinate IDs
//! some other way is reported as unverified rather than as broken.

use std::{fs, io};

/// Subordinate IDs an image with a full 16-bit ID space needs in each map.
pub(crate) const REQUIRED_SUBORDINATE_IDS: u64 = 65_536;
const REQUIRED_CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];
pub(crate) const CGROUP_OWNERSHIP: &str = "ownership of the delegated cgroup by the account";
/// IDs 0..=4294967294 can be mapped; 4294967295 is reserved by the kernel.
const MAPPABLE_ID_END: u64 = (1 << 32) - 1;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ControllerStatus {
    Delegated,
    Missing(Vec<&'static str>),
    Unknown(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SubordinateStatus {
    Sufficient,
    Insufficient { subuid: u64, subgid: u64 },
    Unknown(String),
}

pub(crate) fn missing_controllers(contents: &str) -> Vec<&'static str> {
    let controllers: Vec<_> = contents.split_whitespace().collect();
    REQUIRED_CONTROLLERS
        .into_iter()
        .filter(|controller| !controllers.contains(controller))
        .collect()
}

pub(crate) fn user_manager_controllers_path(uid: u32) -> String {
    format!("/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers")
}

/// Controllers delegated to the account's systemd user manager. A Podman
/// service that runs elsewhere (cgroupfs manager, a system unit with `User=`)
/// is not described by this file, hence `Unknown` when it cannot be read.
pub(crate) fn controller_status(uid: u32) -> ControllerStatus {
    let path = user_manager_controllers_path(uid);
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let missing = missing_controllers(&contents);
            if missing.is_empty() {
                ControllerStatus::Delegated
            } else {
                ControllerStatus::Missing(missing)
            }
        }
        Err(error) => ControllerStatus::Unknown(format!("{path}: {error}")),
    }
}

/// Total distinct subordinate IDs allocated to the account, by name or by
/// numeric uid, across every valid line. Overlapping ranges count once.
pub(crate) fn subordinate_capacity(contents: &str, username: Option<&str>, uid: u32) -> u64 {
    let uid = uid.to_string();
    let mut ranges = contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut fields = line.split(':');
            let owner = fields.next()?;
            let start = fields.next()?.parse::<u64>().ok()?;
            let count = fields.next()?.parse::<u64>().ok()?;
            let end = start.checked_add(count)?;
            let owned = owner == uid || username.is_some_and(|name| owner == name);
            (owned && fields.next().is_none() && count > 0 && end <= MAPPABLE_ID_END)
                .then_some((start, end))
        })
        .collect::<Vec<_>>();
    ranges.sort_unstable();
    let mut total = 0;
    let mut covered = 0;
    for (start, end) in ranges {
        let start = start.max(covered);
        if end > start {
            total += end - start;
            covered = end;
        }
    }
    total
}

pub(crate) fn subordinate_status(username: Option<&str>, uid: u32) -> SubordinateStatus {
    let read = |path: &str| {
        fs::read_to_string(path)
            .map(|contents| subordinate_capacity(&contents, username, uid))
            .map_err(|error| format!("{path}: {error}"))
    };
    match (read("/etc/subuid"), read("/etc/subgid")) {
        (Ok(subuid), Ok(subgid))
            if subuid >= REQUIRED_SUBORDINATE_IDS && subgid >= REQUIRED_SUBORDINATE_IDS =>
        {
            SubordinateStatus::Sufficient
        }
        (Ok(subuid), Ok(subgid)) => SubordinateStatus::Insufficient { subuid, subgid },
        (Err(reason), _) | (_, Err(reason)) => SubordinateStatus::Unknown(reason),
    }
}

/// True when `/etc/nsswitch.conf` names a subordinate-ID provider, in which
/// case the local files are not the source of truth.
pub(crate) fn nss_subid_provider_configured(nsswitch: &str) -> bool {
    nsswitch.lines().any(|line| {
        let line = line.split('#').next().unwrap_or_default().trim();
        line.strip_prefix("subid")
            .and_then(|rest| rest.trim_start().strip_prefix(':'))
            .is_some_and(|sources| {
                sources
                    .split_whitespace()
                    .any(|source| source != "files" && !source.starts_with('['))
            })
    })
}

/// Whether the local subid files may not be the whole story: another
/// provider is configured, or the provider configuration cannot be read.
pub(crate) fn uses_nss_subid_provider() -> bool {
    match fs::read_to_string("/etc/nsswitch.conf") {
        Ok(contents) => nss_subid_provider_configured(&contents),
        Err(error) => error.kind() != io::ErrorKind::NotFound,
    }
}

/// Delegation of a systemd-managed unit, from `systemctl show` output with
/// the `ControlGroup`, `Delegate` and `DelegateControllers` properties and
/// the `cgroup.controllers` file of that control group.
pub(crate) fn managed_controller_status(
    show: &str,
    uid: u32,
    read_controllers: impl FnOnce(&str) -> io::Result<String>,
    owner_of: impl Fn(&str) -> io::Result<u32>,
) -> ControllerStatus {
    let property = |name: &str| {
        show.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .map(str::trim)
    };
    let Some(control_group) = property("ControlGroup").filter(|group| !group.is_empty()) else {
        return ControllerStatus::Unknown("the unit has no control group yet".to_string());
    };
    if !control_group.starts_with('/') || control_group.split('/').any(|part| part == "..") {
        return ControllerStatus::Unknown(format!("unexpected control group {control_group}"));
    }
    if property("Delegate") != Some("yes") {
        return ControllerStatus::Missing(REQUIRED_CONTROLLERS.to_vec());
    }
    if let Some(delegated) = property("DelegateControllers") {
        let missing = missing_controllers(delegated);
        if !missing.is_empty() {
            return ControllerStatus::Missing(missing);
        }
    }
    let path = format!("/sys/fs/cgroup{control_group}/cgroup.controllers");
    match read_controllers(&path) {
        Ok(contents) => {
            let missing = missing_controllers(&contents);
            if !missing.is_empty() {
                return ControllerStatus::Missing(missing);
            }
        }
        Err(error) => return ControllerStatus::Unknown(format!("{path}: {error}")),
    }
    // Visible controllers are not enough: the account itself has to own the
    // delegated directory and its control files to create child cgroups and
    // enable controllers for containers.
    for entry in ["", "/cgroup.procs", "/cgroup.subtree_control"] {
        let path = format!("/sys/fs/cgroup{control_group}{entry}");
        match owner_of(&path) {
            Ok(owner) if owner == uid => {}
            Ok(_) => return ControllerStatus::Missing(vec![CGROUP_OWNERSHIP]),
            Err(error) => return ControllerStatus::Unknown(format!("{path}: {error}")),
        }
    }
    ControllerStatus::Delegated
}

/// Account name for `uid` from a passwd-format file, without running an NSS
/// helper process.
pub(crate) fn local_account_name(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let record_uid = fields.nth(1)?.parse::<u32>().ok()?;
        (record_uid == uid && !name.is_empty()).then(|| name.to_string())
    })
}

fn read_local_account_name(uid: u32) -> io::Result<Option<String>> {
    Ok(local_account_name(&fs::read_to_string("/etc/passwd")?, uid))
}

/// Daemon startup only warns: a working engine may get its delegation or its
/// subordinate IDs from a place these checks cannot see.
pub(crate) fn log_startup_advisories(uid: u32) {
    match controller_status(uid) {
        ControllerStatus::Delegated => {}
        ControllerStatus::Missing(missing) => tracing::warn!(
            uid,
            missing = missing.join(", "),
            "the rootless Podman account's user manager does not delegate these cgroup controllers; CPU, memory or PID limits may be rejected or not enforced"
        ),
        ControllerStatus::Unknown(reason) => tracing::warn!(
            uid,
            %reason,
            "cannot verify delegated cgroup controllers for the rootless Podman account; CPU, memory and PID limits may not be enforced"
        ),
    }
    let username = read_local_account_name(uid).ok().flatten();
    match subordinate_status(username.as_deref(), uid) {
        SubordinateStatus::Sufficient => {}
        SubordinateStatus::Insufficient { subuid, subgid } => tracing::warn!(
            uid,
            subuid,
            subgid,
            required = REQUIRED_SUBORDINATE_IDS,
            "the rootless Podman account has fewer subordinate IDs in /etc/subuid and /etc/subgid than images may need; another subordinate-ID source may be configured"
        ),
        SubordinateStatus::Unknown(reason) => tracing::warn!(
            uid,
            %reason,
            "cannot verify subordinate ID ranges for the rootless Podman account"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_decision() {
        assert!(missing_controllers("io cpu pids memory cpuset\n").is_empty());
        assert_eq!(missing_controllers("cpu io"), vec!["memory", "pids"]);
        assert_eq!(missing_controllers(""), vec!["cpu", "memory", "pids"]);
    }

    #[test]
    fn subordinate_capacity_counts_name_and_numeric_owners() {
        let data = "# comment\n\nsvc:100000:65536\n1002:200000:70000\nsmall:1:65535\n";
        assert_eq!(subordinate_capacity(data, Some("svc"), 1001), 65_536);
        assert_eq!(subordinate_capacity(data, Some("other"), 1002), 70_000);
        assert_eq!(subordinate_capacity(data, None, 1002), 70_000);
        assert_eq!(subordinate_capacity(data, Some("small"), 1003), 65_535);
        assert_eq!(subordinate_capacity(data, Some("missing"), 1004), 0);
    }

    #[test]
    fn subordinate_capacity_adds_split_ranges_and_counts_overlap_once() {
        let split = "svc:100000:32768\nsvc:300000:32768\n";
        assert_eq!(subordinate_capacity(split, Some("svc"), 1001), 65_536);
        let overlapping = "svc:100000:40000\n1001:120000:40000\n";
        assert_eq!(subordinate_capacity(overlapping, Some("svc"), 1001), 60_000);
    }

    #[test]
    fn subordinate_capacity_ignores_malformed_and_out_of_range_lines() {
        let data = "#svc:1:65536\nsvc:no:65536\nsvc:1:65536:extra\nsvc:4294967295:2\nsvc:5:0\n";
        assert_eq!(subordinate_capacity(data, Some("svc"), 1001), 0);
    }

    #[test]
    fn subordinate_capacity_excludes_the_reserved_last_id() {
        assert_eq!(
            subordinate_capacity("svc:4294901759:65536\n", Some("svc"), 1001),
            65_536
        );
        assert_eq!(
            subordinate_capacity("svc:4294901760:65536\n", Some("svc"), 1001),
            0
        );
    }

    #[test]
    fn managed_delegation_needs_the_unit_setting_the_live_controllers_and_ownership() {
        const GROUP: &str = "/user.slice/user-1001.slice/user@1001.service";
        let show = format!(
            "ControlGroup={GROUP}\nDelegate=yes\nDelegateControllers=cpu cpuset io memory pids\n"
        );
        let status = |show: &str, controllers: io::Result<&str>, owner: io::Result<u32>| {
            managed_controller_status(
                show,
                1001,
                |path| {
                    assert_eq!(path, format!("/sys/fs/cgroup{GROUP}/cgroup.controllers"));
                    controllers.map(str::to_string)
                },
                |path| {
                    assert!(
                        path.starts_with(&format!("/sys/fs/cgroup{GROUP}")),
                        "{path}"
                    );
                    match &owner {
                        Ok(uid) => Ok(*uid),
                        Err(error) => Err(io::Error::from(error.kind())),
                    }
                },
            )
        };
        assert_eq!(
            status(&show, Ok("cpu io memory pids"), Ok(1001)),
            ControllerStatus::Delegated
        );
        // The unit asks for the controllers but the kernel tree lacks one.
        assert_eq!(
            status(&show, Ok("memory pids"), Ok(1001)),
            ControllerStatus::Missing(vec!["cpu"])
        );
        // Controllers visible in the tree, but not delegated to this unit.
        assert_eq!(
            status(
                &show.replace("Delegate=yes", "Delegate=no"),
                Ok("cpu memory pids"),
                Ok(1001)
            ),
            ControllerStatus::Missing(vec!["cpu", "memory", "pids"])
        );
        assert_eq!(
            status(
                &show.replace("cpu cpuset io memory pids", "memory pids"),
                Ok("cpu memory pids"),
                Ok(1001)
            ),
            ControllerStatus::Missing(vec!["cpu"])
        );
        // Everything reported, but the cgroup still belongs to root: the
        // setting was reloaded and the manager has not restarted yet.
        assert_eq!(
            status(&show, Ok("cpu memory pids"), Ok(0)),
            ControllerStatus::Missing(vec![CGROUP_OWNERSHIP])
        );
        assert!(matches!(
            status(
                &show,
                Err(io::Error::from(io::ErrorKind::PermissionDenied)),
                Ok(1001)
            ),
            ControllerStatus::Unknown(_)
        ));
        assert!(matches!(
            status(
                &show,
                Ok("cpu memory pids"),
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            ),
            ControllerStatus::Unknown(_)
        ));
        for show in [
            "Delegate=yes\n",
            "ControlGroup=\nDelegate=yes\n",
            "ControlGroup=/a/../b\nDelegate=yes\n",
        ] {
            assert!(matches!(
                status(show, Ok("cpu memory pids"), Ok(1001)),
                ControllerStatus::Unknown(_)
            ));
        }
    }

    #[test]
    fn nss_subid_provider_is_detected_only_for_non_file_sources() {
        assert!(nss_subid_provider_configured("passwd: files\nsubid: sss\n"));
        assert!(nss_subid_provider_configured("subid:files sss # note\n"));
        assert!(!nss_subid_provider_configured("subid: files\n"));
        assert!(!nss_subid_provider_configured(
            "# subid: sss\npasswd: files sss\n"
        ));
        assert!(!nss_subid_provider_configured("subids: sss\n"));
    }

    #[test]
    fn local_account_name_matches_the_uid_field() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\nsvc:x:1001:1001::/home/svc:/bin/sh\n";
        assert_eq!(local_account_name(passwd, 1001).as_deref(), Some("svc"));
        assert_eq!(local_account_name(passwd, 1002), None);
        assert_eq!(local_account_name("bad:x:notanumber:1\n", 1), None);
    }
}
