use std::path::PathBuf;

/// Returns the kernel-reported cgroup membership for either the unified
/// hierarchy (`None`) or one named v1 controller.
pub(crate) fn membership_path(contents: &str, controller: Option<&str>) -> Option<String> {
    contents.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        match controller {
            None if controllers.is_empty() => Some(path.to_string()),
            Some(controller) if controllers.split(',').any(|value| value == controller) => {
                Some(path.to_string())
            }
            _ => None,
        }
    })
}

/// Converts a cgroup membership into a relative path without permitting it to
/// escape a controller mount.
pub(crate) fn safe_relative_path(value: &str) -> Option<PathBuf> {
    let mut path = PathBuf::new();
    for component in value.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || component.contains(['/', '\\']) {
            return None;
        }
        path.push(component);
    }
    Some(path)
}

/// Decodes the escapes used by `/proc/*/mountinfo` path fields.
pub(crate) fn unescape_mountinfo(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unified_and_legacy_memberships() {
        let contents = "0::/system.slice/docker.scope\n4:cpu,cpuacct:/docker/abc\n";
        assert_eq!(
            membership_path(contents, None).as_deref(),
            Some("/system.slice/docker.scope")
        );
        assert_eq!(
            membership_path(contents, Some("cpu")).as_deref(),
            Some("/docker/abc")
        );
    }

    #[test]
    fn rejects_parent_traversal() {
        assert_eq!(safe_relative_path("/docker/abc"), Some("docker/abc".into()));
        assert_eq!(safe_relative_path("/docker/../victim"), None);
    }
}
