use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
};

use super::PathConfig;

const PROTECTED_ROOTS: &[&str] = &[
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib64",
    "/media",
    "/mnt",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/srv",
    "/sys",
    "/tmp",
    "/usr",
    "/usr/bin",
    "/usr/lib",
    "/usr/local",
    "/usr/share",
    "/var",
    "/var/cache",
    "/var/lib",
    "/var/log",
    "/var/run",
    "/var/spool",
];

#[derive(Debug, thiserror::Error)]
pub enum HostPathPolicyError {
    #[error("{field} must be an absolute path: {value}")]
    Relative { field: &'static str, value: String },
    #[error("{field} must be normalized and contain only ordinary path components: {value}")]
    NonNormalized { field: &'static str, value: String },
    #[error("{field} may not target broad or protected host directory {value}")]
    Protected { field: &'static str, value: String },
    #[error("{field} is too shallow to be a managed runtime root: {value}")]
    TooShallow { field: &'static str, value: String },
    #[error("{field} traverses symlink {component}: {value}")]
    Symlink {
        field: &'static str,
        value: String,
        component: String,
    },
    #[error("{field} traverses non-directory component {component}: {value}")]
    NonDirectory {
        field: &'static str,
        value: String,
        component: String,
    },
    #[error("failed to inspect {field} component {component}: {source}")]
    Inspect {
        field: &'static str,
        component: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{field} duplicates managed runtime root {other}: {value}")]
    Duplicate {
        field: &'static str,
        other: &'static str,
        value: String,
    },
}

pub struct HostPathPolicy;

impl HostPathPolicy {
    pub fn validate(paths: &PathConfig) -> Result<(), HostPathPolicyError> {
        let roots = [
            ("paths.data", paths.data.clone()),
            ("paths.metadata", paths.metadata_root()),
            ("paths.volumes", paths.volumes_root()),
            ("paths.backups", paths.backups_root()),
            ("paths.sockets", paths.sockets.clone()),
            ("paths.locks", paths.locks.clone()),
            ("paths.logs", paths.logs.clone()),
            ("paths.artifacts", paths.artifacts.clone()),
            ("paths.exports", paths.exports_root()),
            ("paths.imports", paths.imports_root()),
            ("paths.fuse", paths.fuse_root()),
            ("paths.tmp", paths.tmp_root()),
        ];
        let mut seen = HashMap::<PathBuf, &'static str>::new();

        for (field, value) in roots {
            let path = validate_root(field, &value)?;
            if let Some(other) = seen.insert(path, field) {
                return Err(HostPathPolicyError::Duplicate {
                    field,
                    other,
                    value,
                });
            }
        }
        Ok(())
    }
}

fn validate_root(field: &'static str, value: &str) -> Result<PathBuf, HostPathPolicyError> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(HostPathPolicyError::Relative {
            field,
            value: value.to_string(),
        });
    }

    let components = path.components().collect::<Vec<_>>();
    if components.iter().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(HostPathPolicyError::NonNormalized {
            field,
            value: value.to_string(),
        });
    }
    let ordinary_components = components
        .iter()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    if ordinary_components < 2 {
        return Err(HostPathPolicyError::TooShallow {
            field,
            value: value.to_string(),
        });
    }

    let normalized = path.to_path_buf();
    if PROTECTED_ROOTS
        .iter()
        .any(|protected| normalized == Path::new(protected))
        || is_shallow_home_root(&normalized, ordinary_components)
    {
        return Err(HostPathPolicyError::Protected {
            field,
            value: value.to_string(),
        });
    }

    reject_symlink_components(field, value, &normalized)?;
    Ok(normalized)
}

fn is_shallow_home_root(path: &Path, ordinary_components: usize) -> bool {
    ordinary_components == 2 && (path.starts_with("/home") || path.starts_with("/root"))
}

fn reject_symlink_components(
    field: &'static str,
    value: &str,
    path: &Path,
) -> Result<(), HostPathPolicyError> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        let Component::Normal(component) = component else {
            continue;
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(HostPathPolicyError::Symlink {
                    field,
                    value: value.to_string(),
                    component: current.display().to_string(),
                });
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(HostPathPolicyError::NonDirectory {
                    field,
                    value: value.to_string(),
                    component: current.display().to_string(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => break,
            Err(source) => {
                return Err(HostPathPolicyError::Inspect {
                    field,
                    component: current.display().to_string(),
                    source,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn rejects_host_root_and_broad_system_roots() {
        for path in ["/", "/var", "/var/lib", "/home/operator"] {
            let paths = PathConfig {
                data: path.to_string(),
                ..Default::default()
            };
            assert!(HostPathPolicy::validate(&paths).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn rejects_duplicate_runtime_roots() {
        let defaults = PathConfig::default();
        let paths = PathConfig {
            metadata: defaults.volumes_root(),
            ..defaults
        };

        assert!(matches!(
            HostPathPolicy::validate(&paths),
            Err(HostPathPolicyError::Duplicate { .. })
        ));
    }

    #[test]
    fn rejects_existing_symlink_ancestor() {
        let temporary = tempfile::tempdir().unwrap();
        let real = temporary.path().join("real");
        let linked = temporary.path().join("linked");
        fs::create_dir(&real).unwrap();
        symlink(&real, &linked).unwrap();
        let paths = PathConfig {
            data: linked.join("dbev").display().to_string(),
            ..Default::default()
        };

        assert!(matches!(
            HostPathPolicy::validate(&paths),
            Err(HostPathPolicyError::Symlink { .. })
        ));
    }
}
