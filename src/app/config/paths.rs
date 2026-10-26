use serde::{Deserialize, Serialize};

use crate::utils::constants::defaults;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathConfig {
    pub data: String,
    pub run: String,
    pub metadata: String,
    pub volumes: String,
    pub backups: String,
    pub sockets: String,
    pub locks: String,
    pub logs: String,
    pub artifacts: String,
    pub exports: String,
    pub imports: String,
    pub fuse: String,
    pub tmp: String,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            data: defaults::DATA_PATH.to_string(),
            run: defaults::RUN_PATH.to_string(),
            metadata: String::new(),
            volumes: String::new(),
            backups: String::new(),
            sockets: String::new(),
            locks: String::new(),
            logs: String::new(),
            artifacts: String::new(),
            exports: String::new(),
            imports: String::new(),
            fuse: String::new(),
            tmp: String::new(),
        }
    }
}

/// Paths left empty are derived from `data` (or `run` for sockets and locks),
/// so moving a node only means changing those two.
impl PathConfig {
    pub fn run_root(&self) -> String {
        non_empty_or_else(&self.run, || defaults::RUN_PATH.to_string())
    }

    pub fn sockets_root(&self) -> String {
        non_empty_or_else(&self.sockets, || format!("{}/sockets", self.run_root()))
    }

    pub fn locks_root(&self) -> String {
        non_empty_or_else(&self.locks, || format!("{}/locks", self.run_root()))
    }

    pub fn logs_root(&self) -> String {
        non_empty_or_else(&self.logs, || format!("{}/logs", self.data.trim()))
    }

    pub fn artifacts_root(&self) -> String {
        non_empty_or_else(&self.artifacts, || {
            format!("{}/artifacts", self.data.trim())
        })
    }

    pub fn metadata_root(&self) -> String {
        non_empty_or_else(&self.metadata, || format!("{}/metadata", self.data.trim()))
    }

    pub fn volumes_root(&self) -> String {
        non_empty_or_else(&self.volumes, || format!("{}/volumes", self.data.trim()))
    }

    pub fn backups_root(&self) -> String {
        non_empty_or_else(&self.backups, || format!("{}/backups", self.data.trim()))
    }

    pub fn exports_root(&self) -> String {
        non_empty_or_else(&self.exports, || {
            format!("{}/exports", self.artifacts_root())
        })
    }

    pub fn imports_root(&self) -> String {
        non_empty_or_else(&self.imports, || {
            format!("{}/imports", self.artifacts_root())
        })
    }

    pub fn fuse_root(&self) -> String {
        non_empty_or_else(&self.fuse, || format!("{}/fuse", self.data.trim()))
    }

    pub fn tmp_root(&self) -> String {
        non_empty_or_else(&self.tmp, || format!("{}/tmp", self.data.trim()))
    }
}

pub(crate) fn non_empty_or_else(value: &str, fallback: impl FnOnce() -> String) -> String {
    let value = value.trim();
    if value.is_empty() {
        fallback()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_folder_follows_the_data_and_run_roots() {
        let paths = PathConfig {
            data: "/srv/dbev-2".to_string(),
            run: "/run/dbev-2".to_string(),
            ..PathConfig::default()
        };
        assert_eq!(paths.metadata_root(), "/srv/dbev-2/metadata");
        assert_eq!(paths.volumes_root(), "/srv/dbev-2/volumes");
        assert_eq!(paths.logs_root(), "/srv/dbev-2/logs");
        assert_eq!(paths.artifacts_root(), "/srv/dbev-2/artifacts");
        assert_eq!(paths.exports_root(), "/srv/dbev-2/artifacts/exports");
        assert_eq!(paths.sockets_root(), "/run/dbev-2/sockets");
        assert_eq!(paths.locks_root(), "/run/dbev-2/locks");

        let config = crate::config::Config {
            paths,
            ..Default::default()
        };
        assert_eq!(config.api_socket_path(), "/run/dbev-2/api.sock");
    }

    #[test]
    fn explicit_folders_and_older_full_configs_keep_their_paths() {
        let paths = PathConfig {
            logs: "/var/log/dbev".to_string(),
            sockets: "/run/dbev/sockets".to_string(),
            artifacts: "/mnt/exports".to_string(),
            ..PathConfig::default()
        };
        assert_eq!(paths.logs_root(), "/var/log/dbev");
        assert_eq!(paths.sockets_root(), "/run/dbev/sockets");
        assert_eq!(paths.imports_root(), "/mnt/exports/imports");
        assert_eq!(PathConfig::default().sockets_root(), "/run/dbev/sockets");
        assert_eq!(PathConfig::default().logs_root(), "/var/lib/dbev/logs");
    }
}
