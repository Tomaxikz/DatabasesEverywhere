use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathConfig {
    pub data: String,
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
            metadata: String::new(),
            volumes: String::new(),
            backups: String::new(),
            sockets: defaults::SOCKETS_PATH.to_string(),
            locks: defaults::LOCKS_PATH.to_string(),
            logs: defaults::LOGS_PATH.to_string(),
            artifacts: defaults::ARTIFACTS_PATH.to_string(),
            exports: String::new(),
            imports: String::new(),
            fuse: String::new(),
            tmp: String::new(),
        }
    }
}

impl PathConfig {
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
            format!("{}/exports", self.artifacts.trim())
        })
    }

    pub fn imports_root(&self) -> String {
        non_empty_or_else(&self.imports, || {
            format!("{}/imports", self.artifacts.trim())
        })
    }

    pub fn fuse_root(&self) -> String {
        non_empty_or_else(&self.fuse, || format!("{}/fuse", self.data.trim()))
    }

    pub fn tmp_root(&self) -> String {
        non_empty_or_else(&self.tmp, || format!("{}/tmp", self.data.trim()))
    }
}

fn non_empty_or_else(value: &str, fallback: impl FnOnce() -> String) -> String {
    let value = value.trim();
    if value.is_empty() {
        fallback()
    } else {
        value.to_string()
    }
}
