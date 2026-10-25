//! Console defaults kept next to the node config, in `console.yml`.
//!
//! The daemon has no notion of a public host; the panel supplies one with
//! each new instance. A standalone node records the one chosen during first
//! run here, so the "new instance" form can suggest it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FILE_NAME: &str = "console.yml";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct ConsoleSettings {
    /// Host put into connection strings of instances created here.
    pub public_host: String,
}

impl ConsoleSettings {
    pub(super) fn path(config_path: &Path) -> PathBuf {
        config_path.with_file_name(FILE_NAME)
    }

    /// Only a convenience: a missing or unreadable file means no defaults.
    pub(super) fn load(config_path: &Path) -> Self {
        std::fs::read_to_string(Self::path(config_path))
            .ok()
            .and_then(|text| yaml_serde::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub(super) fn to_yaml(&self) -> anyhow::Result<String> {
        Ok(format!(
            "# Defaults for `dbev --cli`. The daemon does not read this file.\n{}",
            yaml_serde::to_string(self)?
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_roundtrip_next_to_the_config_and_tolerate_absence() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.yml");
        assert_eq!(ConsoleSettings::load(&config), ConsoleSettings::default());
        let settings = ConsoleSettings {
            public_host: "db.example.com".to_string(),
        };
        std::fs::write(ConsoleSettings::path(&config), settings.to_yaml().unwrap()).unwrap();
        assert_eq!(ConsoleSettings::load(&config), settings);
        assert_eq!(
            ConsoleSettings::path(&config),
            directory.path().join("console.yml")
        );
    }
}
