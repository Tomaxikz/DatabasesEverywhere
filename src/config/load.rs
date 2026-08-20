use std::path::Path;

use super::{Config, validate};

const IMPORT_EXPORT_SCHEDULER_FIELDS: [&str; 10] = [
    "dynamic_limiter_enabled",
    "max_queued_jobs",
    "max_queued_jobs_per_instance",
    "manual_max_active_jobs",
    "dynamic_max_active_jobs",
    "dynamic_memory_budget_mib",
    "dynamic_io_budget_mib",
    "dynamic_cpu_units",
    "starvation_timeout_seconds",
    "max_bypass",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigLoadReport {
    pub defaulted_import_export_scheduler_fields: Vec<&'static str>,
}

impl ConfigLoadReport {
    pub fn used_import_export_scheduler_defaults(&self) -> bool {
        !self.defaulted_import_export_scheduler_fields.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse yaml config {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error(transparent)]
    Validate(#[from] validate::ConfigValidationError),
}

pub fn load_config(path: impl AsRef<Path>) -> Result<Config, ConfigLoadError> {
    let config = parse_config_file(path)?;
    validate::validate_config(&config)?;
    Ok(config)
}

pub fn load_config_with_report(
    path: impl AsRef<Path>,
) -> Result<(Config, ConfigLoadReport), ConfigLoadError> {
    let path = path.as_ref();
    let content = read_config_file(path)?;
    let config = parse_config_content(path, &content)?;
    validate::validate_config(&config)?;
    let document = serde_yaml::from_str::<serde_yaml::Value>(&content).map_err(|source| {
        ConfigLoadError::Parse {
            path: path.display().to_string(),
            source,
        }
    })?;
    Ok((config, config_load_report(&document)))
}

pub(crate) fn parse_config_file(path: impl AsRef<Path>) -> Result<Config, ConfigLoadError> {
    let path = path.as_ref();
    let content = read_config_file(path)?;
    parse_config_content(path, &content)
}

fn read_config_file(path: &Path) -> Result<String, ConfigLoadError> {
    std::fs::read_to_string(path).map_err(|source| ConfigLoadError::Read {
        path: path.display().to_string(),
        source,
    })
}

fn parse_config_content(path: &Path, content: &str) -> Result<Config, ConfigLoadError> {
    serde_yaml::from_str::<Config>(content).map_err(|source| ConfigLoadError::Parse {
        path: path.display().to_string(),
        source,
    })
}

fn config_load_report(document: &serde_yaml::Value) -> ConfigLoadReport {
    let scheduler = document
        .as_mapping()
        .and_then(|root| root.get("artifacts"))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|artifacts| artifacts.get("import_export_scheduler"))
        .and_then(serde_yaml::Value::as_mapping);
    let defaulted_import_export_scheduler_fields = IMPORT_EXPORT_SCHEDULER_FIELDS
        .into_iter()
        .filter(|field| scheduler.is_none_or(|scheduler| !scheduler.contains_key(*field)))
        .collect();
    ConfigLoadReport {
        defaulted_import_export_scheduler_fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_serialized_config_needs_no_scheduler_defaults() {
        let document = serde_yaml::to_value(Config::default()).unwrap();
        assert_eq!(config_load_report(&document), ConfigLoadReport::default());
    }

    #[test]
    fn loads_minimal_config_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
remote: https://panel.example.com
uuid: node-uuid
token_id: token-id
token: test-api-token-0123456789abcdef-01
jwt_signing_key: test-jwt-signing-key-0123456789abcdef-02
api:
  host: 127.0.0.1
  port: 8090
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#,
        )
        .unwrap();

        let original = std::fs::read_to_string(&path).unwrap();
        let (config, report) = load_config_with_report(&path).unwrap();

        assert_eq!(config.daemon.engine, crate::config::DaemonEngine::Docker);
        assert_eq!(config.images.postgres, "postgres:18.4");
        assert_eq!(config.images.mongodb, "mongo:7.0.37");
        assert_eq!(config.api.bind_addr(), "127.0.0.1:8090");
        assert!(config.api.fqdn.is_empty());
        assert!(config.api.trusted_origins.is_empty());
        assert_eq!(
            config.cors_allowed_origins(),
            vec!["https://panel.example.com:443"]
        );
        assert!(report.used_import_export_scheduler_defaults());
        assert_eq!(
            report.defaulted_import_export_scheduler_fields.len(),
            IMPORT_EXPORT_SCHEDULER_FIELDS.len()
        );
        assert_eq!(
            config
                .artifacts
                .import_export_scheduler
                .dynamic_memory_budget_mib,
            0
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn defaults_only_missing_scheduler_fields_without_replacing_identity_or_tls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        let original = r#"
remote: https://panel.example.com
uuid: preserved-node-uuid
token_id: preserved-token-id
token: preserved-api-token-0123456789abcdef
jwt_signing_key: preserved-jwt-signing-key-0123456789abcdef
tls:
  cert: /preserved/gateway-cert.pem
  key: /preserved/gateway-key.pem
api:
  host: 127.0.0.1
  port: 8090
  ssl:
    enabled: false
    cert: /preserved/api-cert.pem
    key: /preserved/api-key.pem
artifacts:
  import_export_scheduler:
    dynamic_max_active_jobs: 64
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#;
        std::fs::write(&path, original).unwrap();

        let (config, report) = load_config_with_report(&path).unwrap();

        assert_eq!(config.uuid, "preserved-node-uuid");
        assert_eq!(config.token_id, "preserved-token-id");
        assert_eq!(config.token, "preserved-api-token-0123456789abcdef");
        assert_eq!(config.remote, "https://panel.example.com");
        assert_eq!(config.tls.cert, "/preserved/gateway-cert.pem");
        assert_eq!(config.tls.key, "/preserved/gateway-key.pem");
        assert_eq!(config.api.ssl.cert, "/preserved/api-cert.pem");
        assert_eq!(config.api.ssl.key, "/preserved/api-key.pem");
        assert_eq!(
            config
                .artifacts
                .import_export_scheduler
                .dynamic_max_active_jobs,
            64
        );
        assert_eq!(
            config
                .artifacts
                .import_export_scheduler
                .dynamic_memory_budget_mib,
            0
        );
        assert!(
            !report
                .defaulted_import_export_scheduler_fields
                .contains(&"dynamic_max_active_jobs")
        );
        assert!(
            report
                .defaulted_import_export_scheduler_fields
                .contains(&"dynamic_memory_budget_mib")
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn rejects_legacy_removed_and_unknown_config_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yml");
        for (name, extra) in [
            ("legacy API bind", "api:\n  bind: 127.0.0.1:8090"),
            ("unknown nested field", "daemon:\n  intenal_network: true"),
            (
                "removed Docker section",
                "docker:\n  network: databases-everywhere",
            ),
            (
                "removed allowed hosts",
                "api:\n  allowed_hosts:\n    - panel.example.com",
            ),
            (
                "removed trusted hosts",
                "api:\n  trusted_hosts:\n    - panel.example.com",
            ),
            ("removed API URL", "api:\n  url: https://dbe.example.com"),
        ] {
            std::fs::write(&path, config_document(extra)).unwrap();
            assert!(
                matches!(load_config(&path), Err(ConfigLoadError::Parse { .. })),
                "accepted config case: {name}"
            );
        }
    }

    #[test]
    fn accepts_explicit_disk_fallback_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
remote: https://panel.example.com
uuid: node-uuid
token_id: token-id
token: test-api-token-0123456789abcdef-01
jwt_signing_key: test-jwt-signing-key-0123456789abcdef-02
api:
  host: 127.0.0.1
disk:
  mode: fuse_quota
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#,
        )
        .unwrap();

        let config = load_config(&path).unwrap();

        assert_eq!(
            config.disk.selection,
            crate::config::DiskLimitSelection::FuseQuota
        );
    }

    #[test]
    fn loads_explicit_api_trusted_origins_without_breaking_legacy_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
api:
  host: 127.0.0.1
  port: 8090
  fqdn: db.example.com
  trusted_origins:
    - http://localhost:3000
remote: https://panel.example.com
uuid: node-uuid
token_id: token-id
token: test-api-token-0123456789abcdef-01
jwt_signing_key: test-jwt-signing-key-0123456789abcdef-02
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#,
        )
        .unwrap();

        let config = load_config(&path).unwrap();

        assert_eq!(config.api.fqdn(), Some("db.example.com"));
        assert_eq!(
            config.cors_allowed_origins(),
            vec!["https://panel.example.com:443", "http://localhost:3000"]
        );
    }

    fn config_document(extra: &str) -> String {
        format!(
            r#"
{extra}
remote: https://panel.example.com
uuid: node-uuid
token_id: token-id
token: secret-token
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#
        )
    }
}
