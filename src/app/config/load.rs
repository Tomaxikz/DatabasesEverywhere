use std::path::Path;

use super::{Config, validate};

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
        source: yaml_serde::Error,
    },
    #[error(transparent)]
    Validate(#[from] validate::ConfigValidationError),
}

pub fn load_config(path: impl AsRef<Path>) -> Result<Config, ConfigLoadError> {
    let config = parse_config_file(path)?;
    validate::validate_config(&config)?;
    Ok(config)
}

pub(crate) fn parse_config_file(path: impl AsRef<Path>) -> Result<Config, ConfigLoadError> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).map_err(|source| ConfigLoadError::Read {
        path: path.display().to_string(),
        source,
    })?;
    yaml_serde::from_str::<Config>(&content).map_err(|source| ConfigLoadError::Parse {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let config = load_config(&path).unwrap();

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
    fn yaml_roundtrip_preserves_strings_and_rejects_duplicate_settings() {
        // These are strings, even when they resemble YAML booleans/numbers.
        for token in ["on", "false", "null", "001", "1e3", "test: # $ @ 'value'"] {
            let config = Config {
                token: token.into(),
                ..Config::default()
            };
            let encoded = yaml_serde::to_string(&config).unwrap();
            let decoded: Config = yaml_serde::from_str(&encoded).unwrap();
            assert_eq!(decoded.token, token);
            assert_eq!(
                serde_json::to_value(&decoded).unwrap(),
                serde_json::to_value(&config).unwrap()
            );
        }
        for document in [
            "token: first\ntoken: second\n",
            "api:\n  port: 8090\n  port: 8091\n",
        ] {
            assert!(yaml_serde::from_str::<Config>(document).is_err());
        }
    }

    #[test]
    fn loads_partial_scheduler_without_replacing_identity_or_tls() {
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

        let config = load_config(&path).unwrap();

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
    fn loads_v06_api_fields_without_reexporting_retired_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
api:
  host: 127.0.0.1
  port: 8090
  fqdn: db.example.com
  trusted_hosts:
    - panel.example.com
  trusted_origins:
    - http://localhost:3000
    - https://PANEL.example.com:443
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

        assert_eq!(config.api.fqdn, "db.example.com");
        assert_eq!(config.api.trusted_hosts, ["panel.example.com"]);
        let serialized = yaml_serde::to_string(&config).unwrap();
        assert!(!serialized.contains("fqdn:"));
        assert!(!serialized.contains("trusted_hosts:"));
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
