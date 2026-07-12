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
        source: serde_yaml::Error,
    },
    #[error(transparent)]
    Validate(#[from] validate::ConfigValidationError),
}

pub fn load_config(path: impl AsRef<Path>) -> Result<Config, ConfigLoadError> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).map_err(|source| ConfigLoadError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let config =
        serde_yaml::from_str::<Config>(&content).map_err(|source| ConfigLoadError::Parse {
            path: path.display().to_string(),
            source,
        })?;
    validate::validate_config(&config)?;
    Ok(config)
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

        let config = load_config(&path).unwrap();

        assert_eq!(config.daemon.engine, crate::config::DaemonEngine::Docker);
        assert_eq!(config.images.postgres, "postgres:18.4");
        assert_eq!(config.images.mongodb, "mongo:7.0.37");
        assert_eq!(config.api.bind_addr(), "127.0.0.1:8090");
        assert_eq!(config.cors_allowed_hosts(), vec!["panel.example.com"]);
    }

    #[test]
    fn rejects_legacy_api_bind_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
api:
  bind: 127.0.0.1:8090
uuid: node-uuid
token_id: token-id
token: secret-token
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#,
        )
        .unwrap();

        let error = load_config(&path).unwrap_err();

        assert!(matches!(error, ConfigLoadError::Parse { .. }));
    }

    #[test]
    fn rejects_unknown_nested_config_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
remote: https://panel.example.com
uuid: node-uuid
token_id: token-id
token: secret-token
daemon:
  intenal_network: true
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#,
        )
        .unwrap();

        let error = load_config(&path).unwrap_err();

        assert!(matches!(error, ConfigLoadError::Parse { .. }));
    }

    #[test]
    fn rejects_removed_manual_disk_mode() {
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

        let error = load_config(&path).unwrap_err();

        assert!(matches!(error, ConfigLoadError::Parse { .. }));
    }

    #[test]
    fn rejects_removed_docker_config_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
remote: https://panel.example.com
uuid: node-uuid
token_id: token-id
token: secret-token
docker:
  network: databases-everywhere
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#,
        )
        .unwrap();

        let error = load_config(&path).unwrap_err();

        assert!(matches!(error, ConfigLoadError::Parse { .. }));
    }

    #[test]
    fn rejects_legacy_api_allowed_hosts_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
api:
  allowed_hosts:
    - panel.example.com
uuid: node-uuid
token_id: token-id
token: secret-token
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#,
        )
        .unwrap();

        let error = load_config(&path).unwrap_err();

        assert!(matches!(error, ConfigLoadError::Parse { .. }));
    }

    #[test]
    fn rejects_removed_api_url_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
api:
  url: https://dbe.example.com
uuid: node-uuid
token_id: token-id
token: secret-token
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#,
        )
        .unwrap();

        let error = load_config(&path).unwrap_err();

        assert!(matches!(error, ConfigLoadError::Parse { .. }));
    }

    #[test]
    fn rejects_removed_api_trusted_origins_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
api:
  trusted_origins:
    - https://panel.example.com
uuid: node-uuid
token_id: token-id
token: secret-token
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#,
        )
        .unwrap();

        let error = load_config(&path).unwrap_err();

        assert!(matches!(error, ConfigLoadError::Parse { .. }));
    }
}
