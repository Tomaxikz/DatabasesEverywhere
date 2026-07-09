pub mod files;
pub mod ids;
pub mod images;
pub mod limits;
pub mod logs;
pub mod network;
pub mod protocol;
pub mod redaction;
pub mod shell;
pub mod time;

pub mod backend {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum BackendEndpoint {
        UnixSocket { socket_path: String },
        DockerTcp { host: String, port: u16 },
    }
}

pub mod credentials {
    use secrecy::SecretString;

    #[derive(Debug, Clone)]
    pub struct TenantCredentials {
        pub username: String,
        pub password: SecretString,
    }
}

pub mod errors {
    #[derive(Debug, thiserror::Error)]
    pub enum DaemonError {
        #[error("{0}")]
        Message(String),
    }
}

pub mod types {
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize)]
    pub struct StatusMessage {
        pub status: &'static str,
    }
}
