pub mod backend;
pub mod files;
pub mod ids;
pub mod images;
pub mod limits;
pub mod logs;
pub mod protocol;
pub mod redaction;
pub mod shell;
pub mod time;

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
