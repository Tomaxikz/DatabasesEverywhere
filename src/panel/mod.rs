pub mod client {
    #[derive(Debug, Clone)]
    pub struct PanelClient {
        pub base_url: String,
    }
}

pub mod heartbeat {
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize)]
    pub struct Heartbeat {
        pub daemon_version: &'static str,
        pub runtime: &'static str,
    }

    impl Default for Heartbeat {
        fn default() -> Self {
            Self {
                daemon_version: env!("CARGO_PKG_VERSION"),
                runtime: "docker",
            }
        }
    }
}
