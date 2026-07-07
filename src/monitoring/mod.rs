pub mod messages {
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize)]
    pub struct MonitoringMessage {
        pub r#type: &'static str,
        pub timestamp: String,
        pub instances: Vec<InstanceStats>,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct InstanceStats {
        pub instance_id: String,
        pub protocol: String,
        pub status: String,
        pub runtime: &'static str,
    }
}

pub mod stats {
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize)]
    pub struct DiskStats {
        pub used_bytes: u64,
        pub limit_bytes: u64,
        pub enforced: bool,
        pub enforcement_method: String,
    }
}

pub mod websocket {
    pub const STATUS: &str = "reserved";
}
