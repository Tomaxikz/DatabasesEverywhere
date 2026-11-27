use serde::{Deserialize, Serialize};

/// Protocol names a tether stream may target and a forward may carry. They match the
/// gateway listener names, so a stream names the listener it should end up at.
pub const TETHER_PROTOCOLS: [&str; 9] = [
    "postgres",
    "redis",
    "valkey",
    "mariadb",
    "mysql",
    "mongodb",
    "clickhouse",
    "clickhouse_http",
    "qdrant",
];

/// Links this node to other dbev nodes so a client of one node can reach databases held by
/// another. Off unless `enabled`; nothing else here is read while it is off.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TetherConfig {
    pub enabled: bool,
    /// UDP address the node-to-node endpoint listens on.
    pub bind: String,
    /// This node's id; must equal the single DNS name in its certificate.
    pub node: String,
    /// PEM file with the cluster CA certificate(s).
    pub ca: String,
    /// PEM file with this node's certificate chain.
    pub cert: String,
    /// PEM file with this node's private key.
    pub key: String,
    pub peers: Vec<TetherPeerConfig>,
    pub forwards: Vec<TetherForwardConfig>,
}

impl Default for TetherConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0:7100".to_string(),
            node: String::new(),
            ca: String::new(),
            cert: String::new(),
            key: String::new(),
            peers: Vec::new(),
            forwards: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TetherPeerConfig {
    pub node: String,
    /// `IP:port` of the peer's tether endpoint.
    pub address: String,
    /// Whether this peer may open streams to this node's gateway.
    pub inbound: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TetherForwardConfig {
    /// TCP address on this node that clients connect to.
    pub bind: String,
    /// The configured peer that holds the databases.
    pub node: String,
    /// One of [`TETHER_PROTOCOLS`].
    pub protocol: String,
}
