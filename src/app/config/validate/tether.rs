use std::{collections::HashSet, net::SocketAddr};

use super::ConfigValidationError;
use crate::config::{TETHER_PROTOCOLS, TetherConfig};

fn invalid(field: impl Into<String>, message: impl Into<String>) -> ConfigValidationError {
    ConfigValidationError::InvalidTether {
        field: field.into(),
        message: message.into(),
    }
}

fn node_id(field: String, value: &str) -> Result<::tether::NodeId, ConfigValidationError> {
    value
        .parse::<::tether::NodeId>()
        .map_err(|error| invalid(field, format!("{value:?}: {error}")))
}

fn socket_addr(field: String, value: &str) -> Result<SocketAddr, ConfigValidationError> {
    value
        .parse::<SocketAddr>()
        .map_err(|_| invalid(field, format!("{value:?} must be IP:port")))
}

/// Checked only while tether is enabled; a disabled section may hold anything.
pub(super) fn validate_tether(tether: &TetherConfig) -> Result<(), ConfigValidationError> {
    if !tether.enabled {
        return Ok(());
    }
    let this_node = node_id("node".into(), &tether.node)?;
    for (field, value) in [
        ("ca", &tether.ca),
        ("cert", &tether.cert),
        ("key", &tether.key),
    ] {
        if value.trim().is_empty() {
            return Err(invalid(field, "must not be empty"));
        }
    }
    socket_addr("bind".into(), &tether.bind)?;

    let mut peers = HashSet::new();
    for (index, peer) in tether.peers.iter().enumerate() {
        let id = node_id(format!("peers[{index}].node"), &peer.node)?;
        if id == this_node {
            return Err(invalid(
                format!("peers[{index}].node"),
                "must differ from this node",
            ));
        }
        if !peers.insert(id) {
            return Err(invalid(
                format!("peers[{index}].node"),
                format!("{:?} is listed twice", peer.node),
            ));
        }
        let address = socket_addr(format!("peers[{index}].address"), &peer.address)?;
        // An IPv4-mapped IPv6 address (`::ffff:0.0.0.0`) is the same unspecified address.
        if address.ip().to_canonical().is_unspecified() || address.port() == 0 {
            return Err(invalid(
                format!("peers[{index}].address"),
                format!("{address} must name a reachable IP and a non-zero port"),
            ));
        }
    }

    let mut binds = HashSet::new();
    for (index, forward) in tether.forwards.iter().enumerate() {
        let bind = socket_addr(format!("forwards[{index}].bind"), &forward.bind)?;
        if !binds.insert(bind) {
            return Err(invalid(
                format!("forwards[{index}].bind"),
                format!("{bind} is used by another forward"),
            ));
        }
        let id = node_id(format!("forwards[{index}].node"), &forward.node)?;
        if !peers.contains(&id) {
            return Err(invalid(
                format!("forwards[{index}].node"),
                format!("{:?} is not one of the configured peers", forward.node),
            ));
        }
        if !TETHER_PROTOCOLS.contains(&forward.protocol.as_str()) {
            return Err(invalid(
                format!("forwards[{index}].protocol"),
                format!("{:?} is not a supported protocol", forward.protocol),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, TetherForwardConfig, TetherPeerConfig};

    fn enabled() -> TetherConfig {
        TetherConfig {
            enabled: true,
            node: "node-a".into(),
            ca: "/etc/dbev/ca.pem".into(),
            cert: "/etc/dbev/cert.pem".into(),
            key: "/etc/dbev/key.pem".into(),
            peers: vec![TetherPeerConfig {
                node: "node-b".into(),
                address: "10.0.0.2:7100".into(),
                inbound: false,
            }],
            forwards: vec![TetherForwardConfig {
                bind: "0.0.0.0:15432".into(),
                node: "node-b".into(),
                protocol: "postgres".into(),
            }],
            ..TetherConfig::default()
        }
    }

    #[track_caller]
    fn rejects(change: impl FnOnce(&mut TetherConfig), field: &str) {
        let mut config = enabled();
        change(&mut config);
        match validate_tether(&config) {
            Err(ConfigValidationError::InvalidTether { field: actual, .. }) => {
                assert_eq!(actual, field);
            }
            other => panic!("expected {field} to be rejected, got {other:?}"),
        }
    }

    #[test]
    fn disabled_by_default_and_nothing_is_checked_while_off() {
        let config = Config::default();
        assert!(!config.tether.enabled);
        assert!(config.tether.peers.is_empty() && config.tether.forwards.is_empty());
        assert_eq!(config.tether.bind, "0.0.0.0:7100");

        let mut junk = TetherConfig {
            node: "Not A Node".into(),
            bind: "nope".into(),
            ..TetherConfig::default()
        };
        junk.peers.push(TetherPeerConfig::default());
        assert!(validate_tether(&junk).is_ok());
    }

    #[test]
    fn accepts_a_valid_enabled_config() {
        assert!(validate_tether(&enabled()).is_ok());
        // Local binds may still ask the OS for a port.
        let mut config = enabled();
        config.bind = "127.0.0.1:0".into();
        config.forwards[0].bind = "127.0.0.1:0".into();
        assert!(validate_tether(&config).is_ok());
    }

    #[test]
    fn rejects_each_invalid_setting() {
        rejects(|c| c.node = String::new(), "node");
        rejects(|c| c.node = "Node_A".into(), "node");
        rejects(|c| c.ca = " ".into(), "ca");
        rejects(|c| c.cert = String::new(), "cert");
        rejects(|c| c.key = String::new(), "key");
        rejects(|c| c.bind = "0.0.0.0".into(), "bind");
        rejects(|c| c.peers[0].node = "Bad Node".into(), "peers[0].node");
        rejects(|c| c.peers[0].node = "node-a".into(), "peers[0].node");
        rejects(
            |c| c.peers[0].address = "node-b.example:7100".into(),
            "peers[0].address",
        );
        rejects(
            |c| c.peers[0].address = "0.0.0.0:7100".into(),
            "peers[0].address",
        );
        rejects(
            |c| c.peers[0].address = "[::]:7100".into(),
            "peers[0].address",
        );
        rejects(
            |c| c.peers[0].address = "[::ffff:0.0.0.0]:7100".into(),
            "peers[0].address",
        );
        rejects(
            |c| c.peers[0].address = "10.0.0.2:0".into(),
            "peers[0].address",
        );
        rejects(
            |c| {
                let duplicate = c.peers[0].clone();
                c.peers.push(duplicate);
            },
            "peers[1].node",
        );
        rejects(|c| c.forwards[0].bind = "15432".into(), "forwards[0].bind");
        rejects(
            |c| {
                let duplicate = c.forwards[0].clone();
                c.forwards.push(duplicate);
            },
            "forwards[1].bind",
        );
        rejects(|c| c.forwards[0].node = "node-z".into(), "forwards[0].node");
        rejects(
            |c| c.forwards[0].protocol = "sqlite".into(),
            "forwards[0].protocol",
        );
    }

    #[test]
    fn every_protocol_name_is_accepted() {
        for protocol in TETHER_PROTOCOLS {
            let mut config = enabled();
            config.forwards[0].protocol = protocol.into();
            assert!(validate_tether(&config).is_ok(), "{protocol}");
        }
    }

    #[test]
    fn unknown_keys_under_tether_are_rejected() {
        for yaml in [
            "tether:\n  enabled: true\n  bogus: 1\n",
            "tether:\n  peers:\n    - node: node-b\n      extra: x\n",
            "tether:\n  forwards:\n    - protocol: postgres\n      extra: x\n",
        ] {
            assert!(yaml_serde::from_str::<Config>(yaml).is_err(), "{yaml}");
        }
        let config: Config = yaml_serde::from_str("tether:\n  enabled: true\n  node: node-a\n")
            .expect("known keys parse");
        assert!(config.tether.enabled);
    }
}
