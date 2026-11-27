//! Tether links dbev nodes so one node's gateway can reach a database instance on another.
//!
//! Nodes talk over QUIC connections authenticated in both directions with certificates
//! issued by the cluster's own authority. Each direction dials its own connection (a node
//! never sends streams back over a connection a peer opened to it), so both nodes must be
//! reachable over UDP by the peers that open streams to them. Every proxied database
//! connection is one bidirectional stream: the opener names the target instance and adds an
//! opaque context, the responder answers with a status, and after an `Ok` both sides
//! exchange raw bytes.
//!
//! Nodes upgrade at different times, so every stream starts with a protocol version, and a
//! responder that does not speak it says which version it does.

pub mod endpoint;
pub mod id;
pub mod identity;
pub mod wire;

pub use endpoint::{Authorizer, Config, Incoming, Peer, Stream, Tether};
pub use id::{NodeId, TargetId};
pub use identity::Identity;

/// Highest version of the node-to-node protocol this build speaks and the one it opens
/// streams with. Raise it on any incompatible change.
pub const PROTOCOL_VERSION: u16 = 1;
/// Oldest version this build still answers.
pub const MIN_PROTOCOL_VERSION: u16 = 1;
