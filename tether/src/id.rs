//! Validated names for nodes and for the database instances streams are opened to.

use std::{fmt, str::FromStr};

/// Longest accepted [`NodeId`], the limit of one DNS label.
pub const MAX_NODE_ID_LEN: usize = 63;
/// Longest accepted [`TargetId`]. It must fit the one-byte length in the stream header.
pub const MAX_TARGET_ID_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdError {
    #[error("identifier is empty")]
    Empty,
    #[error("identifier is too long")]
    TooLong,
    #[error("identifier contains a character that is not allowed")]
    InvalidCharacter,
    #[error("identifier cannot be used as a certificate DNS name")]
    NotDnsName,
}

/// Name of a dbev node. It is a single lowercase DNS label (`a-z`, `0-9`, `-`, not starting
/// or ending with `-`, at most [`MAX_NODE_ID_LEN`] bytes) that a certificate can carry as a
/// DNS name, because it is also the DNS name in the node's certificate and the server name a
/// dialer asks for. Labels such as `0` or `0xabc` look like numbers and are refused.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(String);

/// Name of the database instance a stream is opened to: 1 to [`MAX_TARGET_ID_LEN`] bytes of
/// `A-Z`, `a-z`, `0-9`, `_`, `-` and `.`. Tether does not interpret it further.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TargetId(String);

impl NodeId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TargetId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for NodeId {
    type Err = IdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(IdError::Empty);
        }
        if value.len() > MAX_NODE_ID_LEN {
            return Err(IdError::TooLong);
        }
        if value.starts_with('-')
            || value.ends_with('-')
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(IdError::InvalidCharacter);
        }
        // The character rules above are not enough: the DNS name validator also refuses
        // labels that look like numbers, and such a node could never get a usable certificate.
        if rustls_pki_types::DnsName::try_from(value).is_err() {
            return Err(IdError::NotDnsName);
        }
        Ok(Self(value.to_owned()))
    }
}

impl FromStr for TargetId {
    type Err = IdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(IdError::Empty);
        }
        if value.len() > MAX_TARGET_ID_LEN {
            return Err(IdError::TooLong);
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(IdError::InvalidCharacter);
        }
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for TargetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.0)
    }
}

impl fmt::Debug for TargetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TargetId({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries() {
        assert_eq!("".parse::<NodeId>(), Err(IdError::Empty));
        assert_eq!("".parse::<TargetId>(), Err(IdError::Empty));
        assert!("a".repeat(MAX_NODE_ID_LEN).parse::<NodeId>().is_ok());
        assert!("a".repeat(MAX_TARGET_ID_LEN).parse::<TargetId>().is_ok());
        assert_eq!(
            "a".repeat(MAX_NODE_ID_LEN + 1).parse::<NodeId>(),
            Err(IdError::TooLong)
        );
        assert_eq!(
            "a".repeat(MAX_TARGET_ID_LEN + 1).parse::<TargetId>(),
            Err(IdError::TooLong)
        );
    }

    #[test]
    fn node_labels() {
        for value in ["a", "node-42", "0a", "a0"] {
            assert_eq!(value.parse::<NodeId>().expect("valid node").as_str(), value);
        }
        for value in ["-a", "a-", "A", "a_b", "a.b", "a b", "a/b", "é"] {
            assert_eq!(
                value.parse::<NodeId>(),
                Err(IdError::InvalidCharacter),
                "{value}"
            );
        }
    }

    #[test]
    fn labels_a_certificate_cannot_carry_are_refused() {
        for value in ["0", "123", "0xabc"] {
            assert_eq!(value.parse::<NodeId>(), Err(IdError::NotDnsName), "{value}");
        }
    }

    #[test]
    fn target_characters() {
        for value in ["inst_abc.1-2", "A", "-._"] {
            assert_eq!(
                value.parse::<TargetId>().expect("valid target").as_str(),
                value
            );
        }
        for value in ["a b", "a/b", "é", "a\n"] {
            assert_eq!(
                value.parse::<TargetId>(),
                Err(IdError::InvalidCharacter),
                "{value}"
            );
        }
    }
}
