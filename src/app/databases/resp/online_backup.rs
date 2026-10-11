//! Online backup capability of Redis and Valkey.
//!
//! Copying the live data and AOF directories after `BGREWRITEAOF` does not
//! establish a recoverable append-only state: file identity checks miss
//! same-inode truncation (Redis `ftruncate`s short AOF writes) and
//! configuration changes, and padding a shrinking file with zeroes fabricates
//! content. A certified strategy must instead capture a completed, immutable
//! RDB with native integrity checking and restore it in isolation (AOF off,
//! load RDB, regenerate AOF, validate, then normal AOF startup). Until that
//! recipe passes the fork/OOM and failed-save availability gates, strict
//! online capture is rejected rather than downgraded.

pub(crate) const RESP_ONLINE_BACKUP_UNSUPPORTED: &str = "Redis and Valkey online capture requires a certified RDB capture and AOF-regenerating restore recipe, which is not available yet";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::{engine::OnlineBackup, protocol::Protocol};

    #[test]
    fn resp_engines_never_declare_an_online_copy() {
        for protocol in [Protocol::Redis, Protocol::Valkey] {
            assert_eq!(
                protocol.engine().online_backup(),
                OnlineBackup::Unavailable {
                    reason: RESP_ONLINE_BACKUP_UNSUPPORTED
                }
            );
        }
    }
}
