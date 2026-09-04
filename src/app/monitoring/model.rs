use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Read,
    Write,
    Ddl,
    Other,
}

impl OperationKind {
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Ddl => 2,
            Self::Other => 3,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationCounts {
    pub read: u64,
    pub write: u64,
    pub ddl: u64,
    pub other: u64,
}

impl OperationCounts {
    pub const fn total(self) -> u64 {
        self.read
            .saturating_add(self.write)
            .saturating_add(self.ddl)
            .saturating_add(self.other)
    }

    pub(crate) fn from_values(values: [u64; 4]) -> Self {
        Self {
            read: values[OperationKind::Read.index()],
            write: values[OperationKind::Write.index()],
            ddl: values[OperationKind::Ddl.index()],
            other: values[OperationKind::Other.index()],
        }
    }

    pub(crate) fn checked_delta(self, earlier: Self) -> Option<Self> {
        Some(Self {
            read: self.read.checked_sub(earlier.read)?,
            write: self.write.checked_sub(earlier.write)?,
            ddl: self.ddl.checked_sub(earlier.ddl)?,
            other: self.other.checked_sub(earlier.other)?,
        })
    }
}

/// Exact counters measured at the DBEV gateway. Values are cumulative except
/// for `active_connections`, which is a point-in-time gauge.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayActivity {
    pub active_connections: u64,
    pub opened_connections: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityCurrent {
    pub instance_id: String,
    pub stats_epoch: String,
    pub sampled_at_unix: i64,
    pub accepted: OperationCounts,
    /// Internal source state kept beside the matching operation snapshot so
    /// REST and WebSocket responses cannot race the collector publication.
    #[serde(skip)]
    pub(crate) operations_measured: bool,
    pub rejected: OperationCounts,
    pub active_connections: u64,
    pub opened_connections: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Cumulative CPU time observed by an engine-native collector. `None`
    /// means the engine or collector cannot measure it; `Some(0)` is a real
    /// measured zero.
    pub cpu_time_micros: Option<u64>,
    /// Highest observed query memory since this process began tracking the
    /// tenant. It is deliberately not presented as tenant RSS.
    pub peak_query_memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityBucket {
    pub instance_id: String,
    /// Immutable incarnation of `instance_id`. This is kept out of the public
    /// response, but prevents a delayed sampler write from being attached to
    /// a deleted and recreated tenant with the same ID.
    #[serde(skip)]
    pub(crate) instance_generation: String,
    pub bucket_start_unix: i64,
    pub duration_seconds: u32,
    pub stats_epoch: String,
    /// True marks a counter reset or another discontinuity. A gap bucket never
    /// fabricates deltas from incompatible counter epochs.
    pub gap: bool,
    /// Whether the operation counters in this bucket came from a supported
    /// observer. This distinguishes a measured all-zero interval from a metric
    /// that was unavailable for the entire interval.
    pub operations_observed: bool,
    pub accepted: OperationCounts,
    pub rejected: OperationCounts,
    pub active_connections: u64,
    pub opened_connections: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub cpu_time_micros: Option<u64>,
    pub peak_query_memory_bytes: Option<u64>,
}

impl ActivityBucket {
    pub(crate) fn gap(
        instance_id: String,
        instance_generation: String,
        bucket_start_unix: i64,
        duration_seconds: u32,
        stats_epoch: String,
        active_connections: u64,
    ) -> Self {
        Self {
            instance_id,
            instance_generation,
            bucket_start_unix,
            duration_seconds,
            stats_epoch,
            gap: true,
            operations_observed: false,
            accepted: OperationCounts::default(),
            rejected: OperationCounts::default(),
            active_connections,
            opened_connections: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            cpu_time_micros: None,
            peak_query_memory_bytes: None,
        }
    }
}
