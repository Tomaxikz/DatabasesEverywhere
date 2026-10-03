use crate::databases::engine::EngineInspection;

use super::engine::{Redis, Valkey};

impl EngineInspection for Redis {
    fn schema_less_catalog_kind(&self) -> Option<&'static str> {
        Some("keyspace")
    }
}

impl EngineInspection for Valkey {
    fn schema_less_catalog_kind(&self) -> Option<&'static str> {
        Some("keyspace")
    }
}
