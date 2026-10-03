use crate::databases::engine::EngineInspection;

use super::engine::Qdrant;

impl EngineInspection for Qdrant {
    fn schema_less_catalog_kind(&self) -> Option<&'static str> {
        Some("collection_store")
    }
}
