use crate::databases::engine::EngineTenancy;

use super::engine::Qdrant;

impl EngineTenancy for Qdrant {
    fn cleans_stale_import_bridges(&self) -> bool {
        true
    }
}
