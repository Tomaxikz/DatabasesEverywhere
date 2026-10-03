use crate::{
    config::{Config, ImageConfig, PidsLimitConfig},
    databases::engine::{EngineConfig, ImageSettings, ListenerSettings},
};

use super::engine::Qdrant;

impl EngineConfig for Qdrant {
    fn listener<'a>(&self, config: &'a Config) -> ListenerSettings<'a> {
        ListenerSettings {
            enabled: config.qdrant.enabled,
            bind: &config.qdrant.bind,
        }
    }

    fn images<'a>(&self, images: &'a ImageConfig) -> ImageSettings<'a> {
        ImageSettings {
            configured: &images.qdrant,
            allowed: &images.allowed.qdrant,
        }
    }

    fn pids_limit(&self, limits: &PidsLimitConfig) -> Option<i64> {
        limits.qdrant
    }
}
