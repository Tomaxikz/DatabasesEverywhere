use crate::{
    config::{Config, ImageConfig, PidsLimitConfig},
    databases::engine::{EngineConfig, ImageSettings, ListenerSettings},
};

use super::engine::Mongodb;

impl EngineConfig for Mongodb {
    fn listener<'a>(&self, config: &'a Config) -> ListenerSettings<'a> {
        ListenerSettings {
            enabled: config.mongodb.enabled,
            bind: &config.mongodb.bind,
        }
    }

    fn images<'a>(&self, images: &'a ImageConfig) -> ImageSettings<'a> {
        ImageSettings {
            configured: &images.mongodb,
            allowed: &images.allowed.mongodb,
        }
    }

    fn pids_limit(&self, limits: &PidsLimitConfig) -> Option<i64> {
        limits.mongodb
    }
}
