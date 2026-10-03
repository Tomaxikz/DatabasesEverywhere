use crate::{
    config::{Config, ImageConfig, PidsLimitConfig},
    databases::engine::{EngineConfig, ImageSettings, ListenerSettings},
};

use super::engine::{Redis, Valkey};

impl EngineConfig for Redis {
    fn listener<'a>(&self, config: &'a Config) -> ListenerSettings<'a> {
        ListenerSettings {
            enabled: config.redis.enabled,
            bind: &config.redis.bind,
        }
    }

    fn images<'a>(&self, images: &'a ImageConfig) -> ImageSettings<'a> {
        ImageSettings {
            configured: &images.redis,
            allowed: &images.allowed.redis,
        }
    }

    fn pids_limit(&self, limits: &PidsLimitConfig) -> Option<i64> {
        limits.redis
    }
}

impl EngineConfig for Valkey {
    fn listener<'a>(&self, config: &'a Config) -> ListenerSettings<'a> {
        ListenerSettings {
            enabled: config.valkey.enabled,
            bind: &config.valkey.bind,
        }
    }

    fn images<'a>(&self, images: &'a ImageConfig) -> ImageSettings<'a> {
        ImageSettings {
            configured: &images.valkey,
            allowed: &images.allowed.valkey,
        }
    }

    fn pids_limit(&self, limits: &PidsLimitConfig) -> Option<i64> {
        limits.valkey
    }
}
