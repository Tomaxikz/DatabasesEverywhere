use crate::{
    config::{Config, ImageConfig, PidsLimitConfig},
    databases::engine::{EngineConfig, ImageSettings, ListenerSettings},
};

use super::engine::Mariadb;

impl EngineConfig for Mariadb {
    fn listener<'a>(&self, config: &'a Config) -> ListenerSettings<'a> {
        ListenerSettings {
            enabled: config.mariadb.enabled,
            bind: &config.mariadb.bind,
        }
    }

    fn images<'a>(&self, images: &'a ImageConfig) -> ImageSettings<'a> {
        ImageSettings {
            configured: &images.mariadb,
            allowed: &images.allowed.mariadb,
        }
    }

    fn pids_limit(&self, limits: &PidsLimitConfig) -> Option<i64> {
        limits.mariadb
    }
}
