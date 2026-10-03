use crate::{
    config::{Config, ImageConfig, PidsLimitConfig},
    databases::engine::{EngineConfig, ImageSettings, ListenerSettings},
};

use super::engine::Mysql;

impl EngineConfig for Mysql {
    fn listener<'a>(&self, config: &'a Config) -> ListenerSettings<'a> {
        ListenerSettings {
            enabled: config.mysql.enabled,
            bind: &config.mysql.bind,
        }
    }

    fn images<'a>(&self, images: &'a ImageConfig) -> ImageSettings<'a> {
        ImageSettings {
            configured: &images.mysql,
            allowed: &images.allowed.mysql,
        }
    }

    fn pids_limit(&self, limits: &PidsLimitConfig) -> Option<i64> {
        limits.mysql
    }
}
