use crate::config::{Config, ImageConfig, PidsLimitConfig};

use super::EngineInfo;

pub(crate) struct ListenerSettings<'a> {
    pub enabled: bool,
    pub bind: &'a str,
}

pub(crate) struct ImageSettings<'a> {
    pub configured: &'a str,
    pub allowed: &'a [String],
}

pub(crate) trait EngineConfig: EngineInfo {
    fn listener<'a>(&self, config: &'a Config) -> ListenerSettings<'a>;

    fn images<'a>(&self, images: &'a ImageConfig) -> ImageSettings<'a>;

    fn pids_limit(&self, limits: &PidsLimitConfig) -> Option<i64>;
}
