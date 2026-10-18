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

/// Every engine reads its listener, image and pids settings from the config
/// section named after it.
macro_rules! section_config {
    ($($engine:ty => $section:ident),+ $(,)?) => {$(
        impl EngineConfig for $engine {
            fn listener<'a>(&self, config: &'a Config) -> ListenerSettings<'a> {
                ListenerSettings {
                    enabled: config.$section.enabled,
                    bind: &config.$section.bind,
                }
            }

            fn images<'a>(&self, images: &'a ImageConfig) -> ImageSettings<'a> {
                ImageSettings {
                    configured: &images.$section,
                    allowed: &images.allowed.$section,
                }
            }

            fn pids_limit(&self, limits: &PidsLimitConfig) -> Option<i64> {
                limits.$section
            }
        }
    )+};
}

section_config! {
    crate::databases::postgres::engine::Postgres => postgres,
    crate::databases::mysql::engine::Mysql => mysql,
    crate::databases::mariadb::engine::Mariadb => mariadb,
    crate::databases::mongodb::engine::Mongodb => mongodb,
    crate::databases::clickhouse::engine::Clickhouse => clickhouse,
    crate::databases::resp::engine::Redis => redis,
    crate::databases::resp::engine::Valkey => valkey,
    crate::databases::qdrant::engine::Qdrant => qdrant,
}
