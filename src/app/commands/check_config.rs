use std::path::PathBuf;

use serde::Serialize;

use crate::{
    commands::CliCommand,
    config::{Config, load::load_config},
    daemon::runtime_paths::{log_disk_mode, validate_runtime_support},
    utils::term,
};

pub(crate) struct CheckConfigCommand {
    pub(crate) json: bool,
}

#[derive(Serialize)]
struct Summary {
    ok: bool,
    config: PathBuf,
    node: String,
    api: Option<String>,
    api_socket: String,
    disk_mode: &'static str,
    metadata_root: String,
    volumes_root: String,
    logs_root: String,
    engines: Vec<Engine>,
}

#[derive(Serialize)]
struct Engine {
    name: &'static str,
    enabled: bool,
    bind: String,
    tls: bool,
}

impl CliCommand for CheckConfigCommand {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        let mut config = load_config(&config_path)?;
        log_disk_mode(&mut config)?;
        validate_runtime_support(&config).await?;
        let summary = Summary::new(config_path, &config);
        if self.json {
            return term::json(&summary);
        }
        summary.print();
        Ok(())
    }
}

impl Summary {
    fn new(config_path: PathBuf, config: &Config) -> Self {
        let listener = |name, listener: &crate::config::ListenerConfig| Engine {
            name,
            enabled: listener.enabled,
            bind: listener.bind.clone(),
            tls: listener.tls,
        };
        Self {
            ok: true,
            config: config_path,
            node: config.uuid.clone(),
            api: config
                .api
                .enabled
                .then(|| format!("{}:{}", config.api.host, config.api.port)),
            api_socket: config.api_socket_path(),
            disk_mode: config.disk.mode.method(),
            metadata_root: config.paths.metadata_root(),
            volumes_root: config.paths.volumes_root(),
            logs_root: config.paths.logs_root(),
            engines: vec![
                listener("postgres", &config.postgres),
                listener("mariadb", &config.mariadb),
                listener("mysql", &config.mysql),
                listener("redis", &config.redis),
                listener("valkey", &config.valkey),
                listener("mongodb", &config.mongodb),
                Engine {
                    name: "clickhouse",
                    enabled: config.clickhouse.enabled,
                    bind: format!(
                        "{} (http {})",
                        config.clickhouse.bind, config.clickhouse.http_bind
                    ),
                    tls: config.clickhouse.tls,
                },
                listener("qdrant", &config.qdrant),
            ],
        }
    }

    fn print(&self) {
        term::success(format_args!("config ok: {}", self.config.display()));
        if term::quiet() {
            return;
        }
        let api = self.api.clone().unwrap_or_else(|| "disabled".to_string());
        anstream::print!(
            "\n{}",
            term::fields(&[
                ("node", self.node.clone()),
                ("api", api),
                ("api socket", self.api_socket.clone()),
                ("disk mode", self.disk_mode.to_string()),
                ("metadata", self.metadata_root.clone()),
                ("volumes", self.volumes_root.clone()),
                ("logs", self.logs_root.clone()),
            ])
        );
        let rows: Vec<Vec<String>> = self
            .engines
            .iter()
            .map(|engine| {
                vec![
                    engine.name.to_string(),
                    if engine.enabled { "on" } else { "off" }.to_string(),
                    if engine.tls { "yes" } else { "no" }.to_string(),
                    engine.bind.clone(),
                ]
            })
            .collect();
        anstream::print!(
            "\n{}",
            term::table(&["ENGINE", "ENABLED", "TLS", "BIND"], &rows)
        );
    }
}
