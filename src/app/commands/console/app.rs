//! Console state and key handling, independent of the terminal.
//!
//! Keys produce [`Job`]s, which the runner executes against the API in the
//! background; their [`Outcome`]s come back through [`App::on_outcome`]. Nothing
//! here blocks, so the screen stays responsive during long operations.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use secrecy::{ExposeSecret, SecretString};

use super::{
    api::{Backup, BackupMode, CreateRequest, Instance, PowerAction, StatusResponse, SystemInfo},
    form::CreateForm,
};
use crate::databases::protocol::Protocol;

const MESSAGE_TTL: Duration = Duration::from_secs(8);
/// Revealed passwords disappear from the screen on their own.
pub(super) const REVEAL_TTL: Duration = Duration::from_secs(60);
const PAGE: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Screen {
    Instances,
    Logs,
    Backups,
}

/// Text input inside a confirmation dialog.
#[derive(Debug, Clone, Default)]
pub(super) struct Input {
    pub value: String,
}

impl Input {
    fn on_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Backspace => {
                self.value.pop();
            }
            KeyCode::Char(character)
                if !key.modifiers.contains(KeyModifiers::CONTROL) && !character.is_control() =>
            {
                self.value.push(character);
            }
            _ => {}
        }
    }
}

pub(super) struct Revealed {
    pub instance_id: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: SecretString,
    pub admin: Option<(&'static str, SecretString)>,
    pub shown_at: Instant,
}

pub(super) enum Modal {
    Create(Box<CreateForm>),
    ConfirmDelete {
        instance_id: String,
        typed: Input,
        reason: Input,
        on_reason: bool,
    },
    ConfirmPower {
        instance_id: String,
        action: PowerAction,
    },
    ChooseBackupMode {
        instance_id: String,
        online: bool,
    },
    ConfirmRestore {
        instance_id: String,
        backup_id: String,
        reason: Input,
    },
    Reveal(Box<Revealed>),
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Level {
    Info,
    Success,
    Error,
}

pub(super) struct Message {
    pub level: Level,
    pub text: String,
    at: Instant,
}

/// Work for the runner. Every variant is one API call (or the local reveal).
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Job {
    Refresh,
    Progress(String),
    Create(Box<CreateRequest>),
    Power(String, PowerAction),
    Delete {
        instance_id: String,
        reason: String,
    },
    Logs(String),
    Backups(String),
    Backup(String, BackupMode),
    Restore {
        instance_id: String,
        backup_id: String,
        reason: String,
    },
    Reveal(String),
}

impl Job {
    /// Short description shown while the job runs.
    pub(super) fn label(&self) -> Option<String> {
        Some(match self {
            Self::Refresh | Self::Progress(_) | Self::Logs(_) | Self::Backups(_) => return None,
            Self::Create(request) => format!("creating {}", request.instance_id),
            Self::Power(id, action) => format!("{} {id}", action.as_str()),
            Self::Delete { instance_id, .. } => format!("deleting {instance_id}"),
            Self::Backup(id, mode) => format!("{} backup of {id}", mode.as_str()),
            Self::Restore { instance_id, .. } => format!("restoring {instance_id}"),
            Self::Reveal(_) => return None,
        })
    }
}

pub(super) enum Outcome {
    System(SystemInfo),
    Instances(Vec<Instance>),
    Progress(String, StatusResponse),
    /// The status of an instance being watched no longer exists.
    ProgressGone(String),
    Logs(String, String),
    Backups(String, Vec<Backup>),
    Revealed(Box<Revealed>),
    Done {
        label: String,
        refresh: bool,
    },
    Failed {
        label: String,
        error: String,
    },
    /// A background refresh failed; shown without interrupting.
    RefreshFailed(String),
}

pub(super) struct App {
    pub system: Option<SystemInfo>,
    pub api_url: String,
    /// Public host chosen at first run; suggested for new instances.
    pub public_host: String,
    pub instances: Vec<Instance>,
    pub loaded: bool,
    pub selected: usize,
    pub filter: String,
    pub filtering: bool,
    pub screen: Screen,
    pub modal: Option<Modal>,
    pub logs: Option<(String, Vec<String>)>,
    pub log_scroll: usize,
    pub backups: Option<(String, Vec<Backup>)>,
    pub backup_selected: usize,
    pub progress: BTreeMap<String, StatusResponse>,
    /// Instances seen creating (or asked for here). A failed creation is
    /// cleaned up and drops out of the list; its final status says why.
    pub creating: BTreeSet<String>,
    /// On a standalone node, the port each gateway listens on now.
    pub gateway_ports: Vec<(Protocol, u16)>,
    /// Labels of operations still running.
    pub running: Vec<String>,
    pub message: Option<Message>,
    pub refresh_error: Option<String>,
    pub refreshing: bool,
    pub ticks: u64,
    pub quit: bool,
}

impl App {
    pub(super) fn new(api_url: String) -> Self {
        Self {
            system: None,
            api_url,
            public_host: String::new(),
            instances: Vec::new(),
            loaded: false,
            selected: 0,
            filter: String::new(),
            filtering: false,
            screen: Screen::Instances,
            modal: None,
            logs: None,
            log_scroll: 0,
            backups: None,
            backup_selected: 0,
            progress: BTreeMap::new(),
            creating: BTreeSet::new(),
            gateway_ports: Vec::new(),
            running: Vec::new(),
            message: None,
            refresh_error: None,
            refreshing: false,
            ticks: 0,
            quit: false,
        }
    }

    /// Instances matching the filter, in display order.
    pub(super) fn visible(&self) -> Vec<&Instance> {
        let filter = self.filter.to_ascii_lowercase();
        self.instances
            .iter()
            .filter(|instance| {
                filter.is_empty()
                    || [
                        instance.instance_id.as_str(),
                        instance.protocol.as_str(),
                        instance.status.as_str(),
                        instance.deployment_mode.as_str(),
                        instance.database.name.as_str(),
                    ]
                    .iter()
                    .any(|field| field.to_ascii_lowercase().contains(&filter))
            })
            .collect()
    }

    pub(super) fn current(&self) -> Option<&Instance> {
        self.visible().get(self.selected).copied()
    }

    fn current_id(&self) -> Option<String> {
        self.current().map(|instance| instance.instance_id.clone())
    }

    pub(super) fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
        if self
            .message
            .as_ref()
            .is_some_and(|message| message.at.elapsed() > MESSAGE_TTL)
        {
            self.message = None;
        }
        if let Some(Modal::Reveal(revealed)) = &self.modal
            && revealed.shown_at.elapsed() > REVEAL_TTL
        {
            self.modal = None;
        }
    }

    fn say(&mut self, level: Level, text: impl Into<String>) {
        self.message = Some(Message {
            level,
            text: text.into(),
            at: Instant::now(),
        });
    }

    /// The port clients use for an instance. Instances keep the gateway
    /// port they were created with; on a standalone node the gateway's
    /// current port is the one that works after it moves.
    pub(super) fn connect_port(&self, protocol: Protocol, stored: u16) -> u16 {
        self.gateway_ports
            .iter()
            .find(|(candidate, _)| *candidate == protocol)
            .map_or(stored, |(_, port)| *port)
    }

    /// Reports how a creation that left the list ended.
    fn finish_creation(&mut self, id: &str, status: &StatusResponse) {
        let progress = status.progress.as_ref();
        let state = progress.map_or(status.status.as_str(), |progress| progress.status.as_str());
        match state {
            "failed" => {
                self.creating.remove(id);
                let reason = progress
                    .and_then(|progress| progress.diagnostic.as_ref())
                    .map(|diagnostic| match &diagnostic.error_id {
                        Some(error_id) => format!("{} (error id {error_id})", diagnostic.message),
                        None => diagnostic.message.clone(),
                    })
                    .or_else(|| progress.map(|progress| progress.message.clone()))
                    .filter(|reason| !reason.is_empty())
                    .unwrap_or_else(|| "no reason was reported".to_string());
                self.say(
                    Level::Error,
                    format!(
                        "creating {id} failed: {reason}; see journalctl -u databases-everywhere"
                    ),
                );
            }
            "completed" | "running" if status.status != "creating" => {
                self.creating.remove(id);
            }
            _ => {}
        }
    }

    /// Jobs for a periodic refresh: the list, plus progress of creations.
    pub(super) fn refresh_jobs(&mut self) -> Vec<Job> {
        if self.refreshing {
            return Vec::new();
        }
        self.refreshing = true;
        let mut jobs = vec![Job::Refresh];
        jobs.extend(
            self.instances
                .iter()
                .filter(|instance| matches!(instance.status.as_str(), "creating" | "booting"))
                .map(|instance| Job::Progress(instance.instance_id.clone())),
        );
        // Creations that left the list: fetch their final status.
        jobs.extend(
            self.creating
                .iter()
                .filter(|id| {
                    !self
                        .instances
                        .iter()
                        .any(|instance| &instance.instance_id == *id)
                })
                .map(|id| Job::Progress(id.clone())),
        );
        jobs
    }

    pub(super) fn started(&mut self, job: &Job) {
        if let Some(label) = job.label() {
            self.say(Level::Info, format!("{label}…"));
            self.running.push(label);
        }
    }

    pub(super) fn on_outcome(&mut self, outcome: Outcome) -> Vec<Job> {
        match outcome {
            Outcome::System(system) => self.system = Some(system),
            Outcome::Instances(mut instances) => {
                instances.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
                let keep = self.current_id();
                for instance in &instances {
                    if matches!(instance.status.as_str(), "creating" | "booting") {
                        self.creating.insert(instance.instance_id.clone());
                    } else {
                        self.creating.remove(&instance.instance_id);
                    }
                }
                self.instances = instances;
                self.loaded = true;
                self.refreshing = false;
                self.refresh_error = None;
                self.progress.retain(|id, _| {
                    self.instances
                        .iter()
                        .any(|instance| &instance.instance_id == id)
                });
                if let Some(id) = keep
                    && let Some(index) = self
                        .visible()
                        .iter()
                        .position(|instance| instance.instance_id == id)
                {
                    self.selected = index;
                }
                self.clamp_selection();
            }
            Outcome::Progress(id, status) => {
                let listed = self
                    .instances
                    .iter()
                    .any(|instance| instance.instance_id == id);
                if !listed && self.creating.contains(&id) {
                    self.finish_creation(&id, &status);
                } else {
                    self.progress.insert(id, status);
                }
            }
            Outcome::ProgressGone(id) => {
                if self.creating.remove(&id) {
                    self.say(
                        Level::Error,
                        format!(
                            "creating {id} failed and it was removed; see journalctl -u databases-everywhere"
                        ),
                    );
                }
            }
            Outcome::Logs(id, text) => {
                let lines: Vec<String> = text.lines().map(str::to_string).collect();
                self.log_scroll = lines.len().saturating_sub(1);
                self.logs = Some((id, lines));
            }
            Outcome::Backups(id, mut backups) => {
                backups.sort_by(|left, right| right.modified_at.cmp(&left.modified_at));
                self.backup_selected = self.backup_selected.min(backups.len().saturating_sub(1));
                self.backups = Some((id, backups));
            }
            Outcome::Revealed(revealed) => self.modal = Some(Modal::Reveal(revealed)),
            Outcome::Done { label, refresh } => {
                self.running.retain(|running| running != &label);
                self.say(Level::Success, format!("{label}: done"));
                let mut jobs = Vec::new();
                if refresh {
                    jobs.extend(self.refresh_jobs());
                }
                if self.screen == Screen::Backups
                    && let Some((id, _)) = &self.backups
                {
                    jobs.push(Job::Backups(id.clone()));
                }
                return jobs;
            }
            Outcome::Failed { label, error } => {
                self.running.retain(|running| running != &label);
                self.say(Level::Error, format!("{label}: {error}"));
            }
            Outcome::RefreshFailed(error) => {
                self.refreshing = false;
                self.refresh_error = Some(error);
            }
        }
        Vec::new()
    }

    fn clamp_selection(&mut self) {
        self.selected = self.selected.min(self.visible().len().saturating_sub(1));
    }

    pub(super) fn on_key(&mut self, key: KeyEvent) -> Vec<Job> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return Vec::new();
        }
        if self.modal.is_some() {
            return self.on_modal_key(key);
        }
        if self.filtering {
            match key.code {
                KeyCode::Esc => {
                    self.filtering = false;
                    self.filter.clear();
                }
                KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(character) => self.filter.push(character),
                _ => {}
            }
            self.clamp_selection();
            return Vec::new();
        }
        match self.screen {
            Screen::Instances => self.on_instances_key(key),
            Screen::Logs => self.on_logs_key(key),
            Screen::Backups => self.on_backups_key(key),
        }
    }

    fn on_instances_key(&mut self, key: KeyEvent) -> Vec<Job> {
        let count = self.visible().len();
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1).min(count.saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::PageDown => {
                self.selected = (self.selected + PAGE).min(count.saturating_sub(1))
            }
            KeyCode::PageUp => self.selected = self.selected.saturating_sub(PAGE),
            KeyCode::Home | KeyCode::Char('g') => self.selected = 0,
            KeyCode::End | KeyCode::Char('G') => self.selected = count.saturating_sub(1),
            KeyCode::Char('/') => self.filtering = true,
            KeyCode::Char('R') => return self.refresh_jobs(),
            KeyCode::Char('n') => {
                let (protocols, host) = self
                    .system
                    .as_ref()
                    .map(|system| (system.enabled_protocols(), default_public_host(system)))
                    .unwrap_or_default();
                let host = if self.public_host.is_empty() {
                    host
                } else {
                    self.public_host.clone()
                };
                self.modal = Some(Modal::Create(Box::new(CreateForm::new(protocols, &host))));
            }
            _ => return self.on_instance_action(key),
        }
        Vec::new()
    }

    fn on_instance_action(&mut self, key: KeyEvent) -> Vec<Job> {
        let Some(id) = self.current_id() else {
            return Vec::new();
        };
        match key.code {
            KeyCode::Char('s') => return vec![Job::Power(id, PowerAction::Start)],
            KeyCode::Char('x') => {
                self.modal = Some(Modal::ConfirmPower {
                    instance_id: id,
                    action: PowerAction::Stop,
                });
            }
            KeyCode::Char('r') => {
                self.modal = Some(Modal::ConfirmPower {
                    instance_id: id,
                    action: PowerAction::Restart,
                });
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                self.modal = Some(Modal::ConfirmDelete {
                    instance_id: id,
                    typed: Input::default(),
                    reason: Input::default(),
                    on_reason: false,
                });
            }
            KeyCode::Char('l') => {
                self.screen = Screen::Logs;
                self.logs = None;
                return vec![Job::Logs(id)];
            }
            KeyCode::Char('b') => {
                self.screen = Screen::Backups;
                self.backups = None;
                self.backup_selected = 0;
                return vec![Job::Backups(id)];
            }
            KeyCode::Char('p') | KeyCode::Enter => return vec![Job::Reveal(id)],
            _ => {}
        }
        Vec::new()
    }

    fn on_logs_key(&mut self, key: KeyEvent) -> Vec<Job> {
        let lines = self.logs.as_ref().map_or(0, |(_, lines)| lines.len());
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::Instances,
            KeyCode::Down | KeyCode::Char('j') => {
                self.log_scroll = (self.log_scroll + 1).min(lines.saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') => self.log_scroll = self.log_scroll.saturating_sub(1),
            KeyCode::PageDown => {
                self.log_scroll = (self.log_scroll + PAGE * 2).min(lines.saturating_sub(1))
            }
            KeyCode::PageUp => self.log_scroll = self.log_scroll.saturating_sub(PAGE * 2),
            KeyCode::Home | KeyCode::Char('g') => self.log_scroll = 0,
            KeyCode::End | KeyCode::Char('G') => self.log_scroll = lines.saturating_sub(1),
            KeyCode::Char('R') => {
                if let Some((id, _)) = &self.logs {
                    return vec![Job::Logs(id.clone())];
                }
            }
            _ => {}
        }
        Vec::new()
    }

    fn on_backups_key(&mut self, key: KeyEvent) -> Vec<Job> {
        let Some((id, backups)) = &self.backups else {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                self.screen = Screen::Instances;
            }
            return Vec::new();
        };
        let id = id.clone();
        let count = backups.len();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::Instances,
            KeyCode::Down | KeyCode::Char('j') => {
                self.backup_selected = (self.backup_selected + 1).min(count.saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.backup_selected = self.backup_selected.saturating_sub(1);
            }
            KeyCode::Char('R') => return vec![Job::Backups(id)],
            KeyCode::Char('n') => {
                self.modal = Some(Modal::ChooseBackupMode {
                    instance_id: id,
                    online: true,
                });
            }
            KeyCode::Enter | KeyCode::Char('r') => {
                if let Some(backup) = backups.get(self.backup_selected) {
                    self.modal = Some(Modal::ConfirmRestore {
                        instance_id: id,
                        backup_id: backup.id.clone(),
                        reason: Input::default(),
                    });
                }
            }
            _ => {}
        }
        Vec::new()
    }

    fn on_modal_key(&mut self, key: KeyEvent) -> Vec<Job> {
        let Some(modal) = self.modal.take() else {
            return Vec::new();
        };
        if key.code == KeyCode::Esc {
            return Vec::new();
        }
        let (modal, jobs) = match modal {
            Modal::Help => (None, Vec::new()),
            Modal::Reveal(revealed) => match key.code {
                KeyCode::Char(_) | KeyCode::Enter => (None, Vec::new()),
                _ => (Some(Modal::Reveal(revealed)), Vec::new()),
            },
            Modal::Create(mut form) => {
                if form.on_key(key) {
                    match form.request() {
                        Ok(request) => {
                            self.creating.insert(request.instance_id.clone());
                            (None, vec![Job::Create(Box::new(request))])
                        }
                        Err(error) => {
                            form.error = Some(error);
                            (Some(Modal::Create(form)), Vec::new())
                        }
                    }
                } else {
                    (Some(Modal::Create(form)), Vec::new())
                }
            }
            Modal::ConfirmPower {
                instance_id,
                action,
            } => match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    (None, vec![Job::Power(instance_id, action)])
                }
                _ => (None, Vec::new()),
            },
            Modal::ChooseBackupMode {
                instance_id,
                online,
            } => match key.code {
                KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::Char(' ') => (
                    Some(Modal::ChooseBackupMode {
                        instance_id,
                        online: !online,
                    }),
                    Vec::new(),
                ),
                KeyCode::Char('o') => (None, vec![Job::Backup(instance_id, BackupMode::Online)]),
                KeyCode::Char('f') => (None, vec![Job::Backup(instance_id, BackupMode::Offline)]),
                KeyCode::Enter => {
                    let mode = if online {
                        BackupMode::Online
                    } else {
                        BackupMode::Offline
                    };
                    (None, vec![Job::Backup(instance_id, mode)])
                }
                _ => (
                    Some(Modal::ChooseBackupMode {
                        instance_id,
                        online,
                    }),
                    Vec::new(),
                ),
            },
            Modal::ConfirmRestore {
                instance_id,
                backup_id,
                mut reason,
            } => {
                if key.code == KeyCode::Enter && !reason.value.trim().is_empty() {
                    let job = Job::Restore {
                        instance_id,
                        backup_id,
                        reason: reason.value.trim().to_string(),
                    };
                    (None, vec![job])
                } else {
                    reason.on_key(key);
                    (
                        Some(Modal::ConfirmRestore {
                            instance_id,
                            backup_id,
                            reason,
                        }),
                        Vec::new(),
                    )
                }
            }
            Modal::ConfirmDelete {
                instance_id,
                mut typed,
                mut reason,
                mut on_reason,
            } => {
                let confirmed = typed.value == instance_id && !reason.value.trim().is_empty();
                match key.code {
                    KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                        on_reason = !on_reason;
                    }
                    KeyCode::Enter if confirmed => {
                        let job = Job::Delete {
                            instance_id,
                            reason: reason.value.trim().to_string(),
                        };
                        return self.finish_modal(None, vec![job]);
                    }
                    KeyCode::Enter => on_reason = typed.value == instance_id,
                    _ if on_reason => reason.on_key(key),
                    _ => typed.on_key(key),
                }
                (
                    Some(Modal::ConfirmDelete {
                        instance_id,
                        typed,
                        reason,
                        on_reason,
                    }),
                    Vec::new(),
                )
            }
        };
        self.finish_modal(modal, jobs)
    }

    fn finish_modal(&mut self, modal: Option<Modal>, jobs: Vec<Job>) -> Vec<Job> {
        self.modal = modal;
        jobs
    }
}

/// The API host when it is a real address; wildcard binds give no hint.
fn default_public_host(system: &SystemInfo) -> String {
    match system.api_host.trim() {
        "" | "0.0.0.0" | "::" | "[::]" | "127.0.0.1" | "::1" | "localhost" => String::new(),
        host => host.to_string(),
    }
}

/// A client connection string, with the password only when given.
/// Gateway ports of a standalone node (network API off); empty otherwise,
/// because a panel may give instances a different public port on purpose.
pub(super) fn standalone_gateway_ports(config: &crate::config::Config) -> Vec<(Protocol, u16)> {
    if config.api.enabled {
        return Vec::new();
    }
    Protocol::ALL
        .into_iter()
        .filter(|protocol| config.protocol_enabled(*protocol))
        .filter_map(|protocol| {
            let bind = &protocol.engine().listener(config).bind;
            let port = bind.rsplit_once(':')?.1.parse().ok()?;
            Some((protocol, port))
        })
        .collect()
}

pub(super) fn connection_string(
    protocol: Protocol,
    host: &str,
    port: u16,
    database: &str,
    username: &str,
    password: Option<&SecretString>,
) -> String {
    let encode = |value: &str| crate::utils::percent::encode_unreserved(value.as_bytes());
    let credentials = match password {
        Some(password) => format!("{}:{}@", encode(username), encode(password.expose_secret())),
        None => format!("{}@", encode(username)),
    };
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match protocol {
        Protocol::Postgres => format!(
            "postgresql://{credentials}{host}:{port}/{}",
            encode(database)
        ),
        Protocol::Mysql | Protocol::Mariadb => {
            format!("mysql://{credentials}{host}:{port}/{}", encode(database))
        }
        Protocol::Mongodb => format!(
            "mongodb://{credentials}{host}:{port}/{0}?authSource={0}",
            encode(database)
        ),
        Protocol::Redis | Protocol::Valkey => format!("redis://{credentials}{host}:{port}"),
        Protocol::Clickhouse => {
            format!(
                "clickhouse://{credentials}{host}:{port}/{}",
                encode(database)
            )
        }
        // Qdrant authenticates with an API key, not a URL user.
        Protocol::Qdrant => format!("{host}:{port} (API key = password)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::console::api::{DatabaseIdentity, Limits, PublicEndpoint};

    fn instance(id: &str, protocol: Protocol, status: &str) -> Instance {
        Instance {
            instance_id: id.to_string(),
            protocol,
            deployment_mode: "dedicated".to_string(),
            runtime_id: String::new(),
            status: status.to_string(),
            public: PublicEndpoint {
                host: "db.example.com".to_string(),
                port: 5432,
            },
            database: DatabaseIdentity {
                name: "app".to_string(),
                username: "app".to_string(),
            },
            limits: Limits {
                cpu_cores: 1.0,
                memory_mib: 1024,
                disk_mib: 10240,
                disk_enforced: true,
            },
            project_id: None,
            created_at: String::new(),
            image: None,
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_text(app: &mut App, text: &str) {
        for character in text.chars() {
            app.on_key(key(KeyCode::Char(character)));
        }
    }

    fn loaded() -> App {
        let mut app = App::new("http://127.0.0.1:8080".to_string());
        app.on_outcome(Outcome::Instances(vec![
            instance("b_redis", Protocol::Redis, "stopped"),
            instance("a_pg", Protocol::Postgres, "running"),
            instance("c_new", Protocol::Mysql, "creating"),
        ]));
        app
    }

    #[test]
    fn instances_are_sorted_filtered_and_selection_survives_refresh() {
        let mut app = loaded();
        assert_eq!(app.current().unwrap().instance_id, "a_pg");
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.current().unwrap().instance_id, "b_redis");
        app.on_outcome(Outcome::Instances(vec![
            instance("0_first", Protocol::Postgres, "running"),
            instance("a_pg", Protocol::Postgres, "running"),
            instance("b_redis", Protocol::Redis, "running"),
        ]));
        assert_eq!(app.current().unwrap().instance_id, "b_redis");

        app.on_key(key(KeyCode::Char('/')));
        type_text(&mut app, "redis");
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.visible().len(), 1);
        assert_eq!(app.current().unwrap().instance_id, "b_redis");
    }

    #[test]
    fn refresh_polls_progress_of_creating_instances_without_overlapping() {
        let mut app = loaded();
        let jobs = app.refresh_jobs();
        assert_eq!(jobs, [Job::Refresh, Job::Progress("c_new".to_string())]);
        assert!(app.refresh_jobs().is_empty());
        app.on_outcome(Outcome::RefreshFailed("down".to_string()));
        assert!(!app.refresh_jobs().is_empty());
    }

    #[test]
    fn a_creation_that_leaves_the_list_reports_why_it_failed() {
        let mut app = loaded();
        app.on_outcome(Outcome::Instances(vec![instance(
            "a_pg",
            Protocol::Postgres,
            "running",
        )]));
        app.refreshing = false;
        assert!(
            app.refresh_jobs()
                .contains(&Job::Progress("c_new".to_string()))
        );
        let failed: StatusResponse = serde_json::from_value(serde_json::json!({
            "status": "failed",
            "progress": {
                "stage": "starting",
                "message": "container was not ready",
                "status": "failed",
                "diagnostic": { "code": "internal", "message": "instance creation failed", "error_id": "e1" }
            }
        }))
        .unwrap();
        app.on_outcome(Outcome::Progress("c_new".to_string(), failed));
        let message = app.message.as_ref().unwrap();
        assert_eq!(message.level, Level::Error);
        assert!(
            message
                .text
                .contains("creating c_new failed: instance creation failed (error id e1)")
        );
        assert!(app.creating.is_empty());
        app.refreshing = false;
        assert_eq!(app.refresh_jobs(), [Job::Refresh]);

        app.creating.insert("gone".to_string());
        app.on_outcome(Outcome::ProgressGone("gone".to_string()));
        assert!(
            app.message
                .as_ref()
                .unwrap()
                .text
                .contains("creating gone failed")
        );
        assert!(app.creating.is_empty());
    }

    #[test]
    fn standalone_nodes_show_the_gateway_port_the_instance_is_reachable_on() {
        let mut config = crate::config::Config::default();
        config.postgres.enabled = true;
        config.postgres.bind = "127.0.0.1:55432".to_string();
        config.redis.enabled = false;
        // Panel-managed: the stored public port stays authoritative.
        config.api.enabled = true;
        let mut app = loaded();
        app.gateway_ports = standalone_gateway_ports(&config);
        assert_eq!(app.connect_port(Protocol::Postgres, 5434), 5434);

        config.api.enabled = false;
        app.gateway_ports = standalone_gateway_ports(&config);
        assert_eq!(app.connect_port(Protocol::Postgres, 5434), 55432);
        // Disabled gateways and unknown binds keep what was stored.
        assert_eq!(app.connect_port(Protocol::Redis, 6380), 6380);
        config.postgres.bind = "not-an-address".to_string();
        app.gateway_ports = standalone_gateway_ports(&config);
        assert_eq!(app.connect_port(Protocol::Postgres, 5434), 5434);
    }

    #[test]
    fn delete_needs_the_typed_id_and_a_reason() {
        let mut app = loaded();
        app.on_key(key(KeyCode::Char('d')));
        type_text(&mut app, "a_p");
        assert!(app.on_key(key(KeyCode::Enter)).is_empty());
        type_text(&mut app, "g");
        assert!(
            app.on_key(key(KeyCode::Enter)).is_empty(),
            "reason is missing"
        );
        type_text(&mut app, "cleanup");
        assert_eq!(
            app.on_key(key(KeyCode::Enter)),
            [Job::Delete {
                instance_id: "a_pg".to_string(),
                reason: "cleanup".to_string()
            }]
        );
        assert!(app.modal.is_none());
    }

    #[test]
    fn stop_asks_first_and_start_does_not() {
        let mut app = loaded();
        assert!(app.on_key(key(KeyCode::Char('x'))).is_empty());
        assert_eq!(
            app.on_key(key(KeyCode::Char('y'))),
            [Job::Power("a_pg".to_string(), PowerAction::Stop)]
        );
        assert_eq!(
            app.on_key(key(KeyCode::Char('s'))),
            [Job::Power("a_pg".to_string(), PowerAction::Start)]
        );
        app.on_key(key(KeyCode::Char('r')));
        assert!(
            app.on_key(key(KeyCode::Char('n'))).is_empty(),
            "anything but y cancels"
        );
    }

    #[test]
    fn backups_screen_takes_and_restores_backups() {
        let mut app = loaded();
        assert_eq!(
            app.on_key(key(KeyCode::Char('b'))),
            [Job::Backups("a_pg".to_string())]
        );
        app.on_outcome(Outcome::Backups(
            "a_pg".to_string(),
            vec![Backup {
                id: "one.physical.tar.gz".to_string(),
                layout: "physical".to_string(),
                size_bytes: 1,
                modified_at: "2026-10-18T00:00:00Z".to_string(),
                consistency: None,
            }],
        ));
        app.on_key(key(KeyCode::Char('n')));
        assert_eq!(
            app.on_key(key(KeyCode::Enter)),
            [Job::Backup("a_pg".to_string(), BackupMode::Online)]
        );
        app.on_key(key(KeyCode::Enter));
        assert!(
            app.on_key(key(KeyCode::Enter)).is_empty(),
            "reason is required"
        );
        type_text(&mut app, "rollback");
        assert_eq!(
            app.on_key(key(KeyCode::Enter)),
            [Job::Restore {
                instance_id: "a_pg".to_string(),
                backup_id: "one.physical.tar.gz".to_string(),
                reason: "rollback".to_string()
            }]
        );
    }

    #[test]
    fn finished_operations_refresh_and_failures_stay_visible() {
        let mut app = loaded();
        let job = Job::Power("a_pg".to_string(), PowerAction::Start);
        app.started(&job);
        assert_eq!(app.running.len(), 1);
        let jobs = app.on_outcome(Outcome::Done {
            label: job.label().unwrap(),
            refresh: true,
        });
        assert!(app.running.is_empty());
        assert!(jobs.contains(&Job::Refresh));
        app.on_outcome(Outcome::Failed {
            label: "delete x".to_string(),
            error: "409 busy".to_string(),
        });
        assert_eq!(app.message.as_ref().unwrap().level, Level::Error);
    }

    #[test]
    fn connection_strings_encode_credentials_and_hide_the_password_by_default() {
        let password = SecretString::from("p@ss/w:rd".to_string());
        assert_eq!(
            connection_string(Protocol::Postgres, "db.example.com", 5432, "app", "u", None),
            "postgresql://u@db.example.com:5432/app"
        );
        assert_eq!(
            connection_string(Protocol::Mysql, "::1", 3306, "app", "u", Some(&password)),
            "mysql://u:p%40ss%2Fw%3Ard@[::1]:3306/app"
        );
        assert!(
            connection_string(Protocol::Mongodb, "h", 27017, "app", "u", None)
                .ends_with("/app?authSource=app")
        );
    }
}
