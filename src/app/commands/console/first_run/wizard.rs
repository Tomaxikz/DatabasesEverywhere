//! First-run state and key handling, independent of the terminal.
//!
//! The start screen leads either to the managed-mode instructions or through
//! the standalone questions to a summary. Nothing is written until the summary
//! is confirmed; the caller acts on the returned [`Finish`].

use std::{
    net::IpAddr,
    path::{Component, Path, PathBuf},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{
    detect::parse_uid,
    generate::{BindScope, Choices, ContainerRuntime, DiskMode, NodeIdentity, rootless_socket},
};
use crate::{config::Config, databases::protocol::Protocol};

const MAX_HOST_LEN: usize = 253;
const MAX_SOCKET_LEN: usize = 4096;

#[derive(Debug, Clone)]
pub(super) struct Environment {
    pub is_root: bool,
    pub systemd: bool,
    pub hostname: String,
    pub kernel: Option<String>,
    pub config_path: PathBuf,
    pub runtimes: Vec<ContainerRuntime>,
    /// `docker` on PATH is a shim for Podman.
    pub docker_is_podman: bool,
    /// Uids with a rootless Podman socket file present.
    pub user_sockets: Vec<u32>,
    /// The user behind `sudo`, a likely rootless account.
    pub sudo_uid: Option<u32>,
}

/// One row of the Podman socket question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PodmanSocket {
    System,
    User(u32),
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    Start,
    Managed,
    Engines,
    PublicHost,
    Scope,
    Runtime,
    PodmanSocket,
    Disk,
    Api,
    Summary,
}

pub(super) const QUESTIONS: [Step; 7] = [
    Step::Engines,
    Step::PublicHost,
    Step::Scope,
    Step::Runtime,
    Step::PodmanSocket,
    Step::Disk,
    Step::Api,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Finish {
    Quit,
    Managed,
    NotRoot,
    Write,
}

pub(super) struct Wizard {
    pub step: Step,
    pub standalone: bool,
    pub engines: Vec<(Protocol, bool)>,
    pub engine_cursor: usize,
    pub public_host: String,
    pub scope: BindScope,
    pub runtime: ContainerRuntime,
    pub podman_cursor: usize,
    /// A uid or an absolute socket path, typed on the "Another user" row.
    pub podman_other: String,
    pub disk: DiskMode,
    pub api_enabled: bool,
    pub error: Option<String>,
    pub environment: Environment,
    pub identity: NodeIdentity,
}

impl Wizard {
    pub(super) fn new(environment: Environment, identity: NodeIdentity) -> Self {
        // The daemon's own defaults: the engines a fresh node usually needs.
        let defaults = Config::default();
        Self {
            step: Step::Start,
            standalone: true,
            engines: Protocol::ALL
                .into_iter()
                .map(|protocol| (protocol, defaults.protocol_enabled(protocol)))
                .collect(),
            engine_cursor: 0,
            public_host: environment.hostname.clone(),
            scope: BindScope::Local,
            // Docker when it is installed (or nothing is), else Podman.
            runtime: environment
                .runtimes
                .first()
                .copied()
                .unwrap_or(ContainerRuntime::Docker),
            podman_cursor: 0,
            podman_other: String::new(),
            disk: DiskMode::Auto,
            api_enabled: false,
            error: None,
            environment,
            identity,
        }
    }

    pub(super) fn choices(&self) -> Choices {
        Choices {
            engines: self
                .engines
                .iter()
                .filter(|(_, enabled)| *enabled)
                .map(|(protocol, _)| *protocol)
                .collect(),
            public_host: self.public_host.trim().to_string(),
            scope: self.scope,
            runtime: self.runtime,
            socket_path: self.socket_path(),
            disk: self.disk,
            api_enabled: self.api_enabled,
        }
    }

    /// The questions this run asks: the Podman socket only follows Podman.
    pub(super) fn questions(&self) -> Vec<Step> {
        QUESTIONS
            .into_iter()
            .filter(|step| *step != Step::PodmanSocket || self.runtime == ContainerRuntime::Podman)
            .collect()
    }

    pub(super) fn question_number(&self) -> Option<usize> {
        self.questions()
            .iter()
            .position(|step| *step == self.step)
            .map(|index| index + 1)
    }

    /// The rows of the Podman socket question: the system socket, the
    /// detected rootless users (the `sudo` caller first), and manual entry.
    pub(super) fn podman_options(&self) -> Vec<PodmanSocket> {
        let mut users: Vec<u32> = self.environment.sudo_uid.into_iter().collect();
        for uid in &self.environment.user_sockets {
            if !users.contains(uid) {
                users.push(*uid);
            }
        }
        let mut options = vec![PodmanSocket::System];
        options.extend(users.into_iter().map(PodmanSocket::User));
        options.push(PodmanSocket::Other);
        options
    }

    pub(super) fn podman_selected(&self) -> PodmanSocket {
        let options = self.podman_options();
        options[self.podman_cursor.min(options.len() - 1)]
    }

    /// Empty for Docker and for the system Podman socket.
    fn socket_path(&self) -> String {
        if self.runtime != ContainerRuntime::Podman {
            return String::new();
        }
        match self.podman_selected() {
            PodmanSocket::System => String::new(),
            PodmanSocket::User(uid) => rootless_socket(uid),
            PodmanSocket::Other => validate_socket(&self.podman_other).unwrap_or_default(),
        }
    }

    fn advance(&mut self) {
        let questions = self.questions();
        self.step = match self.question_number() {
            Some(number) if number < questions.len() => questions[number],
            Some(_) => Step::Summary,
            None => self.step,
        };
    }

    fn back(&mut self) {
        self.step = match self.step {
            Step::Summary => Step::Api,
            Step::Start | Step::Managed | Step::Engines => Step::Start,
            step => {
                let questions = self.questions();
                questions
                    .iter()
                    .position(|question| *question == step)
                    .map_or(Step::Start, |index| questions[index.saturating_sub(1)])
            }
        };
    }

    pub(super) fn on_key(&mut self, key: KeyEvent) -> Option<Finish> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Some(Finish::Quit);
        }
        self.error = None;
        if self.step == Step::PublicHost {
            return self.on_host_key(key);
        }
        if self.step == Step::PodmanSocket && self.podman_selected() == PodmanSocket::Other {
            return self.on_socket_key(key);
        }
        match key.code {
            KeyCode::Char('q') => return Some(Finish::Quit),
            KeyCode::Esc if self.step == Step::Start => return Some(Finish::Quit),
            KeyCode::Esc | KeyCode::Backspace => self.back(),
            KeyCode::Enter => return self.confirm(),
            _ => self.choose(key),
        }
        None
    }

    fn confirm(&mut self) -> Option<Finish> {
        match self.step {
            Step::Start if !self.standalone => self.step = Step::Managed,
            Step::Start if !self.environment.is_root => return Some(Finish::NotRoot),
            Step::Start => self.step = Step::Engines,
            Step::Managed => return Some(Finish::Managed),
            Step::Engines if self.engines.iter().all(|(_, enabled)| !enabled) => {
                self.error = Some("Enable at least one engine".to_string());
            }
            Step::PodmanSocket => match self.podman_selected() {
                PodmanSocket::Other => match validate_socket(&self.podman_other) {
                    Ok(_) => self.advance(),
                    Err(error) => self.error = Some(error),
                },
                _ => self.advance(),
            },
            Step::Summary => return Some(Finish::Write),
            _ => self.advance(),
        }
        None
    }

    fn choose(&mut self, key: KeyEvent) {
        let forward = matches!(
            key.code,
            KeyCode::Down | KeyCode::Right | KeyCode::Tab | KeyCode::Char('j')
        );
        let backward = matches!(
            key.code,
            KeyCode::Up | KeyCode::Left | KeyCode::BackTab | KeyCode::Char('k')
        );
        let toggle = key.code == KeyCode::Char(' ');
        match self.step {
            Step::Start if forward || backward || toggle => self.standalone = !self.standalone,
            Step::Engines => {
                let count = self.engines.len();
                if forward {
                    self.engine_cursor = (self.engine_cursor + 1) % count;
                } else if backward {
                    self.engine_cursor = (self.engine_cursor + count - 1) % count;
                } else if toggle {
                    let enabled = &mut self.engines[self.engine_cursor].1;
                    *enabled = !*enabled;
                } else if key.code == KeyCode::Char('a') {
                    let all = self.engines.iter().all(|(_, enabled)| *enabled);
                    for (_, enabled) in &mut self.engines {
                        *enabled = !all;
                    }
                }
            }
            Step::Scope if forward || backward || toggle => {
                self.scope = match self.scope {
                    BindScope::Local => BindScope::Network,
                    BindScope::Network => BindScope::Local,
                };
            }
            Step::Runtime if forward || backward || toggle => {
                self.runtime = match self.runtime {
                    ContainerRuntime::Docker => ContainerRuntime::Podman,
                    ContainerRuntime::Podman => ContainerRuntime::Docker,
                };
            }
            Step::PodmanSocket if forward || backward || toggle => {
                let count = self.podman_options().len();
                self.podman_cursor = if backward {
                    (self.podman_cursor + count - 1) % count
                } else {
                    (self.podman_cursor + 1) % count
                };
            }
            Step::Disk if forward || backward || toggle => {
                let count = DiskMode::ALL.len();
                let index = DiskMode::ALL
                    .iter()
                    .position(|mode| *mode == self.disk)
                    .unwrap_or_default();
                let index = if backward {
                    (index + count - 1) % count
                } else {
                    (index + 1) % count
                };
                self.disk = DiskMode::ALL[index];
            }
            Step::Api if forward || backward || toggle => self.api_enabled = !self.api_enabled,
            _ => {}
        }
    }

    /// Keys on the "Another user" row, where letters are text, not commands.
    fn on_socket_key(&mut self, key: KeyEvent) -> Option<Finish> {
        match key.code {
            KeyCode::Esc => self.back(),
            KeyCode::Enter => return self.confirm(),
            KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => self.choose(key),
            KeyCode::Backspace => {
                self.podman_other.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.podman_other.clear();
            }
            KeyCode::Char(character)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !character.is_control()
                    && self.podman_other.len() < MAX_SOCKET_LEN =>
            {
                self.podman_other.push(character);
            }
            _ => {}
        }
        None
    }

    fn on_host_key(&mut self, key: KeyEvent) -> Option<Finish> {
        match key.code {
            KeyCode::Esc => self.back(),
            KeyCode::Enter => match validate_host(self.public_host.trim()) {
                Ok(()) => self.advance(),
                Err(error) => self.error = Some(error),
            },
            KeyCode::Backspace => {
                self.public_host.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.public_host.clear();
            }
            KeyCode::Char(character)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !character.is_control()
                    && self.public_host.len() < MAX_HOST_LEN =>
            {
                self.public_host.push(character);
            }
            _ => {}
        }
        None
    }
}

pub(super) fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("Enter the host clients use to reach this machine".to_string());
    }
    if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    if host.len() <= MAX_HOST_LEN && host.trim_end_matches('.').split('.').all(label_ok) {
        Ok(())
    } else {
        Err(format!(
            "{host} is not a host name or IP address (no scheme, port or path)"
        ))
    }
}

/// A rootless user's uid or an absolute socket path, as the socket path the
/// config will carry. Paths are checked as config validation checks
/// `daemon.socket_path`: absolute, without `..`.
pub(super) fn validate_socket(input: &str) -> Result<String, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Enter the user's uid or the absolute path of its podman.sock".to_string());
    }
    if input.bytes().all(|byte| byte.is_ascii_digit()) {
        return parse_uid(input).map(rootless_socket).ok_or_else(|| {
            format!("{input} is not a rootless uid (1 to 4294967295); root uses the system socket")
        });
    }
    let path = Path::new(input);
    if !path.is_absolute() {
        return Err(format!("{input} is not a uid or an absolute path"));
    }
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(format!("{input} must not contain .."));
    }
    Ok(input.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn wizard(is_root: bool) -> Wizard {
        Wizard::new(
            Environment {
                is_root,
                systemd: true,
                hostname: "node-1".to_string(),
                kernel: None,
                config_path: PathBuf::from("/etc/databases-everywhere/config.yml"),
                runtimes: vec![ContainerRuntime::Docker],
                docker_is_podman: false,
                user_sockets: Vec::new(),
                sudo_uid: None,
            },
            NodeIdentity::generate(),
        )
    }

    fn press(wizard: &mut Wizard, code: KeyCode) -> Option<Finish> {
        wizard.on_key(key(code))
    }

    #[test]
    fn standalone_walks_every_question_to_the_summary_and_writes() {
        let mut wizard = wizard(true);
        assert_eq!(press(&mut wizard, KeyCode::Enter), None);
        let mut visited = vec![wizard.step];
        while wizard.step != Step::Summary {
            assert_eq!(press(&mut wizard, KeyCode::Enter), None);
            visited.push(wizard.step);
        }
        // Docker has no socket question.
        let docker_questions: Vec<Step> = QUESTIONS
            .into_iter()
            .filter(|step| *step != Step::PodmanSocket)
            .collect();
        assert_eq!(visited[..docker_questions.len()], docker_questions);
        assert_eq!(press(&mut wizard, KeyCode::Enter), Some(Finish::Write));

        let choices = wizard.choices();
        assert_eq!(choices.public_host, "node-1");
        assert_eq!(choices.scope, BindScope::Local);
        assert_eq!(choices.runtime, ContainerRuntime::Docker);
        assert_eq!(choices.disk, DiskMode::Auto);
        assert!(!choices.api_enabled, "the network API starts off");
        assert_eq!(
            choices.engines,
            [Protocol::Postgres, Protocol::Redis, Protocol::Mariadb]
        );
    }

    #[test]
    fn escape_goes_back_one_step_and_quits_from_the_start() {
        let mut wizard = wizard(true);
        press(&mut wizard, KeyCode::Enter);
        for _ in 0..wizard.questions().len() {
            press(&mut wizard, KeyCode::Enter);
        }
        assert_eq!(wizard.step, Step::Summary);
        let mut visited = Vec::new();
        while wizard.step != Step::Start {
            press(&mut wizard, KeyCode::Esc);
            visited.push(wizard.step);
        }
        assert_eq!(
            visited,
            [
                Step::Api,
                Step::Disk,
                Step::Runtime,
                Step::Scope,
                Step::PublicHost,
                Step::Engines,
                Step::Start
            ]
        );
        assert_eq!(press(&mut wizard, KeyCode::Esc), Some(Finish::Quit));
    }

    #[test]
    fn managed_shows_the_steps_and_exits() {
        let mut wizard = wizard(false);
        press(&mut wizard, KeyCode::Down);
        assert!(!wizard.standalone);
        assert_eq!(press(&mut wizard, KeyCode::Enter), None);
        assert_eq!(wizard.step, Step::Managed);
        press(&mut wizard, KeyCode::Esc);
        assert_eq!(wizard.step, Step::Start);
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(press(&mut wizard, KeyCode::Enter), Some(Finish::Managed));
    }

    #[test]
    fn standalone_without_root_stops_before_any_question() {
        let mut wizard = wizard(false);
        assert_eq!(press(&mut wizard, KeyCode::Enter), Some(Finish::NotRoot));
        assert_eq!(wizard.step, Step::Start);
    }

    #[test]
    fn engines_toggle_and_at_least_one_is_required() {
        let mut wizard = wizard(true);
        press(&mut wizard, KeyCode::Enter);
        press(&mut wizard, KeyCode::Char('a'));
        assert!(wizard.engines.iter().all(|(_, enabled)| *enabled));
        press(&mut wizard, KeyCode::Char('a'));
        assert_eq!(press(&mut wizard, KeyCode::Enter), None);
        assert_eq!(wizard.step, Step::Engines);
        assert!(wizard.error.is_some());
        press(&mut wizard, KeyCode::Up);
        press(&mut wizard, KeyCode::Char(' '));
        assert_eq!(wizard.choices().engines, [Protocol::Qdrant]);
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::PublicHost);
    }

    #[test]
    fn the_public_host_is_edited_and_checked() {
        let mut wizard = wizard(true);
        press(&mut wizard, KeyCode::Enter);
        press(&mut wizard, KeyCode::Enter);
        wizard.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        for character in "https://db".chars() {
            press(&mut wizard, KeyCode::Char(character));
        }
        // Typing q here edits the host instead of quitting.
        press(&mut wizard, KeyCode::Char('q'));
        assert_eq!(wizard.public_host, "https://dbq");
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::PublicHost);
        assert!(wizard.error.is_some());
        wizard.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        for character in "db.example.com".chars() {
            press(&mut wizard, KeyCode::Char(character));
        }
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::Scope);
        assert_eq!(wizard.choices().public_host, "db.example.com");
    }

    #[test]
    fn choices_cycle_on_scope_runtime_disk_and_api_steps() {
        let mut wizard = wizard(true);
        for _ in 0..3 {
            press(&mut wizard, KeyCode::Enter);
        }
        assert_eq!(wizard.step, Step::Scope);
        press(&mut wizard, KeyCode::Down);
        assert_eq!(wizard.scope, BindScope::Network);
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::Runtime);
        press(&mut wizard, KeyCode::Down);
        assert_eq!(wizard.runtime, ContainerRuntime::Podman);
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::PodmanSocket);
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::Disk);
        press(&mut wizard, KeyCode::Up);
        assert_eq!(wizard.disk, DiskMode::SoftScanner);
        press(&mut wizard, KeyCode::Down);
        press(&mut wizard, KeyCode::Down);
        assert_eq!(wizard.disk, DiskMode::ProjectQuota);
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::Api);
        press(&mut wizard, KeyCode::Char(' '));
        assert!(wizard.api_enabled);
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::Summary);
        assert_eq!(press(&mut wizard, KeyCode::Char('q')), Some(Finish::Quit));
    }

    fn podman_wizard(user_sockets: &[u32], sudo_uid: Option<u32>) -> Wizard {
        let mut wizard = wizard(true);
        wizard.environment.user_sockets = user_sockets.to_vec();
        wizard.environment.sudo_uid = sudo_uid;
        wizard.environment.runtimes = vec![ContainerRuntime::Podman];
        wizard.runtime = ContainerRuntime::Podman;
        wizard.step = Step::Runtime;
        wizard
    }

    #[test]
    fn the_socket_question_only_follows_podman() {
        let mut wizard = wizard(true);
        wizard.step = Step::Runtime;
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::Disk);
        assert_eq!(wizard.question_number(), Some(5));
        press(&mut wizard, KeyCode::Esc);
        assert_eq!(wizard.step, Step::Runtime);

        let mut wizard = podman_wizard(&[], None);
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::PodmanSocket);
        assert_eq!(wizard.question_number(), Some(5));
        assert_eq!(wizard.questions().len(), QUESTIONS.len());
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::Disk);
        press(&mut wizard, KeyCode::Esc);
        assert_eq!(wizard.step, Step::PodmanSocket);
        press(&mut wizard, KeyCode::Esc);
        assert_eq!(wizard.step, Step::Runtime);
    }

    #[test]
    fn podman_defaults_to_the_system_socket() {
        let wizard = podman_wizard(&[1000], Some(1000));
        assert_eq!(wizard.podman_selected(), PodmanSocket::System);
        assert_eq!(wizard.choices().socket_path, "");
    }

    #[test]
    fn rows_list_the_sudo_user_first_without_duplicates() {
        let wizard = podman_wizard(&[1001, 1000], Some(1000));
        assert_eq!(
            wizard.podman_options(),
            [
                PodmanSocket::System,
                PodmanSocket::User(1000),
                PodmanSocket::User(1001),
                PodmanSocket::Other
            ]
        );
        let wizard = podman_wizard(&[], Some(1234));
        assert_eq!(
            wizard.podman_options().len(),
            3,
            "sudo user without a socket"
        );
        let wizard = podman_wizard(&[], None);
        assert_eq!(
            wizard.podman_options(),
            [PodmanSocket::System, PodmanSocket::Other]
        );
    }

    #[test]
    fn a_detected_rootless_user_is_chosen_with_the_arrow_keys() {
        let mut wizard = podman_wizard(&[1000], None);
        press(&mut wizard, KeyCode::Enter);
        press(&mut wizard, KeyCode::Down);
        assert_eq!(wizard.podman_selected(), PodmanSocket::User(1000));
        assert_eq!(
            wizard.choices().socket_path,
            "/run/user/1000/podman/podman.sock"
        );
        press(&mut wizard, KeyCode::Up);
        assert_eq!(wizard.choices().socket_path, "");
        press(&mut wizard, KeyCode::Up);
        assert_eq!(wizard.podman_selected(), PodmanSocket::Other, "wraps");
        press(&mut wizard, KeyCode::Down);
        press(&mut wizard, KeyCode::Down);
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::Disk);
        assert_eq!(
            wizard.choices().socket_path,
            "/run/user/1000/podman/podman.sock"
        );
        // Docker never carries the rootless socket.
        wizard.runtime = ContainerRuntime::Docker;
        assert_eq!(wizard.choices().socket_path, "");
    }

    #[test]
    fn another_user_is_typed_and_checked() {
        let mut wizard = podman_wizard(&[], None);
        press(&mut wizard, KeyCode::Enter);
        press(&mut wizard, KeyCode::Char('j'));
        assert_eq!(wizard.podman_selected(), PodmanSocket::Other);
        // Empty entry is refused.
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::PodmanSocket);
        assert!(wizard.error.is_some());
        // Letters are text here, q does not quit.
        press(&mut wizard, KeyCode::Char('q'));
        assert_eq!(wizard.podman_other, "q");
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.step, Step::PodmanSocket);
        wizard.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        for character in "1001".chars() {
            press(&mut wizard, KeyCode::Char(character));
        }
        press(&mut wizard, KeyCode::Backspace);
        press(&mut wizard, KeyCode::Char('2'));
        assert_eq!(wizard.podman_other, "1002");
        assert_eq!(
            wizard.choices().socket_path,
            "/run/user/1002/podman/podman.sock"
        );
        assert_eq!(press(&mut wizard, KeyCode::Enter), None);
        assert_eq!(wizard.step, Step::Disk);

        press(&mut wizard, KeyCode::Esc);
        wizard.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        for character in "/srv/podman.sock".chars() {
            press(&mut wizard, KeyCode::Char(character));
        }
        press(&mut wizard, KeyCode::Enter);
        assert_eq!(wizard.choices().socket_path, "/srv/podman.sock");
        press(&mut wizard, KeyCode::Esc);
        press(&mut wizard, KeyCode::Esc);
        assert_eq!(wizard.step, Step::Runtime);
    }

    #[test]
    fn sockets_are_validated_like_the_config() {
        assert_eq!(
            validate_socket(" 1000 "),
            Ok("/run/user/1000/podman/podman.sock".to_string())
        );
        assert_eq!(
            validate_socket("/run/user/7/podman/podman.sock"),
            Ok("/run/user/7/podman/podman.sock".to_string())
        );
        for input in [
            "",
            "0",
            "99999999999",
            "podman.sock",
            "/run/../x.sock",
            "alice",
        ] {
            assert!(validate_socket(input).is_err(), "{input}");
        }
    }

    #[test]
    fn hosts_are_names_or_addresses() {
        for host in [
            "db.example.com",
            "node-1",
            "10.0.0.5",
            "::1",
            "[2001:db8::1]",
        ] {
            assert_eq!(validate_host(host), Ok(()), "{host}");
        }
        for host in ["", "db.example.com:5432", "http://db", "-db", "a b", "db/x"] {
            assert!(validate_host(host).is_err(), "{host}");
        }
    }
}
