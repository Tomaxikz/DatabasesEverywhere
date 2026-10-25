//! First-run state and key handling, independent of the terminal.
//!
//! The start screen leads either to the managed-mode instructions or through
//! the standalone questions to a summary. Nothing is written until the summary
//! is confirmed; the caller acts on the returned [`Finish`].

use std::{net::IpAddr, path::PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::generate::{BindScope, Choices, DiskMode, NodeIdentity};
use crate::{config::Config, databases::protocol::Protocol};

const MAX_HOST_LEN: usize = 253;

/// Facts about this machine that the wizard shows or depends on.
#[derive(Debug, Clone)]
pub(super) struct Environment {
    pub is_root: bool,
    pub systemd: bool,
    pub hostname: String,
    pub kernel: Option<String>,
    pub config_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    Start,
    Managed,
    Engines,
    PublicHost,
    Scope,
    Disk,
    Api,
    Summary,
}

/// The standalone questions in order; the summary follows the last one.
pub(super) const QUESTIONS: [Step; 5] = [
    Step::Engines,
    Step::PublicHost,
    Step::Scope,
    Step::Disk,
    Step::Api,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Finish {
    Quit,
    /// Managed by a panel: print the steps and exit.
    Managed,
    /// Standalone was chosen without root.
    NotRoot,
    /// The summary was confirmed: write the config and set the node up.
    Write,
}

pub(super) struct Wizard {
    pub step: Step,
    pub standalone: bool,
    pub engines: Vec<(Protocol, bool)>,
    pub engine_cursor: usize,
    pub public_host: String,
    pub scope: BindScope,
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
            disk: self.disk,
            api_enabled: self.api_enabled,
        }
    }

    /// 1-based position among the questions, for the step counter.
    pub(super) fn question_number(&self) -> Option<usize> {
        QUESTIONS
            .iter()
            .position(|step| *step == self.step)
            .map(|index| index + 1)
    }

    fn advance(&mut self) {
        self.step = match self.question_number() {
            Some(number) if number < QUESTIONS.len() => QUESTIONS[number],
            Some(_) => Step::Summary,
            None => self.step,
        };
    }

    fn back(&mut self) {
        self.step = match self.step {
            Step::Summary => Step::Api,
            Step::Start | Step::Managed | Step::Engines => Step::Start,
            step => QUESTIONS
                .iter()
                .position(|question| *question == step)
                .map_or(Step::Start, |index| QUESTIONS[index.saturating_sub(1)]),
        };
    }

    /// Applies one key. Returns what to do once the wizard is over.
    pub(super) fn on_key(&mut self, key: KeyEvent) -> Option<Finish> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Some(Finish::Quit);
        }
        self.error = None;
        if self.step == Step::PublicHost {
            return self.on_host_key(key);
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
            Step::Summary => return Some(Finish::Write),
            _ => self.advance(),
        }
        None
    }

    /// Moves within the current step's choices.
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

/// A DNS name or an IP address, as clients will type it.
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
        assert_eq!(visited[..QUESTIONS.len()], QUESTIONS);
        assert_eq!(press(&mut wizard, KeyCode::Enter), Some(Finish::Write));

        let choices = wizard.choices();
        assert_eq!(choices.public_host, "node-1");
        assert_eq!(choices.scope, BindScope::Local);
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
        for _ in 0..QUESTIONS.len() {
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
    fn choices_cycle_on_scope_disk_and_api_steps() {
        let mut wizard = wizard(true);
        for _ in 0..3 {
            press(&mut wizard, KeyCode::Enter);
        }
        assert_eq!(wizard.step, Step::Scope);
        press(&mut wizard, KeyCode::Down);
        assert_eq!(wizard.scope, BindScope::Network);
        press(&mut wizard, KeyCode::Enter);
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
