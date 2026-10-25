//! The "new instance" form: fields, editing and client-side validation.
//! The daemon stays authoritative; these checks only catch typos early.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::api::{CreateLimits, CreateRequest};
use crate::databases::protocol::Protocol;

pub(super) const CLI_PROJECT_ID: &str = "dbev-cli";
const GENERATED_PASSWORD_LEN: usize = 24;
const PASSWORD_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Field {
    Protocol,
    Mode,
    ServerId,
    InstanceId,
    Database,
    Username,
    Password,
    PublicHost,
    PublicPort,
    CpuCores,
    MemoryMib,
    DiskMib,
    ProjectId,
}

impl Field {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Protocol => "Engine",
            Self::Mode => "Placement",
            Self::ServerId => "Server ID",
            Self::InstanceId => "Instance ID",
            Self::Database => "Database",
            Self::Username => "Username",
            Self::Password => "Password",
            Self::PublicHost => "Public host",
            Self::PublicPort => "Public port",
            Self::CpuCores => "CPU cores",
            Self::MemoryMib => "Memory MiB",
            Self::DiskMib => "Disk MiB",
            Self::ProjectId => "Project ID",
        }
    }

    pub(super) fn is_choice(self) -> bool {
        matches!(self, Self::Protocol | Self::Mode)
    }

    fn hint(self) -> &'static str {
        match self {
            Self::Protocol | Self::Mode => "←/→ to change",
            Self::PublicPort => "blank picks the engine's gateway port",
            Self::InstanceId | Self::Database | Self::Username => "Ctrl+R for a random one",
            Self::Password => "generated; Ctrl+R for a new one",
            Self::ServerId => "game server that owns the shared pool",
            Self::CpuCores | Self::MemoryMib => "dedicated only",
            _ => "",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct CreateForm {
    pub protocols: Vec<Protocol>,
    pub protocol_index: usize,
    pub shared: bool,
    pub values: Vec<(Field, String)>,
    pub focus: usize,
    pub error: Option<String>,
    /// Set once the operator edits the suggested instance ID.
    id_edited: bool,
}

impl CreateForm {
    pub(super) fn new(protocols: Vec<Protocol>, public_host: &str) -> Self {
        let protocols = if protocols.is_empty() {
            Protocol::ALL.to_vec()
        } else {
            protocols
        };
        let mut form = Self {
            protocols,
            protocol_index: 0,
            shared: false,
            values: vec![
                (Field::Protocol, String::new()),
                (Field::Mode, String::new()),
                (Field::ServerId, String::new()),
                (Field::InstanceId, String::new()),
                (Field::Database, "app".to_string()),
                (Field::Username, "app".to_string()),
                (Field::Password, generate_password()),
                (Field::PublicHost, public_host.to_string()),
                (Field::PublicPort, String::new()),
                (Field::CpuCores, "1".to_string()),
                (Field::MemoryMib, "1024".to_string()),
                (Field::DiskMib, "10240".to_string()),
                (Field::ProjectId, CLI_PROJECT_ID.to_string()),
            ],
            focus: 0,
            error: None,
            id_edited: false,
        };
        form.set(Field::InstanceId, suggested_instance_id(form.protocol()));
        form
    }

    pub(super) fn protocol(&self) -> Protocol {
        self.protocols[self.protocol_index]
    }

    /// Fields shown for the current engine and placement.
    pub(super) fn visible(&self) -> Vec<Field> {
        self.values
            .iter()
            .map(|(field, _)| *field)
            .filter(|field| match field {
                Field::ServerId => self.shared,
                Field::CpuCores | Field::MemoryMib => !self.shared,
                _ => true,
            })
            .collect()
    }

    pub(super) fn focused(&self) -> Field {
        let visible = self.visible();
        visible[self.focus.min(visible.len() - 1)]
    }

    pub(super) fn value(&self, field: Field) -> String {
        match field {
            Field::Protocol => self.protocol().as_str().to_string(),
            Field::Mode => if self.shared { "shared" } else { "dedicated" }.to_string(),
            _ => self
                .values
                .iter()
                .find(|(candidate, _)| *candidate == field)
                .map(|(_, value)| value.clone())
                .unwrap_or_default(),
        }
    }

    pub(super) fn hint(&self, field: Field) -> &'static str {
        field.hint()
    }

    fn set(&mut self, field: Field, value: String) {
        if let Some((_, current)) = self
            .values
            .iter_mut()
            .find(|(candidate, _)| *candidate == field)
        {
            *current = value;
        }
    }

    fn edit(&mut self, field: Field, change: impl FnOnce(&mut String)) {
        if let Some((_, current)) = self
            .values
            .iter_mut()
            .find(|(candidate, _)| *candidate == field)
        {
            change(current);
        }
    }

    fn supports_shared(&self) -> bool {
        !matches!(
            self.protocol(),
            Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
        )
    }

    fn cycle(&mut self, forward: bool) {
        match self.focused() {
            Field::Protocol => {
                let count = self.protocols.len();
                self.protocol_index = if forward {
                    (self.protocol_index + 1) % count
                } else {
                    (self.protocol_index + count - 1) % count
                };
                if !self.supports_shared() {
                    self.shared = false;
                }
                if !self.id_edited {
                    self.set(Field::InstanceId, suggested_instance_id(self.protocol()));
                }
            }
            Field::Mode => {
                if self.supports_shared() {
                    self.shared = !self.shared;
                } else {
                    self.error = Some(format!(
                        "{} supports only dedicated placement",
                        self.protocol()
                    ));
                }
            }
            _ => {}
        }
    }

    /// Applies one key. Returns true when the form should be submitted.
    pub(super) fn on_key(&mut self, key: KeyEvent) -> bool {
        self.error = None;
        let visible = self.visible().len();
        let field = self.focused();
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % visible,
            KeyCode::BackTab | KeyCode::Up => self.focus = (self.focus + visible - 1) % visible,
            KeyCode::Left if field.is_choice() => self.cycle(false),
            KeyCode::Right | KeyCode::Char(' ') if field.is_choice() => self.cycle(true),
            KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.set(Field::Password, generate_password());
            }
            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.randomize(field);
            }
            KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            KeyCode::Enter => {
                if self.focus + 1 == visible {
                    return true;
                }
                self.focus += 1;
            }
            KeyCode::Backspace if !field.is_choice() => {
                self.id_edited |= field == Field::InstanceId;
                self.edit(field, |value| {
                    value.pop();
                });
            }
            KeyCode::Char(character)
                if !field.is_choice()
                    && !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !character.is_control() =>
            {
                self.id_edited |= field == Field::InstanceId;
                self.edit(field, |value| value.push(character));
            }
            _ => {}
        }
        self.focus = self.focus.min(self.visible().len() - 1);
        false
    }

    /// Fills the focused field with a random value; on a field that has
    /// none, renews the database, username and password together.
    fn randomize(&mut self, field: Field) {
        match field {
            Field::InstanceId => {
                self.id_edited = false;
                self.set(Field::InstanceId, suggested_instance_id(self.protocol()));
            }
            Field::Database => self.set(Field::Database, random_identifier("db")),
            Field::Username => self.set(Field::Username, random_identifier("u")),
            Field::Password => self.set(Field::Password, generate_password()),
            _ => {
                self.set(Field::Database, random_identifier("db"));
                self.set(Field::Username, random_identifier("u"));
                self.set(Field::Password, generate_password());
            }
        }
    }

    /// Builds the API request, or explains the first invalid field.
    pub(super) fn request(&self) -> Result<CreateRequest, String> {
        let text = |field| self.value(field).trim().to_string();
        let required = |field: Field| {
            let value = text(field);
            if value.is_empty() {
                Err(format!("{} is required", field.label()))
            } else {
                Ok(value)
            }
        };
        let instance_id = required(Field::InstanceId)?;
        crate::utils::ids::validate_instance_id(&instance_id)
            .map_err(|error| format!("Instance ID: {error}"))?;
        let database = required(Field::Database)?;
        let username = required(Field::Username)?;
        for (field, value) in [(Field::Database, &database), (Field::Username, &username)] {
            if !valid_identifier(value) {
                return Err(format!(
                    "{}: 1-63 characters, a leading letter, then letters, digits, _ or -",
                    field.label()
                ));
            }
        }
        let password = self.value(Field::Password);
        if password.is_empty() || password.contains(['\0', '\r', '\n']) {
            return Err("Password must be non-empty and on one line".to_string());
        }
        let public_host = required(Field::PublicHost)?;
        let public_port = match text(Field::PublicPort) {
            port if port.is_empty() => None,
            port => Some(
                port.parse::<u16>()
                    .ok()
                    .filter(|port| *port > 0)
                    .ok_or("Public port must be 1-65535")?,
            ),
        };
        let disk_mib = positive(&text(Field::DiskMib), Field::DiskMib)?;
        let (cpu_cores, memory_mib) = if self.shared {
            (None, None)
        } else {
            let cpu = text(Field::CpuCores)
                .parse::<f64>()
                .ok()
                .filter(|cpu| cpu.is_finite() && (0.01..=1024.0).contains(cpu))
                .ok_or("CPU cores must be between 0.01 and 1024")?;
            (
                Some(cpu),
                Some(positive(&text(Field::MemoryMib), Field::MemoryMib)?),
            )
        };
        let server_id = if self.shared {
            Some(required(Field::ServerId)?)
        } else {
            None
        };
        Ok(CreateRequest {
            instance_id,
            protocol: self.protocol(),
            deployment_mode: if self.shared { "shared" } else { "dedicated" },
            server_id,
            database,
            username,
            password,
            public_host,
            public_port,
            project_id: match text(Field::ProjectId) {
                project if project.is_empty() => CLI_PROJECT_ID.to_string(),
                project => project,
            },
            limits: CreateLimits {
                cpu_cores,
                memory_mib,
                disk_mib,
            },
        })
    }
}

fn positive(value: &str, field: Field) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{} must be a positive whole number", field.label()))
}

fn valid_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    value.len() <= 63
        && characters
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic())
        && characters
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

/// `<prefix>_` plus 10 random hex digits: a valid database or user name.
fn random_identifier(prefix: &str) -> String {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    format!("{prefix}_{}", &suffix[..10])
}

fn suggested_instance_id(protocol: Protocol) -> String {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    format!("cli_{}_{}", protocol.as_str(), &suffix[..8])
}

/// A uniformly random password from an unambiguous alphabet.
pub(super) fn generate_password() -> String {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let limit = 256 - 256 % PASSWORD_ALPHABET.len();
    let mut password = String::with_capacity(GENERATED_PASSWORD_LEN);
    while password.len() < GENERATED_PASSWORD_LEN {
        let mut random = [0_u8; 64];
        rng.fill(&mut random)
            .expect("system CSPRNG failed to produce a password");
        for byte in random {
            if usize::from(byte) < limit && password.len() < GENERATED_PASSWORD_LEN {
                password.push(char::from(
                    PASSWORD_ALPHABET[usize::from(byte) % PASSWORD_ALPHABET.len()],
                ));
            }
        }
    }
    password
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(form: &mut CreateForm, code: KeyCode) -> bool {
        form.on_key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn focus(form: &mut CreateForm, field: Field) {
        while form.focused() != field {
            press(form, KeyCode::Tab);
        }
    }

    #[test]
    fn ctrl_r_randomizes_the_focused_field_or_all_credentials() {
        let mut form = CreateForm::new(vec![Protocol::Postgres], "127.0.0.1");
        let ctrl_r = KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL);
        focus(&mut form, Field::Username);
        let password = form.value(Field::Password);
        form.on_key(ctrl_r);
        let username = form.value(Field::Username);
        assert!(
            username.starts_with("u_") && valid_identifier(&username),
            "{username}"
        );
        assert_eq!(form.value(Field::Database), "app");
        assert_eq!(form.value(Field::Password), password);

        focus(&mut form, Field::CpuCores);
        form.on_key(ctrl_r);
        assert!(form.value(Field::Database).starts_with("db_"));
        assert_ne!(form.value(Field::Username), username);
        assert_ne!(form.value(Field::Password), password);
        assert_eq!(form.value(Field::CpuCores), "1");
        assert!(form.request().is_ok());
    }

    #[test]
    fn defaults_build_a_valid_dedicated_request_tagged_for_the_cli() {
        let form = CreateForm::new(vec![Protocol::Postgres, Protocol::Redis], "db.example.com");
        let request = form.request().unwrap();
        assert_eq!(request.protocol, Protocol::Postgres);
        assert_eq!(request.deployment_mode, "dedicated");
        assert_eq!(request.project_id, CLI_PROJECT_ID);
        assert_eq!(request.public_host, "db.example.com");
        assert_eq!(request.limits.cpu_cores, Some(1.0));
        assert_eq!(request.password.len(), GENERATED_PASSWORD_LEN);
        assert!(request.instance_id.starts_with("cli_postgres_"));
    }

    #[test]
    fn shared_placement_needs_a_server_and_drops_cpu_and_memory() {
        let mut form = CreateForm::new(vec![Protocol::Postgres], "db.example.com");
        focus(&mut form, Field::Mode);
        press(&mut form, KeyCode::Right);
        assert!(form.visible().contains(&Field::ServerId));
        assert!(!form.visible().contains(&Field::CpuCores));
        assert!(form.request().unwrap_err().contains("Server ID"));
        focus(&mut form, Field::ServerId);
        for character in "srv-1".chars() {
            press(&mut form, KeyCode::Char(character));
        }
        let request = form.request().unwrap();
        assert_eq!(request.deployment_mode, "shared");
        assert_eq!(request.server_id.as_deref(), Some("srv-1"));
        assert_eq!(request.limits.cpu_cores, None);
    }

    #[test]
    fn engines_without_shared_pools_stay_dedicated() {
        let mut form = CreateForm::new(vec![Protocol::Redis], "db.example.com");
        focus(&mut form, Field::Mode);
        press(&mut form, KeyCode::Right);
        assert!(!form.shared);
        assert!(form.error.is_some());
    }

    #[test]
    fn typos_are_reported_before_the_request_is_sent() {
        let mut form = CreateForm::new(vec![Protocol::Mysql], "db.example.com");
        focus(&mut form, Field::Database);
        press(&mut form, KeyCode::Backspace);
        press(&mut form, KeyCode::Backspace);
        press(&mut form, KeyCode::Backspace);
        press(&mut form, KeyCode::Char('9'));
        assert!(form.request().unwrap_err().starts_with("Database"));

        let mut form = CreateForm::new(vec![Protocol::Mysql], "db.example.com");
        focus(&mut form, Field::PublicPort);
        for character in "70000".chars() {
            press(&mut form, KeyCode::Char(character));
        }
        assert!(form.request().unwrap_err().contains("port"));
    }

    #[test]
    fn enter_on_the_last_field_submits() {
        let mut form = CreateForm::new(vec![Protocol::Postgres], "h");
        let last = form.visible().len() - 1;
        for _ in 0..last {
            assert!(!press(&mut form, KeyCode::Enter));
        }
        assert!(press(&mut form, KeyCode::Enter));
    }

    #[test]
    fn generated_passwords_use_only_the_alphabet() {
        let first = generate_password();
        assert_eq!(first.len(), GENERATED_PASSWORD_LEN);
        assert!(first.bytes().all(|byte| PASSWORD_ALPHABET.contains(&byte)));
        assert_ne!(first, generate_password());
    }
}
