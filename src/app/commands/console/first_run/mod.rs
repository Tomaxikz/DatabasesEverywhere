//! First run of `dbev --cli` on a node without a config.
//!
//! A start screen offers panel-managed or standalone operation. Managed mode
//! only explains the steps. Standalone asks a few questions, generates the
//! node identity and secrets, writes the config, runs the regular
//! `dbev --setup` with its output on the terminal, and then hands over to the
//! normal console once the daemon answers.

mod files;
mod generate;
mod ui;
mod wizard;

use std::path::Path;

use anyhow::{Context, bail};
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::StreamExt;
use tracing::instrument::WithSubscriber;

pub(super) use self::files::exists as config_exists;
use self::{
    generate::NodeIdentity,
    wizard::{Environment, Finish, Wizard},
};
use super::settings::ConsoleSettings;
use crate::utils::constants::defaults;

pub(super) enum Next {
    /// Setup ran; open the console once the daemon answers.
    OpenConsole,
    Exit,
}

pub(super) async fn run(config_path: &Path) -> anyhow::Result<Next> {
    files::check_location(config_path)?;
    let environment = Environment {
        is_root: super::credentials::is_root(),
        systemd: Path::new("/run/systemd/system").is_dir(),
        hostname: std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|name| name.trim().to_string())
            .unwrap_or_default(),
        kernel: generate::kernel_release(),
        config_path: config_path.to_path_buf(),
    };
    let mut wizard = Wizard::new(environment, NodeIdentity::generate());
    let mut terminal = ratatui::try_init().context("failed to prepare the terminal")?;
    let finish = event_loop(&mut terminal, &mut wizard).await;
    ratatui::restore();
    match finish? {
        Finish::Quit => Ok(Next::Exit),
        Finish::Managed => {
            println!("To manage this node from a panel:");
            for (index, step) in managed_steps(config_path).iter().enumerate() {
                println!("  {}. {step}", index + 1);
            }
            Ok(Next::Exit)
        }
        Finish::NotRoot => bail!(
            "standalone setup writes {} and installs a system service, so it needs root; \
             rerun it with: sudo dbev --cli",
            config_path.display()
        ),
        Finish::Write => set_up(&wizard).await,
    }
}

async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    wizard: &mut Wizard,
) -> anyhow::Result<Finish> {
    let mut events = EventStream::new();
    loop {
        terminal.draw(|frame| ui::draw(frame, wizard))?;
        match events.next().await {
            Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                if let Some(finish) = wizard.on_key(key) {
                    return Ok(finish);
                }
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error).context("failed to read the terminal"),
            None => return Ok(Finish::Quit),
        }
    }
}

async fn set_up(wizard: &Wizard) -> anyhow::Result<Next> {
    let environment = &wizard.environment;
    let config_path = &environment.config_path;
    let choices = wizard.choices();
    let config = generate::render(&choices, &wizard.identity, environment.kernel.as_deref())?;
    files::write_private(config_path, &config, false, true)?;
    println!("wrote {} (root, mode 0600)", config_path.display());
    let settings = ConsoleSettings {
        public_host: choices.public_host,
    };
    let settings_path = ConsoleSettings::path(config_path);
    if let Err(error) = settings
        .to_yaml()
        .and_then(|yaml| files::write_private(&settings_path, &yaml, true, true))
    {
        // Only the console's suggested public host is lost; keep going.
        eprintln!(
            "warning: could not save {}: {error:#}",
            settings_path.display()
        );
    }

    if !environment.systemd {
        println!();
        println!("systemd is not running here (in a container, for example), so no service");
        println!("was installed. Start the daemon under your supervisor with:");
        println!();
        println!("  {}", daemon_command(config_path));
        println!();
        println!("With the Docker Compose deployment, run `docker compose up -d` instead.");
        println!(
            "Then open the console with: {}",
            console_command(config_path)
        );
        return Ok(Next::Exit);
    }

    println!("running setup…");
    println!();
    crate::daemon::setup::setup_system(config_path.clone())
        .with_subscriber(setup_logging())
        .await
        .with_context(|| {
            format!(
                "setup failed; the new config stays at {}. Fix the problem above, then run \
                 `{}` and `{}`",
                config_path.display(),
                setup_command(config_path),
                console_command(config_path)
            )
        })?;
    println!();
    Ok(Next::OpenConsole)
}

/// Setup's log lines on stdout, like `dbev --setup`, for the setup only:
/// a global subscriber would write over the console once it opens.
fn setup_logging() -> impl tracing::Subscriber + Send + Sync {
    use std::io::IsTerminal;

    let filter = tracing_subscriber::EnvFilter::try_from_env(crate::utils::constants::RUST_LOG_ENV)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("databases_everywhere=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal())
        .finish()
}

pub(super) fn managed_steps(config_path: &Path) -> Vec<String> {
    vec![
        "Generate the node config in the panel.".to_string(),
        format!(
            "Save it to {} (root-owned, mode 0600).",
            config_path.display()
        ),
        format!("Run: {}", setup_command(config_path)),
        "See docs/operations/setup.md for requirements and options.".to_string(),
    ]
}

fn with_config(config_path: &Path, command: &str) -> String {
    if config_path == Path::new(defaults::CONFIG_PATH) {
        format!("dbev {command}")
    } else {
        format!("dbev --config {} {command}", config_path.display())
    }
}

fn setup_command(config_path: &Path) -> String {
    format!("sudo {}", with_config(config_path, "--setup"))
}

fn console_command(config_path: &Path) -> String {
    format!("sudo {}", with_config(config_path, "--cli"))
}

fn daemon_command(config_path: &Path) -> String {
    with_config(config_path, "daemon")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_name_the_config_only_when_it_is_not_the_default() {
        let default = Path::new(defaults::CONFIG_PATH);
        let custom = Path::new("/srv/dbev/config.yml");
        assert_eq!(setup_command(default), "sudo dbev --setup");
        assert_eq!(
            setup_command(custom),
            "sudo dbev --config /srv/dbev/config.yml --setup"
        );
        assert_eq!(
            daemon_command(custom),
            "dbev --config /srv/dbev/config.yml daemon"
        );
        let steps = managed_steps(default);
        assert_eq!(steps.len(), 4);
        assert!(steps[1].contains(defaults::CONFIG_PATH));
        assert!(steps[2].ends_with("sudo dbev --setup"));
        assert!(steps[3].contains("docs/operations/setup.md"));
    }
}
