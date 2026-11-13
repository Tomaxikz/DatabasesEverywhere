//! Rendering of the first-run screens, in the console's look.

use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use super::{
    generate::{BindScope, ContainerRuntime, DiskMode, chosen_mongodb_image},
    managed_steps,
    wizard::{QUESTIONS, Step, Wizard},
};
use crate::{
    commands::console::{
        theme::{
            self, ACCENT, BORDER, ERROR, MUTED, TEXT, WARN, bold, fg, key_hints_fit, muted, panel,
            tag,
        },
        ui::{input_line_with_cursor, popup},
    },
    databases::protocol::Protocol,
    utils::constants::ports,
};

const WIDTH: u16 = 96;

pub(super) fn draw(frame: &mut Frame, wizard: &Wizard) {
    let [header, _, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(5),
        Constraint::Length(2),
    ])
    .areas(frame.area());
    frame.render_widget(
        panel("")
            .title_top(theme::brand("first-run setup"))
            .title_top(
                tag(
                    vec![Span::styled(
                        wizard.environment.config_path.display().to_string(),
                        fg(MUTED),
                    )],
                    BORDER,
                )
                .right_aligned(),
            ),
        header,
    );

    let (title, mut lines) = match wizard.step {
        Step::Start => ("Welcome".to_string(), start(wizard)),
        Step::Managed => ("Managed by a panel".to_string(), managed(wizard)),
        Step::Summary => ("Summary".to_string(), summary(wizard)),
        step => (
            format!(
                "Standalone · {}/{} · {}",
                wizard.question_number().unwrap_or_default(),
                QUESTIONS.len(),
                question_title(step)
            ),
            question(wizard),
        ),
    };
    if let Some(error) = &wizard.error {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(format!("✖ {error}"), fg(ERROR))));
    }
    let text_width = WIDTH
        .min(frame.area().width.saturating_sub(2))
        .saturating_sub(6)
        .max(1) as usize;
    let rows: usize = lines
        .iter()
        .map(|line| line.width().div_ceil(text_width).max(1))
        .sum();
    let inner = popup(frame, &title, WIDTH, rows as u16 + 4);
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        inner.inner(ratatui::layout::Margin::new(1, 1)),
    );

    let [_, keys] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(footer);
    let hints: &[(&str, &str)] = match wizard.step {
        Step::Start => &[("↑↓", "choose"), ("Enter", "continue"), ("q", "quit")],
        Step::Managed => &[("Enter", "exit"), ("Esc", "back")],
        Step::Engines => &[
            ("↑↓", "move"),
            ("Space", "toggle"),
            ("a", "all/none"),
            ("Enter", "next"),
            ("Esc", "back"),
        ],
        Step::PublicHost => &[("Enter", "next"), ("Ctrl+U", "clear"), ("Esc", "back")],
        Step::Scope | Step::Runtime | Step::Disk | Step::Api => {
            &[("↑↓", "choose"), ("Enter", "next"), ("Esc", "back")]
        }
        Step::Summary => &[
            ("Enter", "write and set up"),
            ("Esc", "back"),
            ("q", "quit"),
        ],
    };
    frame.render_widget(
        Paragraph::new(key_hints_fit(hints, keys.width as usize)),
        keys,
    );
    theme::finish(frame.buffer_mut());
}

fn question_title(step: Step) -> &'static str {
    match step {
        Step::Engines => "Engines",
        Step::PublicHost => "Public host",
        Step::Scope => "Listen on",
        Step::Runtime => "Container engine",
        Step::Disk => "Disk limits",
        Step::Api => "Network API",
        Step::Start | Step::Managed | Step::Summary => "",
    }
}

fn dim(text: impl Into<String>) -> Line<'static> {
    muted(text)
}

fn option(selected: bool, title: &str, detail: &str) -> Line<'static> {
    crate::commands::console::ui::option(selected, title, detail, 28)
}

fn field(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<15}"), fg(MUTED)),
        Span::styled(value.into(), fg(TEXT)),
    ])
}

fn warning(text: &'static str) -> Line<'static> {
    Line::from(Span::styled(text, fg(WARN)))
}

fn start(wizard: &Wizard) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!(
            "No config was found at {}.",
            wizard.environment.config_path.display()
        )),
        Line::from("How will this node be run?"),
        Line::default(),
        option(
            !wizard.standalone,
            "Managed by a panel (API)",
            "the panel generates the config and drives the node",
        ),
        option(
            wizard.standalone,
            "Standalone",
            "this console generates every secret and sets the node up",
        ),
        Line::default(),
    ];
    lines.push(if wizard.environment.is_root {
        dim("Nothing is written until you confirm the summary.")
    } else {
        warning("Standalone setup needs root; rerun with sudo dbev --cli to choose it.")
    });
    lines
}

fn managed(wizard: &Wizard) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("Connect this node to a panel:"), Line::default()];
    lines.extend(
        managed_steps(&wizard.environment.config_path)
            .into_iter()
            .enumerate()
            .map(|(index, step)| {
                Line::from(vec![
                    Span::styled(format!(" {}. ", index + 1), bold(ACCENT)),
                    Span::styled(step, fg(TEXT)),
                ])
            }),
    );
    lines.push(Line::default());
    lines.push(dim("These steps are printed again when the console exits."));
    lines
}

fn question(wizard: &Wizard) -> Vec<Line<'static>> {
    match wizard.step {
        Step::Engines => {
            let mut lines = vec![
                Line::from("Which database engines should this node offer?"),
                Line::default(),
            ];
            for (index, (protocol, enabled)) in wizard.engines.iter().enumerate() {
                let focused = index == wizard.engine_cursor;
                lines.push(Line::from(vec![
                    Span::styled(if focused { "› " } else { "  " }, bold(ACCENT)),
                    Span::styled(
                        format!(
                            "[{}] {}",
                            if *enabled { "x" } else { " " },
                            engine_name(*protocol)
                        ),
                        if focused {
                            theme::selected()
                        } else if *enabled {
                            fg(theme::engine_color(*protocol))
                        } else {
                            fg(MUTED)
                        },
                    ),
                ]));
            }
            lines.push(Line::default());
            lines.push(dim(
                "Each engine gets its own gateway port. Images are pulled when an instance is created.",
            ));
            lines
        }
        Step::PublicHost => vec![
            Line::from("Which host name or IP address do clients use to reach this machine?"),
            Line::from("It goes into the connection strings of the instances you create."),
            Line::default(),
            input_line_with_cursor("Public host", &wizard.public_host, true, true),
            Line::default(),
            dim(if wizard.environment.hostname.is_empty() {
                "This machine's host name could not be read.".to_string()
            } else {
                format!(
                    "Suggested: this machine's host name, {}.",
                    wizard.environment.hostname
                )
            }),
        ],
        Step::Scope => vec![
            Line::from("Where should the database gateways accept connections?"),
            Line::default(),
            option(
                wizard.scope == BindScope::Local,
                "This machine only",
                "127.0.0.1: local clients, SSH tunnels, a local proxy",
            ),
            option(
                wizard.scope == BindScope::Network,
                "The network",
                "0.0.0.0: any client that can reach this host",
            ),
            Line::default(),
            dim("On the network, restrict access with a firewall; the gateways start without TLS."),
        ],
        Step::Runtime => {
            let mut lines = vec![
                Line::from("Which container runtime runs the databases?"),
                Line::default(),
            ];
            lines.extend(ContainerRuntime::ALL.iter().map(|runtime| {
                let found = if wizard.environment.runtimes.contains(runtime) {
                    "installed"
                } else {
                    "not found on PATH"
                };
                option(
                    *runtime == wizard.runtime,
                    runtime.label(),
                    &format!("{found}; {}", runtime.description()),
                )
            }));
            lines.push(Line::default());
            if wizard.environment.runtimes.contains(&wizard.runtime) {
                lines.push(dim(
                    "Don't switch runtimes later on a node that has databases.",
                ));
            } else {
                lines.push(dim(format!(
                    "Install {} before setup runs; setup needs its socket.",
                    wizard.runtime.label()
                )));
            }
            lines
        }
        Step::Disk => {
            let mut lines = vec![
                Line::from("How should per-database disk limits be enforced?"),
                Line::default(),
            ];
            lines.extend(
                DiskMode::ALL
                    .iter()
                    .map(|mode| option(*mode == wizard.disk, mode.as_str(), mode.description())),
            );
            lines.push(Line::default());
            lines.push(dim(
                "Setup checks the choice against the filesystem; see docs/operations/disk-limits.md.",
            ));
            lines
        }
        Step::Api => vec![
            Line::from("Open the HTTP management API on the network?"),
            Line::default(),
            option(
                !wizard.api_enabled,
                "Off (recommended)",
                "the console talks to the daemon over a local socket",
            ),
            option(
                wizard.api_enabled,
                "On",
                &format!(
                    "listens on {}:{} with the generated token",
                    wizard.scope.host(),
                    ports::API
                ),
            ),
            Line::default(),
            dim(
                "Only a panel needs the network API. Keep it off unless one will manage this node.",
            ),
        ],
        Step::Start | Step::Managed | Step::Summary => Vec::new(),
    }
}

fn summary(wizard: &Wizard) -> Vec<Line<'static>> {
    let choices = wizard.choices();
    let engines = choices
        .engines
        .iter()
        .map(|protocol| engine_name(*protocol))
        .collect::<Vec<_>>()
        .join(", ");
    let scope = match choices.scope {
        BindScope::Local => "127.0.0.1 (this machine only)",
        BindScope::Network => "0.0.0.0 (the network)",
    };
    let mut lines = vec![
        field("Engines", engines),
        field("Public host", choices.public_host.clone()),
        field("Listen on", scope),
        field("Containers", choices.runtime.label()),
        field("Disk limits", choices.disk.as_str()),
        field(
            "Network API",
            if choices.api_enabled {
                format!("on, {}:{}", choices.scope.host(), ports::API)
            } else {
                "off".to_string()
            },
        ),
    ];
    if choices.engines.contains(&Protocol::Mongodb) {
        lines.push(field(
            "MongoDB image",
            chosen_mongodb_image(wizard.environment.kernel.as_deref()),
        ));
    }
    lines.extend([
        field("Node UUID", wizard.identity.uuid.clone()),
        field("Token ID", wizard.identity.token_id.clone()),
        field(
            "Secrets",
            "API token and JWT signing key, 32 random bytes each",
        ),
        Line::default(),
        Line::from(vec![
            Span::raw("Enter writes "),
            Span::styled(
                wizard.environment.config_path.display().to_string(),
                bold(ACCENT),
            ),
            Span::raw(" (root, mode 0600)"),
        ]),
    ]);
    lines.push(if wizard.environment.systemd {
        Line::from("then runs setup, which installs and starts the databases-everywhere service.")
    } else {
        warning("systemd is not running here, so only the config is written; you start the daemon.")
    });
    lines
}

pub(super) fn engine_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => "PostgreSQL",
        Protocol::Redis => "Redis",
        Protocol::Valkey => "Valkey",
        Protocol::Mariadb => "MariaDB",
        Protocol::Mysql => "MySQL",
        Protocol::Mongodb => "MongoDB",
        Protocol::Clickhouse => "ClickHouse",
        Protocol::Qdrant => "Qdrant",
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::commands::console::first_run::{
        generate::NodeIdentity,
        wizard::{Environment, Wizard},
    };

    #[test]
    fn every_step_renders_on_small_terminals() {
        for is_root in [true, false] {
            let mut wizard = Wizard::new(
                Environment {
                    is_root,
                    systemd: is_root,
                    hostname: String::new(),
                    kernel: Some("7.0.0".to_string()),
                    config_path: PathBuf::from("/etc/databases-everywhere/config.yml"),
                    runtimes: Vec::new(),
                },
                NodeIdentity::generate(),
            );
            wizard.engines[5].1 = true;
            wizard.error = Some("something".to_string());
            for step in [
                Step::Start,
                Step::Managed,
                Step::Engines,
                Step::PublicHost,
                Step::Scope,
                Step::Runtime,
                Step::Disk,
                Step::Api,
                Step::Summary,
            ] {
                wizard.step = step;
                for (width, height) in [(120, 40), (60, 16), (20, 8)] {
                    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                    terminal.draw(|frame| draw(frame, &wizard)).unwrap();
                }
            }
            wizard.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        }
    }

    #[test]
    fn the_summary_shows_identity_but_never_the_secrets() {
        use secrecy::ExposeSecret;

        let mut wizard = Wizard::new(
            Environment {
                is_root: true,
                systemd: false,
                hostname: "node-1".to_string(),
                kernel: None,
                config_path: PathBuf::from("/etc/databases-everywhere/config.yml"),
                runtimes: vec![ContainerRuntime::Podman],
            },
            NodeIdentity::generate(),
        );
        wizard.step = Step::Summary;
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        terminal.draw(|frame| draw(frame, &wizard)).unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(screen.contains(&wizard.identity.uuid));
        assert!(screen.contains("systemd is not running"));
        assert!(!screen.contains(&wizard.identity.token.expose_secret()[..16]));
    }
}
