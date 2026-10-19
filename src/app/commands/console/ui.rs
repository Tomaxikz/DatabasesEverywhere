//! Rendering. Pure functions of [`App`]; no state changes happen here.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState, Wrap,
    },
};
use secrecy::ExposeSecret;

use super::{
    api::{Instance, PowerAction},
    app::{App, Level, Modal, REVEAL_TTL, Revealed, Screen, connection_string},
    form::{CreateForm, Field},
};

const ACCENT: Color = Color::Cyan;
const SPINNER: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];

pub(super) fn draw(frame: &mut Frame, app: &App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(5),
        Constraint::Length(2),
    ])
    .areas(frame.area());
    draw_header(frame, app, header);
    match app.screen {
        Screen::Instances => draw_instances(frame, app, body),
        Screen::Logs => draw_logs(frame, app, body),
        Screen::Backups => draw_backups(frame, app, body),
    }
    draw_footer(frame, app, footer);
    match &app.modal {
        Some(Modal::Create(form)) => draw_create(frame, form),
        Some(Modal::ConfirmDelete {
            instance_id,
            typed,
            reason,
            on_reason,
        }) => draw_confirm_delete(frame, instance_id, &typed.value, &reason.value, *on_reason),
        Some(Modal::ConfirmPower {
            instance_id,
            action,
        }) => draw_confirm_power(frame, instance_id, *action),
        Some(Modal::ChooseBackupMode {
            instance_id,
            online,
        }) => draw_backup_mode(frame, instance_id, *online),
        Some(Modal::ConfirmRestore {
            instance_id,
            backup_id,
            reason,
        }) => draw_confirm_restore(frame, instance_id, backup_id, &reason.value),
        Some(Modal::Reveal(revealed)) => draw_reveal(frame, revealed),
        Some(Modal::Help) => draw_help(frame),
        None => {}
    }
}

fn panel(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
}

fn status_style(status: &str) -> Style {
    let color = match status {
        "running" => Color::Green,
        "creating" | "booting" => Color::Yellow,
        "stopped" => Color::DarkGray,
        "deleting" => Color::Magenta,
        _ => Color::Red,
    };
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

fn status_symbol(status: &str) -> &'static str {
    match status {
        "running" => "●",
        "creating" | "booting" => "◐",
        "stopped" => "○",
        "deleting" => "◌",
        _ => "✖",
    }
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let version = app
        .system
        .as_ref()
        .map(|system| format!("v{} · API {}", system.version, system.api_version))
        .unwrap_or_else(|| "connecting…".to_string());
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for instance in &app.instances {
        *counts.entry(instance.status.as_str()).or_default() += 1;
    }
    let mut spans = vec![
        Span::styled(
            " ◆ dbev console ",
            Style::default().fg(Color::Black).bg(ACCENT).bold(),
        ),
        Span::raw("  "),
        Span::styled(version, Style::default().fg(Color::Gray)),
        Span::styled(
            format!("  ·  {}", app.api_url),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("    "),
    ];
    for (status, count) in counts {
        spans.push(Span::styled(
            format!("{} {count} {status}  ", status_symbol(status)),
            status_style(status),
        ));
    }
    if !app.running.is_empty() {
        let spinner = SPINNER[(app.ticks as usize) % SPINNER.len()];
        spans.push(Span::styled(
            format!("{spinner} {}", app.running.join(", ")),
            Style::default().fg(Color::Yellow),
        ));
    }
    let header = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(header, area.inner(Margin::new(0, 0)));
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let [message, keys] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    let line = if let Some(message) = &app.message {
        let (symbol, color) = match message.level {
            Level::Info => ("›", Color::Gray),
            Level::Success => ("✔", Color::Green),
            Level::Error => ("✖", Color::Red),
        };
        Line::from(Span::styled(
            format!(" {symbol} {}", message.text),
            Style::default().fg(color),
        ))
    } else if let Some(error) = &app.refresh_error {
        Line::from(Span::styled(
            format!(" ✖ refresh failed: {error}"),
            Style::default().fg(Color::Red),
        ))
    } else if app.filtering || !app.filter.is_empty() {
        Line::from(vec![
            Span::styled(" filter: ", Style::default().fg(ACCENT)),
            Span::raw(app.filter.clone()),
            Span::styled(
                if app.filtering { "▏" } else { "" },
                Style::default().fg(ACCENT),
            ),
        ])
    } else {
        Line::default()
    };
    frame.render_widget(Paragraph::new(line), message);
    let hints: &[(&str, &str)] = match app.screen {
        Screen::Instances => &[
            ("↑↓", "select"),
            ("n", "new"),
            ("p", "credentials"),
            ("s/x/r", "power"),
            ("l", "logs"),
            ("b", "backups"),
            ("d", "delete"),
            ("/", "filter"),
            ("?", "help"),
            ("q", "quit"),
        ],
        Screen::Logs => &[("↑↓ PgUp/PgDn", "scroll"), ("R", "reload"), ("Esc", "back")],
        Screen::Backups => &[
            ("↑↓", "select"),
            ("n", "new backup"),
            ("Enter", "restore"),
            ("R", "reload"),
            ("Esc", "back"),
        ],
    };
    frame.render_widget(Paragraph::new(key_hints(hints)), keys);
}

fn key_hints(hints: &[(&str, &str)]) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    for (key, label) in hints {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default().fg(Color::Black).bg(Color::DarkGray),
        ));
        spans.push(Span::styled(
            format!(" {label}  "),
            Style::default().fg(Color::Gray),
        ));
    }
    Line::from(spans)
}

fn draw_instances(frame: &mut Frame, app: &App, area: Rect) {
    let [list, details] =
        Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).areas(area);
    let visible = app.visible();
    let rows = visible.iter().map(|instance| {
        Row::new(vec![
            Cell::from(Span::styled(
                format!("{} {}", status_symbol(&instance.status), instance.status),
                status_style(&instance.status),
            )),
            Cell::from(instance.instance_id.clone()),
            Cell::from(instance.protocol.as_str()),
            Cell::from(instance.deployment_mode.clone()),
            Cell::from(format!("{}:{}", instance.public.host, instance.public.port)),
        ])
    });
    let title = format!("Instances ({}/{})", visible.len(), app.instances.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(13),
            Constraint::Fill(2),
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Fill(2),
        ],
    )
    .header(
        Row::new(["Status", "Instance", "Engine", "Mode", "Endpoint"])
            .style(Style::default().fg(ACCENT).bold())
            .bottom_margin(1),
    )
    .block(panel(&title))
    .row_highlight_style(Style::default().bg(Color::Rgb(40, 44, 52)).bold())
    .highlight_symbol("▌ ");
    let mut state =
        TableState::default().with_selected((!visible.is_empty()).then_some(app.selected));
    frame.render_stateful_widget(table, list, &mut state);
    if visible.is_empty() {
        let empty = if !app.loaded {
            "Loading instances…"
        } else if app.instances.is_empty() {
            "No instances yet. Press n to create one."
        } else {
            "Nothing matches the filter."
        };
        frame.render_widget(
            Paragraph::new(empty)
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::DarkGray)),
            list.inner(Margin::new(2, 4)),
        );
    }
    draw_details(frame, app, app.current(), details);
}

fn draw_details(frame: &mut Frame, app: &App, instance: Option<&Instance>, area: Rect) {
    let Some(instance) = instance else {
        frame.render_widget(panel("Details"), area);
        return;
    };
    let field = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!("{label:<12}"), Style::default().fg(Color::DarkGray)),
            Span::raw(value),
        ])
    };
    let mut lines = vec![
        Line::from(Span::styled(
            instance.instance_id.clone(),
            Style::default().fg(Color::White).bold(),
        )),
        Line::from(Span::styled(
            format!("{} {}", status_symbol(&instance.status), instance.status),
            status_style(&instance.status),
        )),
        Line::default(),
        field("Engine", instance.protocol.to_string()),
        field("Placement", instance.deployment_mode.clone()),
        field("Database", instance.database.name.clone()),
        field("Username", instance.database.username.clone()),
        field(
            "Endpoint",
            format!("{}:{}", instance.public.host, instance.public.port),
        ),
        field(
            "Limits",
            format!(
                "{} CPU · {} RAM · {} disk{}",
                instance.limits.cpu_cores,
                human_bytes(instance.limits.memory_mib.saturating_mul(1024 * 1024)),
                human_bytes(instance.limits.disk_mib.saturating_mul(1024 * 1024)),
                if instance.limits.disk_enforced {
                    ""
                } else {
                    " (soft)"
                }
            ),
        ),
    ];
    if let Some(project) = &instance.project_id {
        lines.push(field("Project", project.clone()));
    }
    if !instance.created_at.is_empty() {
        lines.push(field("Created", instance.created_at.clone()));
    }
    if let Some(progress) = app
        .progress
        .get(&instance.instance_id)
        .and_then(|status| status.progress.as_ref())
    {
        lines.push(Line::default());
        let percent = progress
            .percent
            .map(|percent| format!(" {percent:.0}%"))
            .unwrap_or_default();
        lines.push(field("Progress", format!("{}{percent}", progress.stage)));
        if !progress.message.is_empty() {
            lines.push(Line::from(Span::styled(
                progress.message.clone(),
                Style::default().fg(Color::Yellow),
            )));
        }
    }
    lines.extend([
        Line::default(),
        Line::from(Span::styled("Connect", Style::default().fg(ACCENT).bold())),
        Line::from(connection_string(
            instance.protocol,
            &instance.public.host,
            instance.public.port,
            &instance.database.name,
            &instance.database.username,
            None,
        )),
        Line::default(),
        Line::from(Span::styled(
            "Press p to reveal the password (root only).",
            Style::default().fg(Color::DarkGray),
        )),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel("Details"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_logs(frame: &mut Frame, app: &App, area: Rect) {
    let Some((id, lines)) = &app.logs else {
        frame.render_widget(Paragraph::new("Loading logs…").block(panel("Logs")), area);
        return;
    };
    let height = area.height.saturating_sub(2) as usize;
    let start = app.log_scroll.saturating_sub(height.saturating_sub(1));
    let text: Vec<Line> = lines
        .iter()
        .skip(start)
        .take(height)
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            let style = if lower.contains("error") || lower.contains("fatal") {
                Style::default().fg(Color::Red)
            } else if lower.contains("warn") {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            Line::from(Span::styled(line.clone(), style))
        })
        .collect();
    let title = format!("Logs · {id} · {} lines", lines.len());
    frame.render_widget(Paragraph::new(text).block(panel(&title)), area);
    let mut scroll = ScrollbarState::new(lines.len()).position(app.log_scroll);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight),
        area.inner(Margin::new(0, 1)),
        &mut scroll,
    );
}

fn draw_backups(frame: &mut Frame, app: &App, area: Rect) {
    let Some((id, backups)) = &app.backups else {
        frame.render_widget(
            Paragraph::new("Loading backups…").block(panel("Backups")),
            area,
        );
        return;
    };
    let rows = backups.iter().map(|backup| {
        Row::new(vec![
            Cell::from(backup.modified_at.clone()),
            Cell::from(backup.layout.clone()),
            Cell::from(
                backup
                    .consistency
                    .clone()
                    .unwrap_or_else(|| "—".to_string()),
            ),
            Cell::from(human_bytes(backup.size_bytes)),
            Cell::from(backup.id.clone()),
        ])
    });
    let title = format!("Backups · {id} · {}", backups.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(22),
            Constraint::Length(9),
            Constraint::Length(24),
            Constraint::Length(10),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new(["Taken", "Layout", "Consistency", "Size", "Backup ID"])
            .style(Style::default().fg(ACCENT).bold())
            .bottom_margin(1),
    )
    .block(panel(&title))
    .row_highlight_style(Style::default().bg(Color::Rgb(40, 44, 52)).bold())
    .highlight_symbol("▌ ");
    let mut state =
        TableState::default().with_selected((!backups.is_empty()).then_some(app.backup_selected));
    frame.render_stateful_widget(table, area, &mut state);
    if backups.is_empty() {
        frame.render_widget(
            Paragraph::new("No backups yet. Press n to take one.")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::DarkGray)),
            area.inner(Margin::new(2, 4)),
        );
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A centred popup `width` columns wide and `height` rows tall.
fn popup(frame: &mut Frame, title: &str, width: u16, height: u16) -> Rect {
    let area = frame.area();
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    let rect = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, rect);
    let block = panel(title).border_style(Style::default().fg(ACCENT));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    inner.inner(Margin::new(1, 0))
}

fn input_line(label: &str, value: &str, focused: bool) -> Line<'static> {
    input_line_with_cursor(label, value, focused, focused)
}

fn input_line_with_cursor(label: &str, value: &str, focused: bool, cursor: bool) -> Line<'static> {
    let style = if focused {
        Style::default().fg(Color::White).bg(Color::Rgb(40, 44, 52))
    } else {
        Style::default().fg(Color::Gray)
    };
    Line::from(vec![
        Span::styled(
            format!("{} {label:<13}", if focused { "›" } else { " " }),
            Style::default().fg(if focused { ACCENT } else { Color::DarkGray }),
        ),
        Span::styled(format!(" {value}{} ", if cursor { "▏" } else { "" }), style),
    ])
}

fn draw_create(frame: &mut Frame, form: &CreateForm) {
    let fields = form.visible();
    let inner = popup(frame, "New instance", 76, fields.len() as u16 + 8);
    let focused = form.focused();
    let mut lines = vec![Line::default()];
    for field in &fields {
        let value = form.value(*field);
        let shown = if field.is_choice() {
            format!("◂ {value} ▸")
        } else {
            value
        };
        let is_focused = *field == focused;
        lines.push(input_line_with_cursor(
            field.label(),
            &shown,
            is_focused,
            is_focused && !field.is_choice(),
        ));
    }
    lines.push(Line::default());
    let hint = form.hint(focused);
    if !hint.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("  {hint}"),
            Style::default().fg(Color::DarkGray),
        )));
    }
    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(
            format!("  ✖ {error}"),
            Style::default().fg(Color::Red),
        )));
    } else if focused == Field::Password {
        lines.push(Line::from(Span::styled(
            "  Save this password now; the API never returns it.",
            Style::default().fg(Color::Yellow),
        )));
    }
    lines.push(Line::default());
    lines.push(key_hints(&[
        ("Tab", "next"),
        ("Enter", "next/create"),
        ("Ctrl+S", "create"),
        ("Esc", "cancel"),
    ]));
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_confirm_delete(frame: &mut Frame, id: &str, typed: &str, reason: &str, on_reason: bool) {
    let inner = popup(frame, "Delete instance", 70, 12);
    let lines = vec![
        Line::from(Span::styled(
            format!("Permanently delete {id}?"),
            Style::default().fg(Color::Red).bold(),
        )),
        Line::from("Its data, backups, jobs and exports are removed. This cannot be undone."),
        Line::default(),
        input_line("Type the ID", typed, !on_reason),
        input_line("Reason", reason, on_reason),
        Line::default(),
        if typed == id && !reason.trim().is_empty() {
            Line::from(Span::styled(
                "Press Enter to delete.",
                Style::default().fg(Color::Red),
            ))
        } else {
            Line::from(Span::styled(
                "Type the instance ID and an audit reason.",
                Style::default().fg(Color::DarkGray),
            ))
        },
        Line::default(),
        key_hints(&[
            ("Tab", "switch field"),
            ("Enter", "confirm"),
            ("Esc", "cancel"),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn draw_confirm_power(frame: &mut Frame, id: &str, action: PowerAction) {
    let inner = popup(frame, "Confirm", 56, 7);
    let lines = vec![
        Line::from(format!("{} {id}?", capitalize(action.as_str()))),
        Line::from(Span::styled(
            "Clients are disconnected while it is down.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::default(),
        key_hints(&[("y", "yes"), ("any key", "cancel")]),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_backup_mode(frame: &mut Frame, id: &str, online: bool) {
    let inner = popup(frame, "New backup", 64, 10);
    let option = |selected: bool, title: &str, detail: &str| {
        Line::from(vec![
            Span::styled(
                format!(" {} {title:<9}", if selected { "●" } else { "○" }),
                Style::default()
                    .fg(if selected { ACCENT } else { Color::Gray })
                    .bold(),
            ),
            Span::styled(detail.to_string(), Style::default().fg(Color::DarkGray)),
        ])
    };
    let lines = vec![
        Line::from(format!("Back up {id}")),
        Line::default(),
        option(
            online,
            "Online",
            "keeps serving; fails if the engine has no strategy",
        ),
        option(!online, "Offline", "stops the database for a cold copy"),
        Line::default(),
        key_hints(&[("←→", "choose"), ("Enter", "start"), ("Esc", "cancel")]),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_confirm_restore(frame: &mut Frame, id: &str, backup: &str, reason: &str) {
    let inner = popup(frame, "Restore backup", 72, 10);
    let lines = vec![
        Line::from(Span::styled(
            format!("Replace the data of {id} with {backup}?"),
            Style::default().fg(Color::Red).bold(),
        )),
        Line::from("The instance is stopped and its current data is replaced."),
        Line::default(),
        input_line("Reason", reason, true),
        Line::default(),
        key_hints(&[("Enter", "restore"), ("Esc", "cancel")]),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn draw_reveal(frame: &mut Frame, revealed: &Revealed) {
    let height = if revealed.admin.is_some() { 14 } else { 12 };
    let inner = popup(frame, "Credentials", 86, height);
    let remaining = REVEAL_TTL
        .saturating_sub(revealed.shown_at.elapsed())
        .as_secs();
    let field = |label: &str, value: String, secret: bool| {
        Line::from(vec![
            Span::styled(format!("{label:<12}"), Style::default().fg(Color::DarkGray)),
            Span::styled(
                value,
                if secret {
                    Style::default().fg(Color::Yellow).bold()
                } else {
                    Style::default()
                },
            ),
        ])
    };
    let mut lines = vec![
        Line::from(Span::styled(
            revealed.instance_id.clone(),
            Style::default().bold(),
        )),
        Line::default(),
        field(
            "Host",
            format!("{}:{}", revealed.host, revealed.port),
            false,
        ),
        field("Database", revealed.database.clone(), false),
        field("Username", revealed.username.clone(), false),
        field(
            "Password",
            revealed.password.expose_secret().to_string(),
            true,
        ),
    ];
    if let Some((label, secret)) = &revealed.admin {
        lines.push(field(label, secret.expose_secret().to_string(), true));
    }
    lines.extend([
        Line::default(),
        Line::from(connection_string(
            revealed.protocol,
            &revealed.host,
            revealed.port,
            &revealed.database,
            &revealed.username,
            Some(&revealed.password),
        )),
        Line::default(),
        Line::from(Span::styled(
            format!("Hidden again in {remaining}s · any key closes"),
            Style::default().fg(Color::DarkGray),
        )),
    ]);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn draw_help(frame: &mut Frame) {
    let inner = popup(frame, "Keys", 64, 22);
    let rows: &[(&str, &str)] = &[
        ("↑/↓ j/k", "move selection"),
        ("PgUp/PgDn g/G", "page / first / last"),
        ("/", "filter by id, engine, status, mode, database"),
        ("n", "create an instance"),
        ("p / Enter", "reveal credentials (root)"),
        ("s", "start"),
        ("x", "stop (asks first)"),
        ("r", "restart (asks first)"),
        ("d", "delete (type the id + reason)"),
        ("l", "container logs (dedicated)"),
        ("b", "backups: take, list, restore"),
        ("R", "refresh now"),
        ("Esc", "close / back"),
        ("q / Ctrl+C", "quit"),
    ];
    let mut text = Text::default();
    for (key, action) in rows {
        text.lines.push(Line::from(vec![
            Span::styled(format!("{key:<16}"), Style::default().fg(ACCENT).bold()),
            Span::raw(*action),
        ]));
    }
    text.lines.push(Line::default());
    text.lines.push(Line::from(Span::styled(
        "Instances created here are tagged project_id = dbev-cli; the panel does not know about them.",
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inner);
}

fn capitalize(value: &str) -> String {
    let mut characters = value.chars();
    characters
        .next()
        .map(|first| first.to_uppercase().chain(characters).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;

    #[test]
    fn every_screen_and_popup_renders_on_small_terminals() {
        let mut app = App::new("http://127.0.0.1:8080".to_string());
        for (width, height) in [(120, 40), (60, 16), (20, 8)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            for screen in [Screen::Instances, Screen::Logs, Screen::Backups] {
                app.screen = screen;
                app.modal = Some(Modal::Help);
                terminal.draw(|frame| draw(frame, &app)).unwrap();
                app.modal = Some(Modal::Create(Box::new(CreateForm::new(Vec::new(), "h"))));
                terminal.draw(|frame| draw(frame, &app)).unwrap();
            }
        }
    }

    #[test]
    fn sizes_are_human_readable() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(10 * 1024 * 1024 * 1024), "10.0 GiB");
    }
}
