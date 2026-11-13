//! Rendering. Pure functions of [`App`]; no state changes happen here.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Margin, Rect},
    style::{Color, Modifier},
    text::{Line, Span, Text},
    widgets::{
        Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
        TableState, Wrap,
    },
};
use secrecy::ExposeSecret;

use super::{
    api::{Instance, PowerAction},
    app::{App, Level, Modal, REVEAL_TTL, Revealed, Screen, connection_string},
    form::{CreateForm, Field},
    theme::{
        self, ACCENT, BORDER, ERROR, Gauge, LABEL, MUTED, OK, TEXT, WARN, bold, fg, gauges,
        human_bytes, key_hints, muted, panel, ratio, tag,
    },
};

const SPINNER: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
const MIB: u64 = 1024 * 1024;

pub(super) fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let node_height = if area.height >= 15 { 5 } else { 2 };
    let [node, body, footer] = Layout::vertical([
        Constraint::Length(node_height),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .areas(area);
    draw_node(frame, app, node);
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
        Some(Modal::Reveal(revealed)) => draw_reveal(frame, app, revealed),
        Some(Modal::Help) => draw_help(frame),
        None => {}
    }
    theme::finish(frame.buffer_mut());
}

fn draw_node(frame: &mut Frame, app: &App, area: Rect) {
    let version = app
        .system
        .as_ref()
        .map(|system| format!("v{} · API {}", system.version, system.api_version))
        .unwrap_or_else(|| "connecting…".to_string());
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for instance in &app.instances {
        *counts.entry(instance.status.as_str()).or_default() += 1;
    }
    let mut summary = Vec::new();
    for (status, count) in counts {
        if !summary.is_empty() {
            summary.push(Span::raw("  "));
        }
        summary.push(Span::styled(
            format!("{} {count} {status}", theme::status_symbol(status)),
            bold(theme::status_color(status)),
        ));
    }
    if summary.is_empty() {
        summary.push(Span::styled("no instances", fg(MUTED)));
    }
    let summary = tag(summary, BORDER);
    let room = (area.width as usize).saturating_sub(summary.width() + 10);
    let mut block = panel("")
        .title_top(theme::brand(version))
        .title_top(tag(vec![Span::styled(app.api_url.clone(), fg(MUTED))], BORDER).right_aligned())
        .title_bottom(summary.right_aligned());
    if !app.running.is_empty() && room > 8 {
        let spinner = SPINNER[(app.ticks as usize) % SPINNER.len()];
        let mut running = format!("{spinner} {}", app.running.join(", "));
        if running.chars().count() > room {
            running = running.chars().take(room - 1).collect::<String>() + "…";
        }
        block = block.title_bottom(tag(vec![Span::styled(running, bold(WARN))], BORDER));
    }
    if app.node_stale && app.node.is_some() {
        block = block.title_top(tag(vec![Span::styled("stale", bold(WARN))], BORDER));
    }
    let inner = block.inner(area).inner(Margin::new(1, 0));
    frame.render_widget(block, area);
    if inner.height == 0 {
        return;
    }
    let width = inner.width;
    let rows = match &app.node {
        Some(node) => vec![
            cpu_row(&node.cpu),
            capacity_row("MEM", &node.memory),
            capacity_row("DISK", &node.disk),
        ],
        None => {
            let detail = if app.sampling {
                "sampling…"
            } else {
                "unavailable"
            };
            empty_rows(detail)
        }
    };
    let lines = gauges(&rows, width);
    frame.render_widget(Paragraph::new(lines), inner);
}

fn empty_rows(detail: &str) -> Vec<Gauge> {
    ["CPU", "MEM", "DISK"]
        .into_iter()
        .map(|label| Gauge::new(label, None, detail))
        .collect()
}

/// Live container use in level colours, other host load in grey, and a tick
/// where the allocations end; the detail reads the same way.
fn live_row(
    label: &'static str,
    managed: Option<f64>,
    host: f64,
    allocated: f64,
    total: f64,
    show: impl Fn(f64) -> String,
) -> Gauge {
    let share = |value: f64| (total > 0.0).then(|| value / total);
    let used = managed.unwrap_or(host);
    let mut detail = vec![Span::styled(
        format!(
            "{} {}",
            if managed.is_some() { "dbev" } else { "host" },
            show(used)
        ),
        bold(share(used).map_or(MUTED, theme::level_color)),
    )];
    if managed.is_some() {
        detail.push(Span::styled(format!(" · host {}", show(host)), fg(LABEL)));
    }
    detail.extend([
        Span::styled(format!(" · alloc {}", show(allocated)), fg(ACCENT)),
        Span::styled(format!(" / {}", show(total)), fg(MUTED)),
    ]);
    Gauge {
        label,
        used: share(used),
        other: managed.and(share(host)),
        mark: share(allocated),
        detail,
    }
}

fn cpu_row(cpu: &super::api::NodeCpu) -> Gauge {
    let total = cpu.total_cores as f64;
    live_row(
        "CPU",
        cpu.managed_usage_cores,
        cpu.host_usage_percent / 100.0 * total,
        cpu.allocated_cores,
        total,
        |cores| format!("{cores:.1}c"),
    )
}

fn capacity_row(label: &'static str, capacity: &super::api::NodeCapacity) -> Gauge {
    let bytes = |value: u64| value as f64;
    live_row(
        label,
        capacity.managed_used_bytes.map(bytes),
        bytes(capacity.host_used_bytes),
        bytes(capacity.allocated_bytes),
        bytes(capacity.total_bytes),
        |value| human_bytes(value as u64),
    )
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let [message, keys] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    let line = if let Some(message) = &app.message {
        let (symbol, color) = match message.level {
            Level::Info => ("›", LABEL),
            Level::Success => ("✔", OK),
            Level::Error => ("✖", ERROR),
        };
        Line::from(vec![
            Span::styled(format!(" {symbol} "), bold(color)),
            Span::styled(message.text.clone(), fg(color)),
        ])
    } else if let Some(error) = &app.refresh_error {
        Line::from(vec![
            Span::styled(" ✖ ", bold(ERROR)),
            Span::styled(format!("refresh failed: {error}"), fg(ERROR)),
        ])
    } else if app.filtering || !app.filter.is_empty() {
        Line::from(vec![
            Span::styled(" / ", bold(ACCENT)),
            Span::styled("filter ", fg(LABEL)),
            Span::styled(app.filter.clone(), bold(TEXT)),
            Span::styled(if app.filtering { "▏" } else { "" }, fg(ACCENT)),
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
    frame.render_widget(
        Paragraph::new(theme::key_hints_fit(hints, keys.width as usize)),
        keys,
    );
}

fn table_header(cells: &[&'static str]) -> Row<'static> {
    Row::new(cells.to_vec())
        .style(bold(LABEL).add_modifier(Modifier::UNDERLINED))
        .bottom_margin(1)
}

fn highlight_symbol() -> Text<'static> {
    Text::from(Span::styled("▌", fg(ACCENT)))
}

fn draw_instances(frame: &mut Frame, app: &App, area: Rect) {
    let [list, details] =
        Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(area);
    let visible = app.visible();
    let medium = list.width >= 56;
    let wide = list.width >= 84;
    let rows = visible.iter().map(|instance| {
        let mut cells = vec![
            Cell::from(theme::status(&instance.status)),
            Cell::from(Span::styled(instance.instance_id.clone(), fg(TEXT))),
            Cell::from(Span::styled(
                instance.protocol.as_str(),
                fg(theme::engine_color(instance.protocol)),
            )),
        ];
        if medium {
            cells.push(Cell::from(Span::styled(
                instance.deployment_mode.clone(),
                fg(LABEL),
            )));
        }
        if wide {
            cells.push(Cell::from(Span::styled(
                format!(
                    "{}:{}",
                    instance.public.host,
                    app.connect_port(instance.protocol, instance.public.port)
                ),
                fg(LABEL),
            )));
        }
        Row::new(cells)
    });
    let title = format!("instances {}/{}", visible.len(), app.instances.len());
    let mut widths = vec![
        Constraint::Length(12),
        Constraint::Fill(2),
        Constraint::Length(10),
    ];
    let mut header = vec!["Status", "Instance", "Engine"];
    if medium {
        widths.push(Constraint::Length(9));
        header.push("Mode");
    }
    if wide {
        widths.push(Constraint::Fill(2));
        header.push("Endpoint");
    }
    let table = Table::new(rows, widths)
        .header(table_header(&header))
        .block(panel(&title))
        .row_highlight_style(theme::selected())
        .highlight_symbol(highlight_symbol());
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
                .style(fg(MUTED)),
            list.inner(Margin::new(2, 4)),
        );
    }
    draw_details(frame, app, app.current(), details);
}

fn usage_lines(app: &App, instance: &Instance, width: u16) -> Vec<Line<'static>> {
    let usage = app
        .usage
        .as_ref()
        .filter(|(id, _)| *id == instance.instance_id)
        .map(|(_, usage)| usage);
    let Some(usage) = usage else {
        let detail = if instance.status == "running" {
            "sampling…"
        } else {
            "–"
        };
        return gauges(&empty_rows(detail), width);
    };
    let limits = &instance.limits;
    let cores = usage.cpu.configured_cores.max(limits.cpu_cores);
    let memory_limit = usage
        .memory
        .limit_bytes
        .unwrap_or(usage.memory.configured_mib.saturating_mul(MIB));
    let disk_limit = if usage.disk.limit_bytes > 0 {
        usage.disk.limit_bytes
    } else {
        limits.disk_mib.saturating_mul(MIB)
    };
    let bytes = |used: Option<u64>, limit: u64| -> (Option<f64>, String) {
        match used {
            Some(used) => (
                ratio(used, limit),
                format!("{} / {}", human_bytes(used), human_bytes(limit)),
            ),
            None => (None, "–".to_string()),
        }
    };
    let (memory_ratio, memory) = bytes(usage.memory.usage_bytes, memory_limit);
    let (disk_ratio, disk) = bytes(usage.disk.used_bytes, disk_limit);
    let cpu_ratio = usage
        .cpu
        .usage_percent
        .filter(|_| cores > 0.0)
        .map(|percent| percent / (cores * 100.0));
    gauges(
        &[
            Gauge::new("CPU", cpu_ratio, format!("{cores} cores")),
            Gauge::new("MEM", memory_ratio, memory),
            Gauge::new("DISK", disk_ratio, disk),
        ],
        width,
    )
}

fn draw_details(frame: &mut Frame, app: &App, instance: Option<&Instance>, area: Rect) {
    let Some(instance) = instance else {
        frame.render_widget(panel("details"), area);
        return;
    };
    let field = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!("{label:<12}"), fg(MUTED)),
            Span::styled(value, fg(TEXT)),
        ])
    };
    let port = app.connect_port(instance.protocol, instance.public.port);
    let block = panel("details");
    let width = block.inner(area).width.saturating_sub(2);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(instance.instance_id.clone(), bold(TEXT)),
            Span::raw("  "),
            theme::status(&instance.status),
        ]),
        Line::default(),
    ];
    lines.extend(usage_lines(app, instance, width));
    lines.extend([
        Line::default(),
        Line::from(vec![
            Span::styled(format!("{:<12}", "Engine"), fg(MUTED)),
            Span::styled(
                instance.protocol.to_string(),
                bold(theme::engine_color(instance.protocol)),
            ),
        ]),
        field("Placement", instance.deployment_mode.clone()),
        field("Database", instance.database.name.clone()),
        field("Username", instance.database.username.clone()),
        field("Endpoint", format!("{}:{port}", instance.public.host)),
        field(
            "Limits",
            format!(
                "{} CPU · {} RAM · {} disk{}",
                instance.limits.cpu_cores,
                human_bytes(instance.limits.memory_mib.saturating_mul(MIB)),
                human_bytes(instance.limits.disk_mib.saturating_mul(MIB)),
                if instance.limits.disk_enforced {
                    ""
                } else {
                    " (soft)"
                }
            ),
        ),
    ]);
    if port != instance.public.port {
        lines.push(muted(format!(
            "{:12}created on :{}; the gateway now listens on :{port}",
            "", instance.public.port
        )));
    }
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
            lines.push(Line::from(Span::styled(progress.message.clone(), fg(WARN))));
        }
    }
    lines.extend([
        Line::default(),
        theme::heading("Connect"),
        Line::from(Span::styled(
            connection_string(
                instance.protocol,
                &instance.public.host,
                port,
                &instance.database.name,
                &instance.database.username,
                None,
            ),
            fg(LABEL),
        )),
        Line::default(),
        Line::from(vec![
            Span::styled("p", bold(ACCENT)),
            Span::styled(" reveals the password (root only)", fg(MUTED)),
        ]),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(block.padding(ratatui::widgets::Padding::horizontal(1)))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_logs(frame: &mut Frame, app: &App, area: Rect) {
    let Some((id, lines)) = &app.logs else {
        frame.render_widget(
            Paragraph::new(muted("Loading logs…")).block(panel("logs")),
            area,
        );
        return;
    };
    let height = area.height.saturating_sub(2) as usize;
    let start = app.log_scroll.saturating_sub(height.saturating_sub(1));
    let text: Vec<Line> = lines
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(index, line)| {
            let lower = line.to_ascii_lowercase();
            let color = if lower.contains("error") || lower.contains("fatal") {
                ERROR
            } else if lower.contains("warn") {
                WARN
            } else if lower.contains("debug") || lower.contains("trace") {
                MUTED
            } else {
                Color::Reset
            };
            Line::from(vec![
                Span::styled(format!("{:>5} ", index + 1), fg(BORDER)),
                Span::styled(line.clone(), fg(color)),
            ])
        })
        .collect();
    let block = panel(&format!("logs · {id}")).title_bottom(
        tag(
            vec![Span::styled(format!("{} lines", lines.len()), fg(MUTED))],
            BORDER,
        )
        .right_aligned(),
    );
    frame.render_widget(Paragraph::new(text).block(block), area);
    let mut scroll = ScrollbarState::new(lines.len()).position(app.log_scroll);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_style(fg(ACCENT))
            .track_style(fg(BORDER))
            .begin_symbol(None)
            .end_symbol(None),
        area.inner(Margin::new(0, 1)),
        &mut scroll,
    );
}

fn draw_backups(frame: &mut Frame, app: &App, area: Rect) {
    let Some((id, backups)) = &app.backups else {
        frame.render_widget(
            Paragraph::new(muted("Loading backups…")).block(panel("backups")),
            area,
        );
        return;
    };
    let rows = backups.iter().map(|backup| {
        Row::new(vec![
            Cell::from(Span::styled(backup.modified_at.clone(), fg(TEXT))),
            Cell::from(Span::styled(backup.layout.clone(), fg(LABEL))),
            Cell::from(match &backup.consistency {
                Some(consistency) => Span::styled(consistency.clone(), fg(OK)),
                None => Span::styled("—", fg(MUTED)),
            }),
            Cell::from(
                Line::from(Span::styled(human_bytes(backup.size_bytes), bold(ACCENT)))
                    .right_aligned(),
            ),
            Cell::from(Span::styled(backup.id.clone(), fg(MUTED))),
        ])
    });
    let title = format!("backups · {id} · {}", backups.len());
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
    .column_spacing(2)
    .header(table_header(&[
        "Taken",
        "Layout",
        "Consistency",
        "      Size",
        "Backup ID",
    ]))
    .block(panel(&title))
    .row_highlight_style(theme::selected())
    .highlight_symbol(highlight_symbol());
    let mut state =
        TableState::default().with_selected((!backups.is_empty()).then_some(app.backup_selected));
    frame.render_stateful_widget(table, area, &mut state);
    if backups.is_empty() {
        frame.render_widget(
            Paragraph::new("No backups yet. Press n to take one.")
                .alignment(Alignment::Center)
                .style(fg(MUTED)),
            area.inner(Margin::new(2, 4)),
        );
    }
}

pub(super) fn popup(frame: &mut Frame, title: &str, width: u16, height: u16) -> Rect {
    popup_framed(frame, title, width, height, ACCENT)
}

fn popup_framed(frame: &mut Frame, title: &str, width: u16, height: u16, color: Color) -> Rect {
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
    let block = theme::framed(title, color);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    inner.inner(Margin::new(1, 0))
}

fn input_line(label: &str, value: &str, focused: bool) -> Line<'static> {
    input_line_with_cursor(label, value, focused, focused)
}

pub(super) fn input_line_with_cursor(
    label: &str,
    value: &str,
    focused: bool,
    cursor: bool,
) -> Line<'static> {
    let style = if focused {
        theme::selected().remove_modifier(Modifier::BOLD)
    } else {
        fg(LABEL)
    };
    Line::from(vec![
        Span::styled(
            format!("{} {label:<13}", if focused { "›" } else { " " }),
            if focused { bold(ACCENT) } else { fg(MUTED) },
        ),
        Span::styled(format!(" {value}{} ", if cursor { "▏" } else { "" }), style),
    ])
}

fn draw_create(frame: &mut Frame, form: &CreateForm) {
    let fields = form.visible();
    let inner = popup(frame, "new instance", 82, fields.len() as u16 + 8);
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
        lines.push(muted(format!("  {hint}")));
    }
    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(format!("  ✖ {error}"), fg(ERROR))));
    } else if focused == Field::Password {
        lines.push(Line::from(Span::styled(
            "  Save this password now; the API never returns it.",
            fg(WARN),
        )));
    }
    lines.push(Line::default());
    lines.push(key_hints(&[
        ("Tab", "next"),
        ("Enter", "next/create"),
        ("Ctrl+S", "create"),
        ("Ctrl+R", "random"),
        ("Esc", "cancel"),
    ]));
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_confirm_delete(frame: &mut Frame, id: &str, typed: &str, reason: &str, on_reason: bool) {
    let inner = popup_framed(frame, "delete instance", 70, 12, ERROR);
    let lines = vec![
        Line::from(Span::styled(
            format!("Permanently delete {id}?"),
            bold(ERROR),
        )),
        Line::from("Its data, backups, jobs and exports are removed. This cannot be undone."),
        Line::default(),
        input_line("Type the ID", typed, !on_reason),
        input_line("Reason", reason, on_reason),
        Line::default(),
        if typed == id && !reason.trim().is_empty() {
            Line::from(Span::styled("Press Enter to delete.", bold(ERROR)))
        } else {
            muted("Type the instance ID and an audit reason.")
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
    let inner = popup_framed(frame, "confirm", 56, 7, WARN);
    let lines = vec![
        Line::from(vec![
            Span::styled(capitalize(action.as_str()), bold(WARN)),
            Span::styled(format!(" {id}?"), fg(TEXT)),
        ]),
        muted("Clients are disconnected while it is down."),
        Line::default(),
        key_hints(&[("y", "yes"), ("any key", "cancel")]),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

pub(super) fn option(selected: bool, title: &str, detail: &str, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {} {title:<width$}", if selected { "●" } else { "○" }),
            if selected { bold(ACCENT) } else { fg(LABEL) },
        ),
        Span::styled(detail.to_string(), fg(MUTED)),
    ])
}

fn draw_backup_mode(frame: &mut Frame, id: &str, online: bool) {
    let inner = popup(frame, "new backup", 72, 10);
    let lines = vec![
        Line::from(vec![
            Span::styled("Back up ", fg(LABEL)),
            Span::styled(id.to_string(), bold(TEXT)),
        ]),
        Line::default(),
        option(
            online,
            "Online",
            "keeps serving; fails if the engine has no strategy",
            9,
        ),
        option(!online, "Offline", "stops the database for a cold copy", 9),
        Line::default(),
        key_hints(&[("←→", "choose"), ("Enter", "start"), ("Esc", "cancel")]),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_confirm_restore(frame: &mut Frame, id: &str, backup: &str, reason: &str) {
    let inner = popup_framed(frame, "restore backup", 72, 10, ERROR);
    let lines = vec![
        Line::from(Span::styled(
            format!("Replace the data of {id} with {backup}?"),
            bold(ERROR),
        )),
        Line::from("The instance is stopped and its current data is replaced."),
        Line::default(),
        input_line("Reason", reason, true),
        Line::default(),
        key_hints(&[("Enter", "restore"), ("Esc", "cancel")]),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn draw_reveal(frame: &mut Frame, app: &App, revealed: &Revealed) {
    let height = if revealed.admin.is_some() { 14 } else { 12 };
    let inner = popup_framed(frame, "credentials", 86, height, WARN);
    let remaining = REVEAL_TTL
        .saturating_sub(revealed.shown_at.elapsed())
        .as_secs();
    let field = |label: &str, value: String, secret: bool| {
        Line::from(vec![
            Span::styled(format!("{label:<12}"), fg(MUTED)),
            Span::styled(value, if secret { bold(WARN) } else { fg(TEXT) }),
        ])
    };
    let mut lines = vec![
        Line::from(Span::styled(revealed.instance_id.clone(), bold(TEXT))),
        Line::default(),
        field(
            "Host",
            format!(
                "{}:{}",
                revealed.host,
                app.connect_port(revealed.protocol, revealed.port)
            ),
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
        Line::from(Span::styled(
            connection_string(
                revealed.protocol,
                &revealed.host,
                app.connect_port(revealed.protocol, revealed.port),
                &revealed.database,
                &revealed.username,
                Some(&revealed.password),
            ),
            fg(LABEL),
        )),
        Line::default(),
        muted(format!("Hidden again in {remaining}s · any key closes")),
    ]);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn draw_help(frame: &mut Frame) {
    let inner = popup(frame, "keys", 64, 22);
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
            Span::styled(format!("{key:<16}"), bold(ACCENT)),
            Span::styled(*action, fg(TEXT)),
        ]));
    }
    text.lines.push(Line::default());
    text.lines.push(muted(
        "Instances created here are tagged project_id = dbev-cli; the panel does not know about them.",
    ));
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
}
