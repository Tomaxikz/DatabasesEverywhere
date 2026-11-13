//! The console's colours and shared widgets. Only the 16 ANSI colours are used,
//! and everything is stripped to plain text with `NO_COLOR` or `--color never`.

use std::sync::OnceLock;

use ratatui::{
    buffer::Buffer,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders},
};

use crate::databases::protocol::Protocol;

pub(super) const ACCENT: Color = Color::Cyan;
pub(super) const BORDER: Color = Color::DarkGray;
pub(super) const TEXT: Color = Color::White;
pub(super) const LABEL: Color = Color::Gray;
pub(super) const MUTED: Color = Color::DarkGray;
pub(super) const SELECTED: Color = Color::DarkGray;
pub(super) const OK: Color = Color::Green;
pub(super) const WARN: Color = Color::Yellow;
pub(super) const ERROR: Color = Color::Red;
pub(super) const BUSY: Color = Color::Magenta;

pub(super) fn colored() -> bool {
    static COLORED: OnceLock<bool> = OnceLock::new();
    *COLORED.get_or_init(crate::utils::term::stdout_color)
}

pub(super) fn fg(color: Color) -> Style {
    Style::default().fg(color)
}

pub(super) fn bold(color: Color) -> Style {
    fg(color).add_modifier(Modifier::BOLD)
}

pub(super) fn selected() -> Style {
    Style::default()
        .fg(TEXT)
        .bg(SELECTED)
        .add_modifier(Modifier::BOLD)
}

pub(super) fn muted(text: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(text.into(), fg(MUTED)))
}

pub(super) fn heading(text: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(text.into(), bold(ACCENT)))
}

pub(super) fn panel(title: &str) -> Block<'static> {
    framed(title, BORDER)
}

pub(super) fn framed(title: &str, color: Color) -> Block<'static> {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(fg(color));
    if title.is_empty() {
        return block;
    }
    block.title(tag(
        vec![Span::styled(title.to_string(), bold(ACCENT))],
        color,
    ))
}

/// Text set into a border, btop style: `┤ text ├`.
pub(super) fn tag(spans: Vec<Span<'static>>, border: Color) -> Line<'static> {
    let mut line = vec![Span::styled("┤ ", fg(border))];
    line.extend(spans);
    line.push(Span::styled(" ├", fg(border)));
    Line::from(line)
}

pub(super) fn status_color(status: &str) -> Color {
    match status {
        "running" => OK,
        "creating" | "booting" => WARN,
        "stopped" => LABEL,
        "deleting" => BUSY,
        _ => ERROR,
    }
}

pub(super) fn status_symbol(status: &str) -> &'static str {
    match status {
        "running" => "●",
        "creating" | "booting" => "◐",
        "stopped" => "○",
        "deleting" => "◌",
        _ => "✖",
    }
}

pub(super) fn status(status: &str) -> Span<'static> {
    Span::styled(
        format!("{} {status}", status_symbol(status)),
        bold(status_color(status)),
    )
}

pub(super) fn level_color(ratio: f64) -> Color {
    if ratio < 0.6 {
        OK
    } else if ratio < 0.85 {
        WARN
    } else {
        ERROR
    }
}

pub(super) struct Gauge {
    pub label: &'static str,
    pub used: Option<f64>,
    pub other: Option<f64>,
    pub mark: Option<f64>,
    pub detail: Vec<Span<'static>>,
}

impl Gauge {
    pub(super) fn new(label: &'static str, used: Option<f64>, detail: impl Into<String>) -> Self {
        Self {
            label,
            used,
            other: None,
            mark: None,
            detail: vec![Span::styled(detail.into(), fg(MUTED))],
        }
    }
}

fn cells(ratio: f64, width: usize) -> usize {
    ((ratio.clamp(0.0, 1.0) * width as f64).round() as usize).min(width)
}

/// A btop-style meter: `used` cells take the colour of their own level, cells up
/// to `other` (other load on the host) are grey, and `mark` draws a tick.
pub(super) fn meter(
    used: Option<f64>,
    other: Option<f64>,
    mark: Option<f64>,
    width: usize,
) -> Vec<Span<'static>> {
    let Some(used) = used else {
        return vec![Span::styled("·".repeat(width), fg(MUTED))];
    };
    let filled = cells(used, width);
    let busy = other.map_or(filled, |other| cells(other, width).max(filled));
    let mark = mark.and_then(|mark| cells(mark, width).checked_sub(1));
    let (other_symbol, empty_symbol) = if colored() {
        ("■", "■")
    } else {
        ("▪", "·")
    };
    (0..width)
        .map(|cell| {
            if mark == Some(cell) && cell >= filled {
                Span::styled("┃", bold(ACCENT))
            } else if cell < filled {
                let level = (cell as f64 + 1.0) / width as f64;
                Span::styled("■", fg(level_color(level)))
            } else if cell < busy {
                Span::styled(other_symbol, fg(LABEL))
            } else {
                Span::styled(empty_symbol, fg(BORDER))
            }
        })
        .collect()
}

/// Rows of `LABEL ■■■■■■····  42%  detail` whose meters share one width.
pub(super) fn gauges(rows: &[Gauge], width: u16) -> Vec<Line<'static>> {
    let width = width as usize;
    let mut detail = rows
        .iter()
        .map(|row| row.detail.iter().map(Span::width).sum::<usize>() + 2)
        .max()
        .unwrap_or(0);
    if width < 5 + 12 + 5 + detail {
        detail = 0;
    }
    let bar = width.saturating_sub(5 + 5 + detail).max(4);
    rows.iter()
        .map(|row| {
            let percent = match row.used {
                Some(ratio) => {
                    Span::styled(format!("{:>4.0}%", ratio * 100.0), bold(level_color(ratio)))
                }
                None => Span::styled("    –", fg(MUTED)),
            };
            let mut spans = vec![Span::styled(format!("{:<5}", row.label), bold(LABEL))];
            spans.extend(meter(row.used, row.other, row.mark, bar));
            spans.push(percent);
            if detail > 0 {
                spans.push(Span::raw("  "));
                spans.extend(row.detail.iter().cloned());
            }
            Line::from(spans)
        })
        .collect()
}

pub(super) fn key_hints(hints: &[(&str, &str)]) -> Line<'static> {
    key_hints_fit(hints, usize::MAX)
}

/// Hints that do not fit in `width` are left out rather than cut.
pub(super) fn key_hints_fit(hints: &[(&str, &str)], width: usize) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    let mut used = 1;
    for (index, (key, label)) in hints.iter().enumerate() {
        let separator = if index > 0 { " │ " } else { "" };
        let size = separator.chars().count() + key.chars().count() + 1 + label.chars().count();
        if used + size > width {
            break;
        }
        used += size;
        spans.push(Span::styled(separator, fg(BORDER)));
        spans.push(Span::styled((*key).to_string(), bold(ACCENT)));
        spans.push(Span::styled(format!(" {label}"), fg(LABEL)));
    }
    Line::from(spans)
}

pub(super) fn engine_color(protocol: Protocol) -> Color {
    match protocol {
        Protocol::Postgres => Color::LightBlue,
        Protocol::Redis => Color::LightRed,
        Protocol::Valkey => Color::Magenta,
        Protocol::Mariadb => Color::Yellow,
        Protocol::Mysql => Color::Blue,
        Protocol::Mongodb => Color::Green,
        Protocol::Clickhouse => Color::LightYellow,
        Protocol::Qdrant => Color::LightMagenta,
    }
}

/// The `◆ dbev` mark set into the top border of the first panel.
pub(super) fn brand(subtitle: impl Into<String>) -> Line<'static> {
    tag(
        vec![
            Span::styled("◆ dbev", bold(ACCENT)),
            Span::styled(format!("  {}", subtitle.into()), fg(LABEL)),
        ],
        BORDER,
    )
}

/// Without colour, highlights become reverse video and every colour is dropped.
pub(super) fn finish(buffer: &mut Buffer) {
    if colored() {
        return;
    }
    for position in buffer.area.positions() {
        let cell = &mut buffer[position];
        if cell.bg != Color::Reset {
            cell.modifier.insert(Modifier::REVERSED);
        }
        cell.fg = Color::Reset;
        cell.bg = Color::Reset;
    }
}

pub(super) fn human_bytes(bytes: u64) -> String {
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

pub(super) fn ratio(used: u64, total: u64) -> Option<f64> {
    (total > 0).then(|| used as f64 / total as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_human_readable() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(10 * 1024 * 1024 * 1024), "10.0 GiB");
    }

    #[test]
    fn meters_fill_to_the_ratio_and_keep_their_width() {
        let width = |used, other, mark| {
            meter(used, other, mark, 10)
                .iter()
                .map(|span| span.content.chars().count())
                .sum::<usize>()
        };
        assert_eq!(width(Some(0.42), None, None), 10);
        assert_eq!(width(Some(2.0), Some(3.0), Some(0.5)), 10);
        assert_eq!(width(None, None, None), 10);
        let symbols: String = meter(Some(0.2), Some(0.5), Some(0.8), 10)
            .iter()
            .map(|span| span.content.to_string())
            .collect();
        assert_eq!(symbols.chars().nth(7), Some('┃'));
        let unallocated: String = meter(Some(0.0), None, Some(0.0), 10)
            .iter()
            .map(|span| span.content.to_string())
            .collect();
        assert!(!unallocated.contains('┃'));
    }
}
