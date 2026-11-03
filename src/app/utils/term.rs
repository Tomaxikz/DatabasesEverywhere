use std::{
    fmt::Display,
    io,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

use anstream::{AutoStream, ColorChoice};
use anstyle::{AnsiColor, Style};

pub const OK: Style = AnsiColor::Green.on_default().bold();
pub const WARN: Style = AnsiColor::Yellow.on_default().bold();
pub const ERROR: Style = AnsiColor::Red.on_default().bold();
pub const HEADER: Style = Style::new().bold();
pub const DIM: Style = Style::new().dimmed();

static QUIET: AtomicBool = AtomicBool::new(false);
static VERBOSITY: AtomicU8 = AtomicU8::new(0);
static LOGS_TO_STDERR: AtomicBool = AtomicBool::new(false);

pub fn configure(color: ColorChoice, quiet: bool, verbosity: u8) {
    color.write_global();
    QUIET.store(quiet, Ordering::Relaxed);
    VERBOSITY.store(verbosity, Ordering::Relaxed);
}

pub fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

pub fn verbosity() -> u8 {
    VERBOSITY.load(Ordering::Relaxed)
}

pub fn stdout_color() -> bool {
    AutoStream::choice(&io::stdout()) != ColorChoice::Never
}

/// Keeps stdout for command results; the daemon still logs to stdout for the journal.
pub fn send_logs_to_stderr() {
    LOGS_TO_STDERR.store(true, Ordering::Relaxed);
}

pub fn log_color() -> bool {
    if LOGS_TO_STDERR.load(Ordering::Relaxed) {
        AutoStream::choice(&io::stderr()) != ColorChoice::Never
    } else {
        stdout_color()
    }
}

pub fn log_writer() -> Box<dyn io::Write> {
    if LOGS_TO_STDERR.load(Ordering::Relaxed) {
        Box::new(io::stderr())
    } else {
        Box::new(io::stdout())
    }
}

pub fn status(message: impl Display) {
    if !quiet() {
        anstream::println!("{message}");
    }
}

pub fn success(message: impl Display) {
    if !quiet() {
        anstream::println!("{OK}✓{OK:#} {message}");
    }
}

pub fn warning(message: impl Display) {
    anstream::eprintln!("{WARN}warning:{WARN:#} {message}");
}

pub fn error(error: &anyhow::Error) {
    let mut shown = error.to_string();
    anstream::eprintln!("{ERROR}error:{ERROR:#} {shown}");
    for cause in error.chain().skip(1) {
        let cause = cause.to_string();
        if !shown.contains(&cause) {
            anstream::eprintln!("  {DIM}caused by:{DIM:#} {cause}");
        }
        shown = cause;
    }
}

pub fn heading(title: impl Display) {
    status(format_args!("{HEADER}{title}{HEADER:#}"));
}

pub fn json(value: &impl serde::Serialize) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub fn table<R: AsRef<[String]>>(headers: &[&str], rows: &[R]) -> String {
    let mut widths: Vec<usize> = headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row.as_ref()) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let header = pad_row(headers.iter().copied(), &widths);
    out.push_str(&format!("{HEADER}{header}{HEADER:#}\n"));
    for row in rows {
        out.push_str(&pad_row(row.as_ref().iter().map(String::as_str), &widths));
        out.push('\n');
    }
    out
}

pub fn fields(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(key, value)| format!("  {DIM}{key:<width$}{DIM:#}  {value}\n"))
        .collect()
}

fn pad_row<'a>(cells: impl Iterator<Item = &'a str>, widths: &[usize]) -> String {
    let cells: Vec<&str> = cells.collect();
    let last = cells.len().saturating_sub(1);
    let mut line = String::from("  ");
    for (index, (cell, width)) in cells.iter().zip(widths).enumerate() {
        if index == last {
            line.push_str(cell);
        } else {
            line.push_str(&format!("{cell:<width$}  "));
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_align_columns_to_the_widest_cell() {
        let rows = vec![
            vec!["1".to_string(), "pool".to_string(), "open".to_string()],
            vec![
                "120".to_string(),
                "instance".to_string(),
                "closed".to_string(),
            ],
        ];
        let rendered =
            anstream::adapter::strip_str(&table(&["ID", "KIND", "STATUS"], &rows)).to_string();
        assert_eq!(
            rendered,
            "  ID   KIND      STATUS\n  1    pool      open\n  120  instance  closed\n"
        );
    }
}
