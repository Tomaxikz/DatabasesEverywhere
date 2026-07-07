pub fn truncate_log_tail(logs: &str, max_chars: usize) -> String {
    if logs.is_empty() {
        return "<empty>".to_string();
    }
    if logs.len() <= max_chars {
        return logs.to_string();
    }

    let mut start = logs.len().saturating_sub(max_chars);
    while start < logs.len() && !logs.is_char_boundary(start) {
        start += 1;
    }
    format!("...{}", &logs[start..])
}

pub fn summarize_failure_logs(logs: &str, max_chars: usize) -> String {
    let logs = logs.trim();
    if logs.is_empty() {
        return "<empty>".to_string();
    }

    let important = logs
        .lines()
        .filter(|line| failure_line_is_important(line))
        .take(20)
        .collect::<Vec<_>>();

    if important.is_empty() {
        return truncate_log_tail(logs, max_chars);
    }

    let summary = format!(
        "important log lines:\n{}\nrecent log tail:\n{}",
        important.join("\n"),
        truncate_log_tail(logs, max_chars / 2)
    );
    truncate_log_tail(&summary, max_chars)
}

fn failure_line_is_important(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("\"s\":\"f\"")
        || lower.contains("\"s\":\"e\"")
        || lower.contains(" fatal")
        || lower.contains("fatal:")
        || lower.contains(" error")
        || lower.contains("error:")
        || lower.contains("exception")
        || lower.contains("cannot start")
        || lower.contains("not compatible")
        || lower.contains("incompatible")
        || lower.contains("upgrade")
        || lower.contains("downgrade")
        || lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("no space left")
        || lower.contains("disk quota exceeded")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_summary_preserves_important_lines_before_shutdown_tail() {
        let logs = [
            r#"{"s":"I","msg":"starting"}"#,
            r#"{"s":"F","msg":"MongoDB cannot start: incompatible kernel"}"#,
            r#"{"s":"I","msg":"shutdown checkpoint has successfully finished"}"#,
            r#"{"s":"I","msg":"mongod shutdown complete"}"#,
        ]
        .join("\n");

        let summary = summarize_failure_logs(&logs, 500);

        assert!(summary.contains("MongoDB cannot start"));
        assert!(summary.contains("recent log tail"));
    }
}
