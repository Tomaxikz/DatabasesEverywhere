use super::redaction;

pub(crate) const LOG_RECORD_LIMIT: usize = 128 * 1024;
pub(crate) const TRUNCATED_RECORD: &str = "[oversized log record omitted]\n";
pub(crate) const INCOMPLETE_RECORD: &str = "[incomplete secret-bearing log record omitted]\n";

#[derive(Default)]
pub(crate) struct LogRedactor {
    pending: String,
    pub(crate) failed: bool,
}

impl LogRedactor {
    pub(crate) fn push(&mut self, text: &str) -> String {
        let mut output = String::new();
        for part in text.split_inclusive(['\n', '\r']) {
            let complete = part.ends_with(['\n', '\r']);
            if self.failed {
                break;
            }
            if self.pending.len().saturating_add(part.len()) > LOG_RECORD_LIMIT {
                self.pending.clear();
                self.failed = true;
                output.push_str(TRUNCATED_RECORD);
                break;
            }
            self.pending.push_str(part);
            if complete && let Some(safe) = redaction::redact_log_record(&self.pending) {
                output.push_str(&safe);
                self.pending.clear();
            }
        }
        output
    }

    pub(crate) fn finish(&mut self) -> String {
        let pending = std::mem::take(&mut self.pending);
        redaction::redact_log_record(&pending).unwrap_or_else(|| INCOMPLETE_RECORD.into())
    }
}

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
