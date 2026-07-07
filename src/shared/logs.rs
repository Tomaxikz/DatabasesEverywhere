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
