pub(super) fn normalize_qualified_sql(input: &str, database: &str) -> String {
    let quoted = format!("`{}`.", database.replace('`', "``"));
    rewrite_outside_literals(input, |segment| segment.replace(&quoted, "`tenant`."))
}

pub(super) fn normalize_clickhouse_ddl(input: &str, database: &str) -> String {
    let normalized = normalize_qualified_sql(input, database);
    let without_uuid = strip_clickhouse_uuid(&normalized);
    collapse_sql_whitespace(&without_uuid)
}

fn strip_clickhouse_uuid(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if matches!(bytes[cursor], b'\'' | b'"' | b'`') {
            let end = quoted_end(input, cursor).unwrap_or(bytes.len());
            output.push_str(&input[cursor..end]);
            cursor = end;
            continue;
        }
        if bytes[cursor..].len() >= 4
            && bytes[cursor..cursor + 4].eq_ignore_ascii_case(b"UUID")
            && (cursor == 0 || !is_word(bytes[cursor - 1]))
            && (cursor + 4 == bytes.len() || !is_word(bytes[cursor + 4]))
        {
            let mut end = cursor + 4;
            while end < bytes.len() && bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            if end < bytes.len()
                && bytes[end] == b'\''
                && let Some(end) = quoted_end(input, end)
            {
                cursor = end;
                continue;
            }
        }
        let ch = input[cursor..].chars().next().expect("valid UTF-8");
        output.push(ch);
        cursor += ch.len_utf8();
    }
    output
}

fn quoted_end(input: &str, start: usize) -> Option<usize> {
    let quote = input[start..].chars().next()?;
    let mut cursor = start + quote.len_utf8();
    while cursor < input.len() {
        let ch = input[cursor..].chars().next()?;
        cursor += ch.len_utf8();
        if ch == '\\' {
            if cursor < input.len() {
                cursor += input[cursor..].chars().next()?.len_utf8();
            }
        } else if ch == quote {
            if input[cursor..].starts_with(quote) {
                cursor += quote.len_utf8();
            } else {
                return Some(cursor);
            }
        }
    }
    None
}

fn rewrite_outside_literals(input: &str, rewrite: impl Fn(&str) -> String) -> String {
    let mut output = String::with_capacity(input.len());
    let mut plain = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if !matches!(ch, '\'' | '"') {
            plain.push(ch);
            continue;
        }
        output.push_str(&rewrite(&plain));
        plain.clear();
        output.push(ch);
        while let Some(inner) = chars.next() {
            output.push(inner);
            if inner == '\\' {
                if let Some(escaped) = chars.next() {
                    output.push(escaped);
                }
            } else if inner == ch {
                if chars.peek() == Some(&ch) {
                    output.push(chars.next().expect("peeked quote"));
                } else {
                    break;
                }
            }
        }
    }
    output.push_str(&rewrite(&plain));
    output
}

fn collapse_sql_whitespace(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut pending_space = false;
    let mut quote = None;
    let mut escaped = false;
    for ch in input.chars() {
        if let Some(active) = quote {
            output.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            if pending_space && !output.ends_with(' ') {
                output.push(' ');
            }
            pending_space = false;
            quote = Some(ch);
            output.push(ch);
        } else if ch.is_whitespace() {
            pending_space = true;
        } else {
            if pending_space && !output.is_empty() && !output.ends_with(' ') {
                output.push(' ');
            }
            pending_space = false;
            output.push(ch);
        }
    }
    output.trim().to_string()
}

const fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_qualifiers_are_normalized_but_string_literals_are_not() {
        assert_eq!(
            normalize_qualified_sql(
                "SELECT * FROM `source`.`t` WHERE x='`source`.`literal`'",
                "source"
            ),
            "SELECT * FROM `tenant`.`t` WHERE x='`source`.`literal`'"
        );
    }

    #[test]
    fn clickhouse_runtime_uuid_is_removed_without_removing_uuid_types() {
        assert_eq!(
            normalize_clickhouse_ddl(
                "CREATE TABLE `source`.`t` UUID '1234' (id UUID) ENGINE = MergeTree ORDER BY id",
                "source"
            ),
            "CREATE TABLE `tenant`.`t` (id UUID) ENGINE = MergeTree ORDER BY id"
        );
        assert_eq!(
            normalize_clickhouse_ddl(
                "CREATE TABLE `source`.`t` (note String COMMENT 'UUID \\'keep\\'', id UUID) ENGINE = Log",
                "source"
            ),
            "CREATE TABLE `tenant`.`t` (note String COMMENT 'UUID \\'keep\\'', id UUID) ENGINE = Log"
        );
    }
}
