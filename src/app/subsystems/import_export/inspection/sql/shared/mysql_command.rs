use std::collections::VecDeque;

use super::{
    Protocol, SharedObserver, SharedSqlError, SharedSqlIssue, SqlComment, SqlObserver, SqlToken,
    Statement,
    errors::{ExecutableCommentTooLarge, MysqlCommandPolicyError},
    scan_sql_reader,
    words::{create_object, has_keyword, has_keyword_sequence, statement_words},
};

/// Applies only the physical-storage boundary required by a live shared
/// MySQL/MariaDB session. Unlike dump admission, this deliberately permits
/// ordinary application SQL while denying statements that can replace the
/// routed database or place table data outside its managed directory.
pub(crate) fn validate_shared_mysql_command(
    sql: &[u8],
    protocol: Protocol,
) -> Result<(), MysqlCommandPolicyError> {
    check_shared_mysql_command(sql, protocol, false)
}

pub(super) fn check_shared_mysql_command(
    sql: &[u8],
    protocol: Protocol,
    executable_fragment: bool,
) -> Result<(), MysqlCommandPolicyError> {
    if !protocol.engine().family().is_mysql() {
        return Err(MysqlCommandPolicyError::Invalid);
    }
    let mut observer = MysqlCommandObserver {
        protocol,
        executable_fragment,
        keywords: VecDeque::with_capacity(4),
        violation: None,
    };
    scan_sql_reader(std::io::Cursor::new(sql), protocol, &mut observer)
}

pub(super) struct MysqlCommandObserver {
    pub(super) protocol: Protocol,
    pub(super) executable_fragment: bool,
    pub(super) keywords: VecDeque<String>,
    pub(super) violation: Option<MysqlStorageViolation>,
}

impl SqlObserver for MysqlCommandObserver {
    type Error = MysqlCommandPolicyError;

    fn comment(&mut self, comment: &SqlComment) -> Result<(), Self::Error> {
        match executable_mysql_comment(comment)? {
            Some(body) if !is_mysqldump_sandbox_directive(body) => {
                check_shared_mysql_command(body, self.protocol, true)
            }
            _ => Ok(()),
        }
    }

    fn token(&mut self, token: &SqlToken) -> Result<(), Self::Error> {
        let SqlToken::Identifier(word) = token else {
            self.keywords.clear();
            return Ok(());
        };
        if self.keywords.len() == 4 {
            self.keywords.pop_front();
        }
        self.keywords.push_back(word.to_ascii_uppercase());
        self.violation = self
            .violation
            .or_else(|| mysql_keyword_violation(&self.keywords, self.executable_fragment));
        Ok(())
    }

    fn statement(&mut self, _protocol: Protocol, statement: &Statement) -> Result<(), Self::Error> {
        let violation = self
            .violation
            .take()
            .or_else(|| mysql_storage_policy_violation(statement, self.executable_fragment));
        self.keywords.clear();
        match violation {
            Some(MysqlStorageViolation::DynamicSql) => Err(MysqlCommandPolicyError::DynamicSql),
            Some(MysqlStorageViolation::StorageEscape) => {
                Err(MysqlCommandPolicyError::StorageEscape)
            }
            None => Ok(()),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum MysqlStorageViolation {
    StorageEscape,
    DynamicSql,
}

pub(super) fn mysql_keyword_violation(
    keywords: &VecDeque<String>,
    executable_fragment: bool,
) -> Option<MysqlStorageViolation> {
    let last = |offset: usize| {
        keywords
            .len()
            .checked_sub(offset + 1)
            .and_then(|index| keywords.get(index))
            .map(String::as_str)
    };
    let current = last(0)?;
    if current == "PREPARE" || (last(1) == Some("EXECUTE") && current == "IMMEDIATE") {
        return Some(MysqlStorageViolation::DynamicSql);
    }
    if [
        "TABLESPACE",
        "DATAFILE",
        "UNDOFILE",
        "REDOFILE",
        "FILE_NAME",
        "TABLE_TYPE",
        "SECONDARY_ENGINE",
        "ENGINE_ATTRIBUTE",
        "SECONDARY_ENGINE_ATTRIBUTE",
    ]
    .contains(&current)
        || (executable_fragment && ["DATABASE", "SCHEMA", "DIRECTORY"].contains(&current))
        || matches!(
            (last(1), current),
            (
                Some("CREATE" | "ALTER" | "DROP" | "RENAME"),
                "DATABASE" | "SCHEMA"
            ) | (Some("DATA" | "INDEX"), "DIRECTORY")
                | (Some("LOGFILE"), "GROUP")
                | (Some("STORAGE"), "DISK" | "MEMORY")
                | (Some("IMPORT"), "TABLE")
        )
        || (matches!(current, "DATABASE" | "SCHEMA")
            && last(1) == Some("REPLACE")
            && last(2) == Some("OR")
            && last(3) == Some("CREATE"))
    {
        return Some(MysqlStorageViolation::StorageEscape);
    }
    None
}

pub(super) fn executable_mysql_comment(
    comment: &SqlComment,
) -> Result<Option<&[u8]>, ExecutableCommentTooLarge> {
    let trimmed = trim_leading(&comment.bytes, u8::is_ascii_whitespace);
    let Some(body) = trimmed
        .strip_prefix(b"!")
        .or_else(|| trimmed.strip_prefix(b"M!"))
        .or_else(|| trimmed.strip_prefix(b"m!"))
    else {
        return Ok(None);
    };
    if comment.truncated {
        return Err(ExecutableCommentTooLarge);
    }
    let body = trim_leading(body, u8::is_ascii_whitespace);
    let without_version = trim_leading(body, u8::is_ascii_digit);
    Ok(Some(trim_leading(without_version, u8::is_ascii_whitespace)))
}

pub(super) fn trim_leading(bytes: &[u8], mut skip: impl FnMut(&u8) -> bool) -> &[u8] {
    let skipped = bytes.iter().take_while(|byte| skip(byte)).count();
    &bytes[skipped..]
}

pub(super) fn is_mysqldump_sandbox_directive(body: &[u8]) -> bool {
    body.starts_with(b"\\- enable the sandbox mode")
}

pub(super) fn mysql_storage_policy_violation(
    statement: &Statement,
    executable_fragment: bool,
) -> Option<MysqlStorageViolation> {
    let words = statement_words(statement);
    if has_keyword(&statement.tokens, "PREPARE")
        || has_keyword_sequence(&statement.tokens, &["EXECUTE", "IMMEDIATE"])
    {
        return Some(MysqlStorageViolation::DynamicSql);
    }

    if executable_fragment
        && ["DATABASE", "SCHEMA", "TABLESPACE", "DIRECTORY"]
            .into_iter()
            .any(|keyword| has_keyword(&statement.tokens, keyword))
    {
        return Some(MysqlStorageViolation::StorageEscape);
    }

    // Database aliases are the route boundary. Match token sequences rather
    // than substrings so strings, comments, and quoted identifiers cannot
    // either trigger false positives or hide an executable statement.
    if mysql_database_ddl(statement, &words) {
        return Some(MysqlStorageViolation::StorageEscape);
    }

    if has_keyword(&statement.tokens, "TABLESPACE")
        || has_keyword_sequence(&statement.tokens, &["DATA", "DIRECTORY"])
        || has_keyword_sequence(&statement.tokens, &["INDEX", "DIRECTORY"])
        || has_keyword_sequence(&statement.tokens, &["LOGFILE", "GROUP"])
        || has_keyword_sequence(&statement.tokens, &["STORAGE", "DISK"])
        || has_keyword_sequence(&statement.tokens, &["STORAGE", "MEMORY"])
        || has_keyword_sequence(&statement.tokens, &["IMPORT", "TABLE"])
        || [
            "DATAFILE",
            "UNDOFILE",
            "REDOFILE",
            "FILE_NAME",
            "TABLE_TYPE",
            "SECONDARY_ENGINE",
            "ENGINE_ATTRIBUTE",
            "SECONDARY_ENGINE_ATTRIBUTE",
        ]
        .into_iter()
        .any(|keyword| has_keyword(&statement.tokens, keyword))
    {
        return Some(MysqlStorageViolation::StorageEscape);
    }
    None
}

pub(super) fn mysql_database_ddl(statement: &Statement, words: &[String]) -> bool {
    let Some(command) = words.first() else {
        return false;
    };
    ["DATABASE", "SCHEMA"].into_iter().any(|object| {
        ["CREATE", "ALTER", "DROP", "RENAME"]
            .into_iter()
            .any(|verb| has_keyword_sequence(&statement.tokens, &[verb, object]))
            || (command.eq_ignore_ascii_case("CREATE") && create_object(words) == Some(object))
    })
}

pub(super) fn validate_engine(
    tokens: &[SqlToken],
    allowed: &[&str],
    label: &str,
    observer: &SharedObserver<'_>,
) -> Result<bool, SharedSqlError> {
    let mut depth = 0_usize;
    let mut found = false;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            SqlToken::OpenParen => {
                depth = depth.saturating_add(1);
                continue;
            }
            SqlToken::CloseParen => {
                depth = depth.saturating_sub(1);
                continue;
            }
            _ => {}
        }
        if depth != 0 {
            continue;
        }
        let is_engine_assignment = matches!(token, SqlToken::Identifier(word) if word.eq_ignore_ascii_case("ENGINE"))
            && matches!(tokens.get(index + 1), Some(SqlToken::Equal));
        if !is_engine_assignment {
            continue;
        }
        if found {
            return observer.reject(
                SharedSqlIssue::AmbiguousStatement,
                format!("{label} table declares more than one engine"),
            );
        }
        found = true;
        let Some(SqlToken::Identifier(engine)) = tokens.get(index + 2) else {
            return observer.reject(
                SharedSqlIssue::AmbiguousStatement,
                format!("{label} table engine could not be determined safely"),
            );
        };
        if !allowed
            .iter()
            .any(|allowed| engine.eq_ignore_ascii_case(allowed))
        {
            return observer.reject(
                SharedSqlIssue::ExternalAccess,
                format!("{label} table engine {engine} is not allowed in a shared import"),
            );
        }
    }
    Ok(found)
}
