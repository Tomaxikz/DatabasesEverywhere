use crate::server::monitoring::OperationKind;

const SQL_READ_KEYWORDS: &[&[u8]] = &[b"SELECT", b"SHOW", b"DESCRIBE", b"DESC", b"EXPLAIN"];
const SQL_WRITE_KEYWORDS: &[&[u8]] = &[
    b"INSERT", b"UPDATE", b"DELETE", b"REPLACE", b"MERGE", b"LOAD",
];
const SQL_DDL_KEYWORDS: &[&[u8]] = &[
    b"CREATE",
    b"ALTER",
    b"DROP",
    b"TRUNCATE",
    b"RENAME",
    b"GRANT",
    b"REVOKE",
];

const MONGODB_READ_COMMANDS: &[&[u8]] = &[b"find", b"getMore", b"aggregate", b"count", b"distinct"];
const MONGODB_WRITE_COMMANDS: &[&[u8]] = &[
    b"insert",
    b"update",
    b"delete",
    b"findAndModify",
    b"bulkWrite",
];
const MONGODB_DDL_COMMANDS: &[&[u8]] = &[
    b"create",
    b"drop",
    b"renameCollection",
    b"createIndexes",
    b"dropIndexes",
];
pub(super) const MONGODB_IDENTITY_COMMANDS: &[&[u8]] = &[
    b"saslStart",
    b"saslContinue",
    b"authenticate",
    b"logout",
    b"getnonce",
    b"hello",
    b"isMaster",
    b"ismaster",
    b"$query",
];

pub(super) fn matches_any_ignore_case(word: &[u8], candidates: &[&[u8]]) -> bool {
    candidates
        .iter()
        .any(|candidate| word.eq_ignore_ascii_case(candidate))
}

pub(super) fn classify_sql(sql: &[u8]) -> OperationKind {
    let Some(keyword) = sql_keyword(sql) else {
        return OperationKind::Other;
    };
    if matches_any_ignore_case(keyword, SQL_READ_KEYWORDS) {
        OperationKind::Read
    } else if matches_any_ignore_case(keyword, SQL_WRITE_KEYWORDS) {
        OperationKind::Write
    } else if matches_any_ignore_case(keyword, SQL_DDL_KEYWORDS) {
        OperationKind::Ddl
    } else {
        OperationKind::Other
    }
}

pub(super) fn sql_keyword(mut sql: &[u8]) -> Option<&[u8]> {
    loop {
        let start = sql
            .iter()
            .position(|byte| !byte.is_ascii_whitespace() && *byte != b';')
            .unwrap_or(sql.len());
        sql = &sql[start..];
        if sql.is_empty() {
            return None;
        }
        if sql.starts_with(b"--") || sql.starts_with(b"#") {
            let end = sql.iter().position(|byte| *byte == b'\n')?;
            sql = &sql[end + 1..];
        } else if let Some(comment) = sql.strip_prefix(b"/*") {
            let end = comment.windows(2).position(|window| window == b"*/")?;
            sql = &comment[end + 2..];
        } else {
            let end = sql
                .iter()
                .position(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
                .unwrap_or(sql.len());
            return (end > 0).then_some(&sql[..end]);
        }
    }
}

pub(super) fn classify_mongodb(command: &[u8]) -> OperationKind {
    if matches_any_ignore_case(command, MONGODB_READ_COMMANDS) {
        OperationKind::Read
    } else if matches_any_ignore_case(command, MONGODB_WRITE_COMMANDS) {
        OperationKind::Write
    } else if matches_any_ignore_case(command, MONGODB_DDL_COMMANDS) {
        OperationKind::Ddl
    } else {
        OperationKind::Other
    }
}
