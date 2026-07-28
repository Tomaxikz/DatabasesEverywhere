use std::{
    collections::VecDeque,
    io::{self, BufWriter, Read, Write},
    path::Path,
};

use crate::api::api_response::ApiError;

const MAX_QUOTED_IDENTIFIER_BYTES: usize = 1024;
const MAX_QUALIFIER_GAP_BYTES: usize = 64 * 1024;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;

/// Safely rebases MySQL/MariaDB schema-qualified object references in place.
///
/// The input is parsed as bytes so dump contents do not need to be UTF-8. Replacement is
/// performed through a private file in the same directory and committed with one durable
/// rename. The original path is never followed when it is a symlink. Both the observed input
/// length and the rewritten output are capped by `max_staged_bytes`, including file growth that
/// happens after the initial metadata check.
pub(super) async fn rewrite_mysql_schema_qualifiers(
    path: &Path,
    source_database: &str,
    target_database: &str,
    max_staged_bytes: u64,
) -> Result<(), ApiError> {
    rewrite_schema_qualifiers(path, source_database, target_database, max_staged_bytes, 64).await
}

pub(super) async fn rewrite_clickhouse_schema_qualifiers(
    path: &Path,
    source_database: &str,
    target_database: &str,
    max_staged_bytes: u64,
) -> Result<(), ApiError> {
    rewrite_schema_qualifiers(
        path,
        source_database,
        target_database,
        max_staged_bytes,
        128,
    )
    .await
}

async fn rewrite_schema_qualifiers(
    path: &Path,
    source_database: &str,
    target_database: &str,
    max_staged_bytes: u64,
    max_database_chars: usize,
) -> Result<(), ApiError> {
    validate_database_name_with_limit(source_database, "source database", max_database_chars)
        .map_err(rewrite_api_error)?;
    validate_database_name_with_limit(target_database, "target database", max_database_chars)
        .map_err(rewrite_api_error)?;
    if source_database == target_database {
        return Ok(());
    }

    let path = path.to_path_buf();
    let source_database = source_database.as_bytes().to_vec();
    let quoted_target_database = quote_identifier(target_database.as_bytes(), b'`');
    let double_quoted_target_database = quote_identifier(target_database.as_bytes(), b'"');
    tokio::task::spawn_blocking(move || {
        rewrite_mysql_schema_qualifiers_atomic(
            &path,
            &source_database,
            &quoted_target_database,
            &double_quoted_target_database,
            max_staged_bytes,
        )
    })
    .await
    .map_err(|error| {
        ApiError::Runtime(format!(
            "mysql schema qualifier rewrite worker failed: {error}"
        ))
    })?
    .map(|_| ())
    .map_err(rewrite_api_error)
}

fn rewrite_api_error(error: MysqlSqlRewriteError) -> ApiError {
    match error {
        MysqlSqlRewriteError::InvalidDatabaseName { .. }
        | MysqlSqlRewriteError::InputLimit { .. }
        | MysqlSqlRewriteError::OutputLimit { .. }
        | MysqlSqlRewriteError::Malformed(_) => {
            ApiError::BadRequest(format!("SQL dump cannot be safely rebased: {error}"))
        }
        MysqlSqlRewriteError::Io(error) => {
            ApiError::Runtime(format!("failed to rewrite SQL dump safely: {error}"))
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum MysqlSqlRewriteError {
    #[error("{field} is not a valid database identifier")]
    InvalidDatabaseName { field: &'static str },
    #[error("SQL dump exceeds the {limit}-byte input limit")]
    InputLimit { limit: u64 },
    #[error("rewritten SQL dump exceeds the {limit}-byte output limit")]
    OutputLimit { limit: u64 },
    #[error("malformed SQL dump: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
fn validate_database_name(database: &str, field: &'static str) -> Result<(), MysqlSqlRewriteError> {
    validate_database_name_with_limit(database, field, 64)
}

fn validate_database_name_with_limit(
    database: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), MysqlSqlRewriteError> {
    if database.is_empty()
        || database.chars().count() > max_chars
        || database
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(MysqlSqlRewriteError::InvalidDatabaseName { field });
    }
    Ok(())
}

fn quote_identifier(identifier: &[u8], quote: u8) -> Vec<u8> {
    let escaped_quotes = identifier.iter().filter(|byte| **byte == quote).count();
    let mut quoted = Vec::with_capacity(identifier.len() + escaped_quotes + 2);
    quoted.push(quote);
    for byte in identifier {
        quoted.push(*byte);
        if *byte == quote {
            quoted.push(quote);
        }
    }
    quoted.push(quote);
    quoted
}

#[cfg(unix)]
fn rewrite_mysql_schema_qualifiers_atomic(
    path: &Path,
    source_database: &[u8],
    quoted_target_database: &[u8],
    double_quoted_target_database: &[u8],
    max_bytes: u64,
) -> Result<u64, MysqlSqlRewriteError> {
    use std::fs::File;

    use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "mysql dump path has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "mysql dump path has no file name",
        )
    })?;
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let source_descriptor = rustix::fs::openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let mut source = File::from(source_descriptor);
    let source_metadata = source.metadata()?;
    if !source_metadata.is_file() {
        return Err(MysqlSqlRewriteError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mysql dump is not a regular file",
        )));
    }
    if source_metadata.len() > max_bytes {
        return Err(MysqlSqlRewriteError::InputLimit { limit: max_bytes });
    }

    let temporary_name = format!(".mysql-schema-rewrite-{}.tmp", uuid::Uuid::new_v4());
    let temporary_descriptor = rustix::fs::openat(
        &directory,
        temporary_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(io::Error::from)?;
    let mut temporary = File::from(temporary_descriptor);

    let rewrite_result = (|| {
        let replacements = {
            let mut input = BoundedInput::new(&mut source, max_bytes);
            let mut output = BoundedOutput::new(&mut temporary, max_bytes);
            let mut context = SqlContext::default();
            let identifiers = RewriteIdentifiers {
                source_database,
                quoted_target_database,
                double_quoted_target_database,
            };
            let replacements =
                rewrite_sql(&mut input, &mut output, &identifiers, &mut context, false)?;
            output.flush()?;
            replacements
        };
        rustix::fs::fchmod(&temporary, Mode::RUSR | Mode::WUSR).map_err(io::Error::from)?;
        temporary.sync_all()?;
        Ok(replacements)
    })();

    drop(source);
    drop(temporary);

    let replacements = match rewrite_result {
        Ok(replacements) => replacements,
        Err(error) => {
            let _ = rustix::fs::unlinkat(&directory, temporary_name.as_str(), AtFlags::empty());
            return Err(error);
        }
    };

    if let Err(error) = rustix::fs::renameat_with(
        &directory,
        temporary_name.as_str(),
        &directory,
        file_name,
        RenameFlags::empty(),
    ) {
        let _ = rustix::fs::unlinkat(&directory, temporary_name.as_str(), AtFlags::empty());
        return Err(MysqlSqlRewriteError::Io(io::Error::from(error)));
    }
    sync_directory(&directory)?;
    Ok(replacements)
}

#[cfg(not(unix))]
fn rewrite_mysql_schema_qualifiers_atomic(
    _path: &Path,
    _source_database: &[u8],
    _quoted_target_database: &[u8],
    _double_quoted_target_database: &[u8],
    _max_bytes: u64,
) -> Result<u64, MysqlSqlRewriteError> {
    Err(MysqlSqlRewriteError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "safe mysql dump replacement is only available on Unix",
    )))
}

#[cfg(unix)]
fn sync_directory(directory: &impl std::os::fd::AsFd) -> Result<(), MysqlSqlRewriteError> {
    match rustix::fs::fsync(directory) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP) => Ok(()),
        Err(error) => Err(MysqlSqlRewriteError::Io(io::Error::from(error))),
    }
}

struct BoundedInput<R> {
    reader: R,
    buffer: Box<[u8]>,
    start: usize,
    end: usize,
    lookahead: VecDeque<u8>,
    bytes_read: u64,
    max_bytes: u64,
}

impl<R: Read> BoundedInput<R> {
    fn new(reader: R, max_bytes: u64) -> Self {
        Self {
            reader,
            buffer: vec![0; STREAM_BUFFER_BYTES].into_boxed_slice(),
            start: 0,
            end: 0,
            lookahead: VecDeque::with_capacity(4),
            bytes_read: 0,
            max_bytes,
        }
    }

    fn available(&mut self) -> Result<&[u8], MysqlSqlRewriteError> {
        if !self.lookahead.is_empty() {
            return Ok(self.lookahead.as_slices().0);
        }
        self.fill_buffer()?;
        Ok(&self.buffer[self.start..self.end])
    }

    fn consume(&mut self, length: usize) {
        if !self.lookahead.is_empty() {
            debug_assert!(length <= self.lookahead.as_slices().0.len());
            for _ in 0..length {
                let _ = self.lookahead.pop_front();
            }
        } else {
            debug_assert!(length <= self.end - self.start);
            self.start += length;
        }
    }

    fn next_byte(&mut self) -> Result<Option<u8>, MysqlSqlRewriteError> {
        if let Some(byte) = self.lookahead.pop_front() {
            return Ok(Some(byte));
        }
        self.next_buffer_byte()
    }

    fn next_buffer_byte(&mut self) -> Result<Option<u8>, MysqlSqlRewriteError> {
        self.fill_buffer()?;
        if self.start == self.end {
            return Ok(None);
        }
        let byte = self.buffer[self.start];
        self.start += 1;
        Ok(Some(byte))
    }

    fn peek_byte(&mut self) -> Result<Option<u8>, MysqlSqlRewriteError> {
        self.peek_nth_byte(0)
    }

    fn peek_nth_byte(&mut self, index: usize) -> Result<Option<u8>, MysqlSqlRewriteError> {
        while self.lookahead.len() <= index {
            let Some(byte) = self.next_buffer_byte()? else {
                return Ok(None);
            };
            self.lookahead.push_back(byte);
        }
        Ok(self.lookahead.get(index).copied())
    }

    fn fill_buffer(&mut self) -> Result<(), MysqlSqlRewriteError> {
        if self.start < self.end {
            return Ok(());
        }
        self.start = 0;
        self.end = 0;

        let remaining = self.max_bytes.saturating_sub(self.bytes_read);
        let requested = if remaining >= self.buffer.len() as u64 {
            self.buffer.len()
        } else {
            usize::try_from(remaining)
                .unwrap_or(self.buffer.len() - 1)
                .saturating_add(1)
                .min(self.buffer.len())
        };
        let read = loop {
            match self.reader.read(&mut self.buffer[..requested]) {
                Ok(read) => break read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(MysqlSqlRewriteError::Io(error)),
            }
        };
        if u64::try_from(read).unwrap_or(u64::MAX) > remaining {
            return Err(MysqlSqlRewriteError::InputLimit {
                limit: self.max_bytes,
            });
        }
        self.bytes_read += u64::try_from(read).unwrap_or(u64::MAX);
        self.end = read;
        Ok(())
    }
}

struct BoundedOutput<W: Write> {
    writer: BufWriter<W>,
    bytes_written: u64,
    max_bytes: u64,
}

impl<W: Write> BoundedOutput<W> {
    fn new(writer: W, max_bytes: u64) -> Self {
        Self {
            writer: BufWriter::with_capacity(STREAM_BUFFER_BYTES, writer),
            bytes_written: 0,
            max_bytes,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), MysqlSqlRewriteError> {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let new_length =
            self.bytes_written
                .checked_add(length)
                .ok_or(MysqlSqlRewriteError::OutputLimit {
                    limit: self.max_bytes,
                })?;
        if new_length > self.max_bytes {
            return Err(MysqlSqlRewriteError::OutputLimit {
                limit: self.max_bytes,
            });
        }
        self.writer.write_all(bytes)?;
        self.bytes_written = new_length;
        Ok(())
    }

    fn write_byte(&mut self, byte: u8) -> Result<(), MysqlSqlRewriteError> {
        self.write_bytes(&[byte])
    }

    fn flush(&mut self) -> Result<(), MysqlSqlRewriteError> {
        self.writer.flush()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum StatementKind {
    #[default]
    Unknown,
    Create,
    Drop,
    Alter,
    Truncate,
    Rename,
    Lock,
    Insert,
    Replace,
    Update,
    Call,
    Load,
    Other,
}

#[derive(Default)]
struct SqlContext {
    statement: StatementKind,
    object_expected: bool,
    create_trigger: bool,
    trigger_on_seen: bool,
    table_list: bool,
    parenthesis_depth: usize,
    from_table_list_depths: Vec<usize>,
}

impl SqlContext {
    fn observe_word(&mut self, word: &[u8]) {
        if word.eq_ignore_ascii_case(b"BEGIN")
            || word.eq_ignore_ascii_case(b"THEN")
            || word.eq_ignore_ascii_case(b"ELSE")
            || word.eq_ignore_ascii_case(b"DO")
            || word.eq_ignore_ascii_case(b"LOOP")
            || word.eq_ignore_ascii_case(b"REPEAT")
            || word.eq_ignore_ascii_case(b"ROW") && self.create_trigger && self.trigger_on_seen
        {
            self.statement = StatementKind::Unknown;
            self.object_expected = false;
            self.table_list = false;
            self.from_table_list_depths.clear();
            if word.eq_ignore_ascii_case(b"ROW") || word.eq_ignore_ascii_case(b"BEGIN") {
                self.create_trigger = false;
            }
            return;
        }
        if is_from_clause_boundary(word) {
            self.from_table_list_depths
                .retain(|depth| *depth != self.parenthesis_depth);
        }
        if self.object_expected && is_object_modifier(word) {
            return;
        }
        self.object_expected = false;
        if self.statement == StatementKind::Unknown {
            self.statement = statement_kind(word);
        }
        let ddl = matches!(
            self.statement,
            StatementKind::Create
                | StatementKind::Drop
                | StatementKind::Alter
                | StatementKind::Truncate
                | StatementKind::Rename
        );

        let from_or_join = word.eq_ignore_ascii_case(b"FROM") || word.eq_ignore_ascii_case(b"JOIN");
        if from_or_join || word.eq_ignore_ascii_case(b"REFERENCES") {
            self.object_expected = true;
            if from_or_join
                && self.from_table_list_depths.last().copied() != Some(self.parenthesis_depth)
            {
                self.from_table_list_depths.push(self.parenthesis_depth);
            }
        } else if (word.eq_ignore_ascii_case(b"INTO")
            && matches!(
                self.statement,
                StatementKind::Insert | StatementKind::Replace | StatementKind::Load
            ))
            || (word.eq_ignore_ascii_case(b"UPDATE") && self.statement == StatementKind::Update)
        {
            self.object_expected = true;
        } else if (word.eq_ignore_ascii_case(b"TABLE") || word.eq_ignore_ascii_case(b"TABLES"))
            && (ddl || self.statement == StatementKind::Lock)
        {
            self.object_expected = true;
            self.table_list = matches!(self.statement, StatementKind::Rename | StatementKind::Lock);
        } else if word.eq_ignore_ascii_case(b"TO")
            && self.statement == StatementKind::Rename
            && self.table_list
        {
            self.object_expected = true;
        } else if (word.eq_ignore_ascii_case(b"VIEW")
            || word.eq_ignore_ascii_case(b"EVENT")
            || word.eq_ignore_ascii_case(b"PROCEDURE")
            || word.eq_ignore_ascii_case(b"FUNCTION"))
            && ddl
            || word.eq_ignore_ascii_case(b"CALL")
        {
            self.object_expected = true;
        } else if word.eq_ignore_ascii_case(b"TRIGGER") && ddl {
            self.object_expected = true;
            self.create_trigger = self.statement == StatementKind::Create;
        } else if word.eq_ignore_ascii_case(b"ON") && self.create_trigger && !self.trigger_on_seen {
            self.object_expected = true;
            self.trigger_on_seen = true;
        }
    }

    fn observe_identifier_or_value(&mut self) {
        self.object_expected = false;
    }

    fn observe_punctuation(&mut self, byte: u8) {
        if byte == b';' {
            *self = Self::default();
        } else if byte == b'(' {
            self.parenthesis_depth = self.parenthesis_depth.saturating_add(1);
            self.object_expected = false;
        } else if byte == b')' {
            self.parenthesis_depth = self.parenthesis_depth.saturating_sub(1);
            self.from_table_list_depths
                .retain(|depth| *depth <= self.parenthesis_depth);
            self.object_expected = false;
        } else if byte == b','
            && (self.table_list
                || self.from_table_list_depths.last().copied() == Some(self.parenthesis_depth))
        {
            self.object_expected = true;
        } else if !byte.is_ascii_whitespace() {
            self.object_expected = false;
        }
    }
}

fn statement_kind(word: &[u8]) -> StatementKind {
    [
        (b"CREATE".as_slice(), StatementKind::Create),
        (b"DROP".as_slice(), StatementKind::Drop),
        (b"ALTER".as_slice(), StatementKind::Alter),
        (b"TRUNCATE".as_slice(), StatementKind::Truncate),
        (b"RENAME".as_slice(), StatementKind::Rename),
        (b"LOCK".as_slice(), StatementKind::Lock),
        (b"INSERT".as_slice(), StatementKind::Insert),
        (b"REPLACE".as_slice(), StatementKind::Replace),
        (b"UPDATE".as_slice(), StatementKind::Update),
        (b"CALL".as_slice(), StatementKind::Call),
        (b"LOAD".as_slice(), StatementKind::Load),
    ]
    .into_iter()
    .find_map(|(keyword, kind)| word.eq_ignore_ascii_case(keyword).then_some(kind))
    .unwrap_or(StatementKind::Other)
}

fn is_object_modifier(word: &[u8]) -> bool {
    word.eq_ignore_ascii_case(b"IF")
        || word.eq_ignore_ascii_case(b"NOT")
        || word.eq_ignore_ascii_case(b"EXISTS")
        || word.eq_ignore_ascii_case(b"ONLY")
}

fn is_from_clause_boundary(word: &[u8]) -> bool {
    word.eq_ignore_ascii_case(b"ON")
        || word.eq_ignore_ascii_case(b"USING")
        || word.eq_ignore_ascii_case(b"WHERE")
        || word.eq_ignore_ascii_case(b"GROUP")
        || word.eq_ignore_ascii_case(b"HAVING")
        || word.eq_ignore_ascii_case(b"ORDER")
        || word.eq_ignore_ascii_case(b"LIMIT")
        || word.eq_ignore_ascii_case(b"UNION")
        || word.eq_ignore_ascii_case(b"EXCEPT")
        || word.eq_ignore_ascii_case(b"INTERSECT")
        || word.eq_ignore_ascii_case(b"WINDOW")
        || word.eq_ignore_ascii_case(b"QUALIFY")
        || word.eq_ignore_ascii_case(b"INTO")
        || word.eq_ignore_ascii_case(b"FOR")
        || word.eq_ignore_ascii_case(b"LOCK")
        || word.eq_ignore_ascii_case(b"PROCEDURE")
}

struct RewriteIdentifiers<'a> {
    source_database: &'a [u8],
    quoted_target_database: &'a [u8],
    double_quoted_target_database: &'a [u8],
}

fn rewrite_sql<R: Read, W: Write>(
    input: &mut BoundedInput<R>,
    output: &mut BoundedOutput<W>,
    identifiers: &RewriteIdentifiers<'_>,
    context: &mut SqlContext,
    executable_comment: bool,
) -> Result<u64, MysqlSqlRewriteError> {
    let mut replacements = 0_u64;
    let mut executable_version_pending = executable_comment;
    loop {
        let (special, available_length) = {
            let available = input.available()?;
            (find_normal_special(available), available.len())
        };
        if available_length == 0 {
            return if executable_comment {
                Err(MysqlSqlRewriteError::Malformed(
                    "unterminated executable comment",
                ))
            } else {
                Ok(replacements)
            };
        }
        match special {
            Some(index) if index > 0 => {
                if executable_version_pending {
                    let available = input.available()?;
                    if available[..index]
                        .iter()
                        .any(|byte| !byte.is_ascii_whitespace())
                    {
                        executable_version_pending = false;
                    }
                }
                copy_normal_prefix(input, output, context, index)?;
                continue;
            }
            None => {
                if executable_version_pending {
                    let available = input.available()?;
                    if available[..available_length]
                        .iter()
                        .any(|byte| !byte.is_ascii_whitespace())
                    {
                        executable_version_pending = false;
                    }
                }
                copy_normal_prefix(input, output, context, available_length)?;
                continue;
            }
            Some(_) => {}
        }

        let byte = input
            .next_byte()?
            .expect("a special byte must remain available");
        match byte {
            b'\'' => {
                executable_version_pending = false;
                output.write_byte(byte)?;
                copy_quoted_string(input, output, byte, executable_comment)?;
                context.observe_identifier_or_value();
            }
            b'"' => {
                executable_version_pending = false;
                replacements += handle_double_quoted_token(
                    input,
                    output,
                    identifiers.source_database,
                    identifiers.double_quoted_target_database,
                    context,
                    executable_comment,
                )?;
            }
            b'`' => {
                executable_version_pending = false;
                let identifier = read_delimited_identifier(input, b'`', executable_comment)?;
                if identifier.decoded.as_slice() == identifiers.source_database {
                    replacements += handle_source_qualifier(
                        input,
                        output,
                        &identifier.raw,
                        identifiers.quoted_target_database,
                        SourceTokenKind::Quoted,
                        context,
                        executable_comment,
                    )?;
                } else {
                    output.write_bytes(&identifier.raw)?;
                    context.observe_identifier_or_value();
                }
            }
            byte if is_unquoted_identifier_byte(byte) => {
                replacements += handle_unquoted_token(
                    input,
                    output,
                    byte,
                    identifiers,
                    context,
                    executable_comment,
                    executable_version_pending,
                )?;
                executable_version_pending = false;
            }
            b'#' => {
                executable_version_pending = false;
                output.write_byte(byte)?;
                copy_line_comment(input, output, executable_comment)?;
            }
            b'-' => {
                executable_version_pending = false;
                output.write_byte(byte)?;
                if input.peek_byte()? == Some(b'-') {
                    let _ = input.next_byte()?;
                    output.write_byte(b'-')?;
                    let starts_comment = input
                        .peek_byte()?
                        .is_none_or(|next| next.is_ascii_whitespace() || next.is_ascii_control());
                    if starts_comment {
                        copy_line_comment(input, output, executable_comment)?;
                    } else {
                        context.observe_punctuation(b'-');
                        context.observe_punctuation(b'-');
                    }
                } else {
                    context.observe_punctuation(b'-');
                }
            }
            b'/' => {
                executable_version_pending = false;
                output.write_byte(byte)?;
                if input.peek_byte()? != Some(b'*') {
                    context.observe_punctuation(byte);
                    continue;
                }
                let _ = input.next_byte()?;
                output.write_byte(b'*')?;
                if executable_comment {
                    return Err(MysqlSqlRewriteError::Malformed(
                        "nested block comment inside executable comment",
                    ));
                }
                let is_executable = if input.peek_byte()? == Some(b'!') {
                    let _ = input.next_byte()?;
                    output.write_byte(b'!')?;
                    true
                } else if input.peek_byte()? == Some(b'M') && input.peek_nth_byte(1)? == Some(b'!')
                {
                    let _ = input.next_byte()?;
                    let _ = input.next_byte()?;
                    output.write_bytes(b"M!")?;
                    true
                } else {
                    false
                };
                if is_executable {
                    replacements += rewrite_sql(input, output, identifiers, context, true)?;
                } else {
                    copy_block_comment(input, output)?;
                }
            }
            b'*' => {
                if input.peek_byte()? == Some(b'/') {
                    let _ = input.next_byte()?;
                    if !executable_comment {
                        return Err(MysqlSqlRewriteError::Malformed(
                            "unexpected block comment terminator",
                        ));
                    }
                    output.write_bytes(b"*/")?;
                    return Ok(replacements);
                }
                output.write_byte(byte)?;
                context.observe_punctuation(byte);
            }
            _ => unreachable!("normal scanner returned a non-special byte"),
        }
    }
}

fn copy_available_prefix<R: Read, W: Write>(
    input: &mut BoundedInput<R>,
    output: &mut BoundedOutput<W>,
    length: usize,
) -> Result<(), MysqlSqlRewriteError> {
    {
        let available = input.available()?;
        output.write_bytes(&available[..length])?;
    }
    input.consume(length);
    Ok(())
}

fn copy_normal_prefix<R: Read, W: Write>(
    input: &mut BoundedInput<R>,
    output: &mut BoundedOutput<W>,
    context: &mut SqlContext,
    length: usize,
) -> Result<(), MysqlSqlRewriteError> {
    {
        let available = input.available()?;
        for byte in &available[..length] {
            context.observe_punctuation(*byte);
        }
        output.write_bytes(&available[..length])?;
    }
    input.consume(length);
    Ok(())
}

fn find_normal_special(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|byte| {
        matches!(*byte, b'\'' | b'"' | b'`' | b'/' | b'-' | b'#' | b'*')
            || is_unquoted_identifier_byte(*byte)
    })
}

fn is_unquoted_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$') || byte >= 0x80
}

fn handle_unquoted_token<R: Read, W: Write>(
    input: &mut BoundedInput<R>,
    output: &mut BoundedOutput<W>,
    first_byte: u8,
    identifiers: &RewriteIdentifiers<'_>,
    context: &mut SqlContext,
    executable_comment: bool,
    executable_version_pending: bool,
) -> Result<u64, MysqlSqlRewriteError> {
    let mut token = Vec::with_capacity(32);
    token.push(first_byte);
    while input.peek_byte()?.is_some_and(is_unquoted_identifier_byte) {
        if token.len() >= MAX_QUOTED_IDENTIFIER_BYTES {
            output.write_bytes(&token)?;
            copy_unquoted_token_remainder(input, output)?;
            context.observe_identifier_or_value();
            return Ok(0);
        }
        token.push(
            input
                .next_byte()?
                .expect("peek confirmed an unquoted token byte"),
        );
    }

    if executable_version_pending && token.iter().all(|byte| byte.is_ascii_digit()) {
        output.write_bytes(&token)?;
        return Ok(0);
    }
    if token.as_slice() == identifiers.source_database {
        handle_source_qualifier(
            input,
            output,
            &token,
            identifiers.quoted_target_database,
            SourceTokenKind::Unquoted,
            context,
            executable_comment,
        )
    } else {
        output.write_bytes(&token)?;
        context.observe_word(&token);
        Ok(0)
    }
}

fn copy_unquoted_token_remainder<R: Read, W: Write>(
    input: &mut BoundedInput<R>,
    output: &mut BoundedOutput<W>,
) -> Result<(), MysqlSqlRewriteError> {
    loop {
        let (end, available_length) = {
            let available = input.available()?;
            (
                available
                    .iter()
                    .position(|byte| !is_unquoted_identifier_byte(*byte)),
                available.len(),
            )
        };
        match end {
            Some(0) => return Ok(()),
            Some(index) => {
                copy_available_prefix(input, output, index)?;
                return Ok(());
            }
            None if available_length == 0 => return Ok(()),
            None => copy_available_prefix(input, output, available_length)?,
        }
    }
}

fn handle_double_quoted_token<R: Read, W: Write>(
    input: &mut BoundedInput<R>,
    output: &mut BoundedOutput<W>,
    source_database: &[u8],
    double_quoted_target_database: &[u8],
    context: &mut SqlContext,
    executable_comment: bool,
) -> Result<u64, MysqlSqlRewriteError> {
    let mut raw = vec![b'"'];
    let mut decoded = Vec::with_capacity(source_database.len());
    loop {
        let byte = input.next_byte()?.ok_or(MysqlSqlRewriteError::Malformed(
            "unterminated double-quoted token",
        ))?;
        if executable_comment && byte == b'*' && input.peek_byte()? == Some(b'/') {
            return Err(MysqlSqlRewriteError::Malformed(
                "executable comment terminator inside quoted string",
            ));
        }
        push_token_byte(&mut raw, byte)?;
        if byte == b'\\' {
            if source_database.get(decoded.len()) == Some(&b'\\') {
                return Err(MysqlSqlRewriteError::Malformed(
                    "ambiguous backslash in possible ANSI-quoted source qualifier",
                ));
            }
            let escaped = input.next_byte()?.ok_or(MysqlSqlRewriteError::Malformed(
                "double-quoted string ends after an escape byte",
            ))?;
            push_token_byte(&mut raw, escaped)?;
            output.write_bytes(&raw)?;
            copy_quoted_string(input, output, b'"', executable_comment)?;
            context.observe_identifier_or_value();
            return Ok(0);
        }
        if byte == b'"' {
            if input.peek_byte()? == Some(b'"') {
                let _ = input.next_byte()?;
                push_token_byte(&mut raw, b'"')?;
                push_token_byte(&mut decoded, b'"')?;
            } else if decoded.as_slice() == source_database {
                return handle_source_qualifier(
                    input,
                    output,
                    &raw,
                    double_quoted_target_database,
                    SourceTokenKind::DoubleQuoted,
                    context,
                    executable_comment,
                );
            } else {
                output.write_bytes(&raw)?;
                context.observe_identifier_or_value();
                return Ok(0);
            }
        } else {
            push_token_byte(&mut decoded, byte)?;
        }

        if !source_database.starts_with(&decoded) {
            output.write_bytes(&raw)?;
            copy_quoted_string(input, output, b'"', executable_comment)?;
            context.observe_identifier_or_value();
            return Ok(0);
        }
    }
}

#[derive(Clone, Copy)]
enum SourceTokenKind {
    Unquoted,
    Quoted,
    DoubleQuoted,
}

fn handle_source_qualifier<R: Read, W: Write>(
    input: &mut BoundedInput<R>,
    output: &mut BoundedOutput<W>,
    raw_source: &[u8],
    replacement: &[u8],
    source_kind: SourceTokenKind,
    context: &mut SqlContext,
    executable_comment: bool,
) -> Result<u64, MysqlSqlRewriteError> {
    let safe_two_part_context = context.object_expected;
    let before_dot = read_qualifier_gap(input, executable_comment)?;
    if input.peek_byte()? != Some(b'.') {
        output.write_bytes(raw_source)?;
        output.write_bytes(&before_dot)?;
        observe_unqualified_source(context, source_kind, raw_source);
        return Ok(0);
    }
    let _ = input.next_byte()?;
    let after_dot = read_qualifier_gap(input, executable_comment)?;
    let second = read_qualified_identifier(input, executable_comment)?.ok_or(
        MysqlSqlRewriteError::Malformed(
            "source qualifier dot is not followed by a supported identifier",
        ),
    )?;
    let after_second = read_qualifier_gap(input, executable_comment)?;

    let mut third_separator = None;
    let is_three_part = input.peek_byte()? == Some(b'.');
    if is_three_part {
        if second.is_star {
            return Err(MysqlSqlRewriteError::Malformed(
                "wildcard cannot be the middle of a three-part source qualifier",
            ));
        }
        let _ = input.next_byte()?;
        let gap = read_qualifier_gap(input, executable_comment)?;
        if !input
            .peek_byte()?
            .is_some_and(is_qualified_identifier_start)
        {
            return Err(MysqlSqlRewriteError::Malformed(
                "three-part source qualifier has no final identifier",
            ));
        }
        third_separator = Some(gap);
    }
    let is_function = !is_three_part && input.peek_byte()? == Some(b'(');
    if !is_three_part && !is_function && (!safe_two_part_context || second.is_star) {
        return Err(MysqlSqlRewriteError::Malformed(
            "ambiguous source-prefixed two-part identifier could be an alias or column reference",
        ));
    }

    output.write_bytes(replacement)?;
    output.write_bytes(&before_dot)?;
    output.write_byte(b'.')?;
    output.write_bytes(&after_dot)?;
    output.write_bytes(&second.raw)?;
    output.write_bytes(&after_second)?;
    if let Some(gap) = third_separator {
        output.write_byte(b'.')?;
        output.write_bytes(&gap)?;
    }
    context.observe_identifier_or_value();
    Ok(1)
}

fn observe_unqualified_source(
    context: &mut SqlContext,
    source_kind: SourceTokenKind,
    raw_source: &[u8],
) {
    match source_kind {
        SourceTokenKind::Unquoted => context.observe_word(raw_source),
        SourceTokenKind::Quoted | SourceTokenKind::DoubleQuoted => {
            context.observe_identifier_or_value();
        }
    }
}

struct QualifiedIdentifier {
    raw: Vec<u8>,
    is_star: bool,
}

fn read_qualified_identifier<R: Read>(
    input: &mut BoundedInput<R>,
    executable_comment: bool,
) -> Result<Option<QualifiedIdentifier>, MysqlSqlRewriteError> {
    match input.peek_byte()? {
        Some(b'`') | Some(b'"') => {
            let quote = input
                .next_byte()?
                .expect("peek confirmed a quoted identifier");
            let identifier = read_delimited_identifier(input, quote, executable_comment)?;
            Ok(Some(QualifiedIdentifier {
                raw: identifier.raw,
                is_star: false,
            }))
        }
        Some(b'*') => {
            let _ = input.next_byte()?;
            Ok(Some(QualifiedIdentifier {
                raw: vec![b'*'],
                is_star: true,
            }))
        }
        Some(byte) if is_unquoted_identifier_byte(byte) => {
            let mut raw = Vec::with_capacity(32);
            while input.peek_byte()?.is_some_and(is_unquoted_identifier_byte) {
                if raw.len() >= MAX_QUOTED_IDENTIFIER_BYTES {
                    return Err(MysqlSqlRewriteError::Malformed(
                        "unquoted identifier in source qualifier exceeds the token limit",
                    ));
                }
                raw.push(
                    input
                        .next_byte()?
                        .expect("peek confirmed an unquoted identifier byte"),
                );
            }
            Ok(Some(QualifiedIdentifier {
                raw,
                is_star: false,
            }))
        }
        _ => Ok(None),
    }
}

fn is_qualified_identifier_start(byte: u8) -> bool {
    matches!(byte, b'`' | b'"' | b'*') || is_unquoted_identifier_byte(byte)
}

fn read_qualifier_gap<R: Read>(
    input: &mut BoundedInput<R>,
    executable_comment: bool,
) -> Result<Vec<u8>, MysqlSqlRewriteError> {
    let mut gap = Vec::new();
    loop {
        match input.peek_byte()? {
            Some(byte) if byte.is_ascii_whitespace() => {
                let byte = input.next_byte()?.expect("peek confirmed whitespace");
                push_gap_byte(&mut gap, byte)?;
            }
            Some(b'#') => {
                push_gap_byte(
                    &mut gap,
                    input.next_byte()?.expect("peek confirmed a hash comment"),
                )?;
                read_gap_line_comment(input, &mut gap, executable_comment)?;
            }
            Some(b'-')
                if input.peek_nth_byte(1)? == Some(b'-')
                    && input.peek_nth_byte(2)?.is_none_or(|next| {
                        next.is_ascii_whitespace() || next.is_ascii_control()
                    }) =>
            {
                push_gap_byte(&mut gap, input.next_byte()?.expect("peek confirmed dash"))?;
                push_gap_byte(&mut gap, input.next_byte()?.expect("peek confirmed dash"))?;
                read_gap_line_comment(input, &mut gap, executable_comment)?;
            }
            Some(b'/') if input.peek_nth_byte(1)? == Some(b'*') => {
                if executable_comment {
                    return Err(MysqlSqlRewriteError::Malformed(
                        "nested block comment inside executable comment",
                    ));
                }
                if input.peek_nth_byte(2)? == Some(b'!')
                    || input.peek_nth_byte(2)? == Some(b'M')
                        && input.peek_nth_byte(3)? == Some(b'!')
                {
                    return Err(MysqlSqlRewriteError::Malformed(
                        "executable comment inside a source qualifier is unsupported",
                    ));
                }
                push_gap_byte(&mut gap, input.next_byte()?.expect("peek confirmed slash"))?;
                push_gap_byte(&mut gap, input.next_byte()?.expect("peek confirmed star"))?;
                read_gap_block_comment(input, &mut gap)?;
            }
            _ => return Ok(gap),
        }
    }
}

fn read_gap_line_comment<R: Read>(
    input: &mut BoundedInput<R>,
    gap: &mut Vec<u8>,
    executable_comment: bool,
) -> Result<(), MysqlSqlRewriteError> {
    loop {
        let byte = match input.next_byte()? {
            Some(byte) => byte,
            None if executable_comment => {
                return Err(MysqlSqlRewriteError::Malformed(
                    "unterminated executable comment",
                ));
            }
            None => return Ok(()),
        };
        if executable_comment && byte == b'*' && input.peek_byte()? == Some(b'/') {
            return Err(MysqlSqlRewriteError::Malformed(
                "executable comment terminator inside line comment",
            ));
        }
        push_gap_byte(gap, byte)?;
        if byte == b'\n' {
            return Ok(());
        }
    }
}

fn read_gap_block_comment<R: Read>(
    input: &mut BoundedInput<R>,
    gap: &mut Vec<u8>,
) -> Result<(), MysqlSqlRewriteError> {
    loop {
        let byte = input.next_byte()?.ok_or(MysqlSqlRewriteError::Malformed(
            "unterminated block comment in source qualifier",
        ))?;
        push_gap_byte(gap, byte)?;
        if byte == b'*' && input.peek_byte()? == Some(b'/') {
            push_gap_byte(
                gap,
                input
                    .next_byte()?
                    .expect("peek confirmed block comment terminator"),
            )?;
            return Ok(());
        }
    }
}

fn push_gap_byte(gap: &mut Vec<u8>, byte: u8) -> Result<(), MysqlSqlRewriteError> {
    if gap.len() >= MAX_QUALIFIER_GAP_BYTES {
        return Err(MysqlSqlRewriteError::Malformed(
            "source qualifier separators exceed the token limit",
        ));
    }
    gap.push(byte);
    Ok(())
}

fn copy_quoted_string<R: Read, W: Write>(
    input: &mut BoundedInput<R>,
    output: &mut BoundedOutput<W>,
    quote: u8,
    executable_comment: bool,
) -> Result<(), MysqlSqlRewriteError> {
    loop {
        let (special, available_length) = {
            let available = input.available()?;
            let special = available.iter().position(|byte| {
                *byte == quote || *byte == b'\\' || executable_comment && *byte == b'*'
            });
            (special, available.len())
        };
        if available_length == 0 {
            return Err(MysqlSqlRewriteError::Malformed(
                "unterminated quoted string",
            ));
        }
        match special {
            Some(index) if index > 0 => {
                copy_available_prefix(input, output, index)?;
                continue;
            }
            None => {
                copy_available_prefix(input, output, available_length)?;
                continue;
            }
            Some(_) => {}
        }

        let byte = input
            .next_byte()?
            .expect("a quoted-string special byte must remain available");
        match byte {
            b'\\' => {
                output.write_byte(byte)?;
                let escaped = input.next_byte()?.ok_or(MysqlSqlRewriteError::Malformed(
                    "quoted string ends after an escape byte",
                ))?;
                if executable_comment && escaped == b'*' && input.peek_byte()? == Some(b'/') {
                    return Err(MysqlSqlRewriteError::Malformed(
                        "executable comment terminator inside quoted string",
                    ));
                }
                output.write_byte(escaped)?;
            }
            byte if byte == quote => {
                output.write_byte(byte)?;
                if input.peek_byte()? == Some(quote) {
                    let _ = input.next_byte()?;
                    output.write_byte(quote)?;
                } else {
                    return Ok(());
                }
            }
            b'*' => {
                if input.peek_byte()? == Some(b'/') {
                    return Err(MysqlSqlRewriteError::Malformed(
                        "executable comment terminator inside quoted string",
                    ));
                }
                output.write_byte(byte)?;
            }
            _ => unreachable!("quoted-string scanner returned a non-special byte"),
        }
    }
}

struct DelimitedIdentifier {
    raw: Vec<u8>,
    decoded: Vec<u8>,
}

fn read_delimited_identifier<R: Read>(
    input: &mut BoundedInput<R>,
    quote: u8,
    executable_comment: bool,
) -> Result<DelimitedIdentifier, MysqlSqlRewriteError> {
    let mut raw = Vec::with_capacity(64);
    let mut decoded = Vec::with_capacity(64);
    push_token_byte(&mut raw, quote)?;

    loop {
        let byte = input.next_byte()?.ok_or(MysqlSqlRewriteError::Malformed(
            "unterminated quoted identifier",
        ))?;
        if executable_comment && byte == b'*' && input.peek_byte()? == Some(b'/') {
            return Err(MysqlSqlRewriteError::Malformed(
                "executable comment terminator inside quoted identifier",
            ));
        }
        push_token_byte(&mut raw, byte)?;
        if byte != quote {
            push_token_byte(&mut decoded, byte)?;
            continue;
        }
        if input.peek_byte()? == Some(quote) {
            let _ = input.next_byte()?;
            push_token_byte(&mut raw, quote)?;
            push_token_byte(&mut decoded, quote)?;
            continue;
        }
        return Ok(DelimitedIdentifier { raw, decoded });
    }
}

fn push_token_byte(token: &mut Vec<u8>, byte: u8) -> Result<(), MysqlSqlRewriteError> {
    if token.len() >= MAX_QUOTED_IDENTIFIER_BYTES {
        return Err(MysqlSqlRewriteError::Malformed(
            "quoted identifier exceeds the token limit",
        ));
    }
    token.push(byte);
    Ok(())
}

fn copy_line_comment<R: Read, W: Write>(
    input: &mut BoundedInput<R>,
    output: &mut BoundedOutput<W>,
    executable_comment: bool,
) -> Result<(), MysqlSqlRewriteError> {
    loop {
        let (special, available_length) = {
            let available = input.available()?;
            let special = available
                .iter()
                .position(|byte| *byte == b'\n' || executable_comment && *byte == b'*');
            (special, available.len())
        };
        if available_length == 0 {
            return if executable_comment {
                Err(MysqlSqlRewriteError::Malformed(
                    "unterminated executable comment",
                ))
            } else {
                Ok(())
            };
        }
        match special {
            Some(index) if index > 0 => {
                copy_available_prefix(input, output, index)?;
                continue;
            }
            None => {
                copy_available_prefix(input, output, available_length)?;
                continue;
            }
            Some(_) => {}
        }

        let byte = input
            .next_byte()?
            .expect("a line-comment special byte must remain available");
        if byte == b'\n' {
            output.write_byte(byte)?;
            return Ok(());
        }
        if input.peek_byte()? == Some(b'/') {
            return Err(MysqlSqlRewriteError::Malformed(
                "executable comment terminator inside line comment",
            ));
        }
        output.write_byte(byte)?;
    }
}

fn copy_block_comment<R: Read, W: Write>(
    input: &mut BoundedInput<R>,
    output: &mut BoundedOutput<W>,
) -> Result<(), MysqlSqlRewriteError> {
    loop {
        let (star, available_length) = {
            let available = input.available()?;
            (
                available.iter().position(|byte| *byte == b'*'),
                available.len(),
            )
        };
        if available_length == 0 {
            return Err(MysqlSqlRewriteError::Malformed(
                "unterminated block comment",
            ));
        }
        match star {
            Some(index) if index > 0 => {
                copy_available_prefix(input, output, index)?;
                continue;
            }
            None => {
                copy_available_prefix(input, output, available_length)?;
                continue;
            }
            Some(_) => {}
        }

        let _ = input.next_byte()?;
        output.write_byte(b'*')?;
        if input.peek_byte()? == Some(b'/') {
            let _ = input.next_byte()?;
            output.write_byte(b'/')?;
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn rewrite_bytes(
        input: &[u8],
        source_database: &str,
        target_database: &str,
    ) -> Result<Vec<u8>, MysqlSqlRewriteError> {
        rewrite_bytes_with_limit(
            input,
            source_database,
            target_database,
            u64::try_from(input.len())
                .unwrap_or(u64::MAX)
                .saturating_add(4096)
                .max(1),
        )
    }

    fn rewrite_bytes_with_limit(
        input: &[u8],
        source_database: &str,
        target_database: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, MysqlSqlRewriteError> {
        validate_database_name(source_database, "source database")?;
        validate_database_name(target_database, "target database")?;
        if u64::try_from(input.len()).unwrap_or(u64::MAX) > max_bytes {
            return Err(MysqlSqlRewriteError::InputLimit { limit: max_bytes });
        }
        if source_database == target_database {
            return Ok(input.to_vec());
        }
        let mut reader = BoundedInput::new(Cursor::new(input), max_bytes);
        let mut rewritten = Vec::new();
        {
            let mut writer = BoundedOutput::new(&mut rewritten, max_bytes);
            let mut context = SqlContext::default();
            let quoted_target_database = quote_identifier(target_database.as_bytes(), b'`');
            let double_quoted_target_database = quote_identifier(target_database.as_bytes(), b'"');
            let identifiers = RewriteIdentifiers {
                source_database: source_database.as_bytes(),
                quoted_target_database: &quoted_target_database,
                double_quoted_target_database: &double_quoted_target_database,
            };
            rewrite_sql(&mut reader, &mut writer, &identifiers, &mut context, false)?;
            writer.flush()?;
        }
        Ok(rewritten)
    }

    #[test]
    fn rewrites_qualifiers_but_preserves_literals_and_ordinary_comments() {
        let input = br#"INSERT INTO `source_db`.`events` VALUES
  ('`source_db`.`literal`', "a ""`source_db`.`double_literal`"" b", 'it\'s intact');
-- `source_db`.`line_comment`
# `source_db`.`hash_comment`
/* `source_db`.`block_comment` */
SELECT * FROM `source_db`.`real_table`;
"#;
        let expected = br#"INSERT INTO `target_db`.`events` VALUES
  ('`source_db`.`literal`', "a ""`source_db`.`double_literal`"" b", 'it\'s intact');
-- `source_db`.`line_comment`
# `source_db`.`hash_comment`
/* `source_db`.`block_comment` */
SELECT * FROM `target_db`.`real_table`;
"#;

        assert_eq!(
            rewrite_bytes(input, "source_db", "target_db").unwrap(),
            expected
        );
    }

    #[test]
    fn rebases_clickhouse_style_function_and_table_references() {
        let input = br#"CREATE TABLE `items` (`id` UInt64 DEFAULT source_db.normalize(`raw`))
ENGINE = MergeTree ORDER BY id;
INSERT INTO `items` SELECT * FROM source_db.source_items;
SELECT 'source_db.literal';
"#;
        let expected = br#"CREATE TABLE `items` (`id` UInt64 DEFAULT `target_db`.normalize(`raw`))
ENGINE = MergeTree ORDER BY id;
INSERT INTO `items` SELECT * FROM `target_db`.source_items;
SELECT 'source_db.literal';
"#;

        assert_eq!(
            rewrite_bytes(input, "source_db", "target_db").unwrap(),
            expected
        );
        assert!(
            validate_database_name_with_limit(&"a".repeat(128), "source database", 128).is_ok()
        );
        assert!(
            validate_database_name_with_limit(&"a".repeat(129), "source database", 128).is_err()
        );
    }

    #[test]
    fn processes_mysql_executable_comments_without_touching_strings() {
        let input = br#"/*!50003 CREATE*/ /*!50020 DEFINER=`user`@`%` SQL SECURITY DEFINER */
/*!50001 CREATE VIEW `source`.`view_name` AS
SELECT '`source`.`literal`' AS value FROM `source`.`table_name` */;
/* ordinary `source`.`untouched` */
"#;
        let expected = br#"/*!50003 CREATE*/ /*!50020 DEFINER=`user`@`%` SQL SECURITY DEFINER */
/*!50001 CREATE VIEW `target`.`view_name` AS
SELECT '`source`.`literal`' AS value FROM `target`.`table_name` */;
/* ordinary `source`.`untouched` */
"#;

        assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
    }

    #[test]
    fn processes_mariadb_executable_comments() {
        let input = br#"/*M!100100 CREATE VIEW source . "view_name" AS
SELECT * FROM `source`   . table_name */;
"#;
        let expected = br#"/*M!100100 CREATE VIEW `target` . "view_name" AS
SELECT * FROM `target`   . table_name */;
"#;

        assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
    }

    #[test]
    fn handles_routines_delimiters_and_doubled_string_quotes() {
        let input = br#"DELIMITER ;;
CREATE PROCEDURE `source`.`refresh_data`()
BEGIN
  SET @sql = 'SELECT ''`source`.`not_code`''';
  INSERT INTO `source`.`audit` VALUES ("`source`.`also_not_code`");
END;;
DELIMITER ;
"#;
        let expected = br#"DELIMITER ;;
CREATE PROCEDURE `target`.`refresh_data`()
BEGIN
  SET @sql = 'SELECT ''`source`.`not_code`''';
  INSERT INTO `target`.`audit` VALUES ("`source`.`also_not_code`");
END;;
DELIMITER ;
"#;

        assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
    }

    #[test]
    fn rewrites_trigger_name_target_and_body_table_contexts() {
        let input = br#"DELIMITER ;;
CREATE TRIGGER source.trigger_name BEFORE INSERT ON `source`.`orders`
FOR EACH ROW
BEGIN
  INSERT INTO source.audit_log VALUES (NEW.id);
END;;
DELIMITER ;
"#;
        let expected = br#"DELIMITER ;;
CREATE TRIGGER `target`.trigger_name BEFORE INSERT ON `target`.`orders`
FOR EACH ROW
BEGIN
  INSERT INTO `target`.audit_log VALUES (NEW.id);
END;;
DELIMITER ;
"#;

        assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
    }

    #[test]
    fn rewrites_comma_separated_from_table_lists() {
        let input = br#"CREATE VIEW `source`.`combined` AS
SELECT a.id, b.value
FROM `source`.`first_table` AS a, `source`.`second_table` AS b
WHERE a.id = b.id;
"#;
        let expected = br#"CREATE VIEW `target`.`combined` AS
SELECT a.id, b.value
FROM `target`.`first_table` AS a, `target`.`second_table` AS b
WHERE a.id = b.id;
"#;

        assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
    }

    #[test]
    fn from_list_context_ends_before_expression_commas() {
        let input = b"SELECT * FROM `other`.`orders` AS `source` WHERE id IN (1, `source`.`id`);\n";

        assert!(matches!(
            rewrite_bytes(input, "source", "target"),
            Err(MysqlSqlRewriteError::Malformed(message))
                if message.contains("ambiguous source-prefixed two-part")
        ));
    }

    #[test]
    fn from_list_commas_inside_table_expressions_do_not_authorize_alias_columns() {
        let input = br#"SELECT *
FROM `other`.`orders` AS `source`
JOIN JSON_TABLE(`other`.`payload`, `source`.`path` COLUMNS (value JSON PATH '$')) AS jt;
"#;

        assert!(matches!(
            rewrite_bytes(input, "source", "target"),
            Err(MysqlSqlRewriteError::Malformed(message))
                if message.contains("ambiguous source-prefixed two-part")
        ));
    }

    #[test]
    fn rewrites_statements_inside_loop_and_repeat_bodies() {
        let input = br#"DELIMITER ;;
CREATE PROCEDURE `source`.`refresh_data`()
BEGIN
  work_loop: LOOP
    INSERT INTO `source`.`audit` VALUES (1);
    LEAVE work_loop;
  END LOOP;
  REPEAT
    INSERT INTO source.history VALUES (2);
  UNTIL done END REPEAT;
END;;
DELIMITER ;
"#;
        let expected = br#"DELIMITER ;;
CREATE PROCEDURE `target`.`refresh_data`()
BEGIN
  work_loop: LOOP
    INSERT INTO `target`.`audit` VALUES (1);
    LEAVE work_loop;
  END LOOP;
  REPEAT
    INSERT INTO `target`.history VALUES (2);
  UNTIL done END REPEAT;
END;;
DELIMITER ;
"#;

        assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
    }

    #[test]
    fn decodes_and_reencodes_escaped_backticks_in_identifiers() {
        let input = b"SELECT * FROM `source``database`.`table``name`, `source_database`.`other`;\n";
        let expected =
            b"SELECT * FROM `target``database`.`table``name`, `source_database`.`other`;\n";

        assert_eq!(
            rewrite_bytes(input, "source`database", "target`database").unwrap(),
            expected
        );
    }

    #[test]
    fn equal_database_names_leave_every_byte_unchanged() {
        let input = b"SELECT * FROM `same`.`table` WHERE value='`same`.`literal`';\n";

        assert_eq!(rewrite_bytes(input, "same", "same").unwrap(), input);
    }

    #[test]
    fn rewrites_a_qualifier_split_across_stream_buffers() {
        let mut input = vec![b' '; STREAM_BUFFER_BYTES - 8];
        input.extend_from_slice(b"FROM `source`.`table`;\n");
        let mut expected = vec![b' '; STREAM_BUFFER_BYTES - 8];
        expected.extend_from_slice(b"FROM `target`.`table`;\n");

        assert_eq!(rewrite_bytes(&input, "source", "target").unwrap(), expected);
    }

    #[test]
    fn handles_legal_quoted_unquoted_whitespace_and_ansi_forms() {
        let input = br#"CREATE TABLE `source`.table_name (id INT);
INSERT INTO source . `table_name` VALUES (1);
SELECT * FROM "source" . "table_name";
SELECT `source`.`table_name`.`column_name`, source.function_name();
"#;
        let expected = br#"CREATE TABLE `target`.table_name (id INT);
INSERT INTO `target` . `table_name` VALUES (1);
SELECT * FROM "target" . "table_name";
SELECT `target`.`table_name`.`column_name`, `target`.function_name();
"#;

        assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
    }

    #[test]
    fn rejects_alias_column_two_part_names() {
        let input = b"SELECT `source`.`id` FROM `other`.`orders` AS `source`;\n";

        assert!(matches!(
            rewrite_bytes(input, "source", "target"),
            Err(MysqlSqlRewriteError::Malformed(message))
                if message.contains("ambiguous source-prefixed two-part")
        ));
    }

    #[test]
    fn rejects_input_and_output_size_overruns() {
        assert!(matches!(
            rewrite_bytes_with_limit(b"12345", "a", "b", 4),
            Err(MysqlSqlRewriteError::InputLimit { limit: 4 })
        ));
        let expanding = b"FROM `a`.`b`";
        let limit = u64::try_from(expanding.len()).unwrap();
        assert!(matches!(
            rewrite_bytes_with_limit(expanding, "a", "longer", limit),
            Err(MysqlSqlRewriteError::OutputLimit { limit: actual }) if actual == limit
        ));
    }

    #[test]
    fn rejects_malformed_and_overlong_tokens() {
        for malformed in [
            b"SELECT 'unterminated".as_slice(),
            b"SELECT \"unterminated".as_slice(),
            b"SELECT `unterminated".as_slice(),
            b"SELECT /* unterminated".as_slice(),
            b"SELECT /*! `source`.`table`".as_slice(),
            b"SELECT */ 1".as_slice(),
        ] {
            assert!(
                matches!(
                    rewrite_bytes(malformed, "source", "target"),
                    Err(MysqlSqlRewriteError::Malformed(_))
                ),
                "accepted malformed input: {}",
                String::from_utf8_lossy(malformed)
            );
        }

        let mut overlong = Vec::from(b"SELECT `".as_slice());
        overlong.extend(std::iter::repeat_n(b'a', MAX_QUOTED_IDENTIFIER_BYTES));
        overlong.extend_from_slice(b"`");
        assert!(matches!(
            rewrite_bytes(&overlong, "source", "target"),
            Err(MysqlSqlRewriteError::Malformed(_))
        ));

        let mut overlong_gap = Vec::from(b"FROM `source`".as_slice());
        overlong_gap.extend(std::iter::repeat_n(b' ', MAX_QUALIFIER_GAP_BYTES + 1));
        overlong_gap.extend_from_slice(b".`table`");
        assert!(matches!(
            rewrite_bytes(&overlong_gap, "source", "target"),
            Err(MysqlSqlRewriteError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_invalid_database_names() {
        assert!(validate_database_name("", "source").is_err());
        assert!(validate_database_name("line\nbreak", "source").is_err());
        assert!(validate_database_name(&"a".repeat(65), "source").is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn atomically_replaces_regular_files_and_rejects_symlink_inputs() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let dump = directory.path().join("source.mysql.sql");
        std::fs::write(&dump, b"SELECT * FROM `source`.`table`;\n").unwrap();
        std::fs::set_permissions(&dump, std::fs::Permissions::from_mode(0o640)).unwrap();

        rewrite_mysql_schema_qualifiers(&dump, "source", "target", 1024 * 1024)
            .await
            .unwrap();

        assert_eq!(
            std::fs::read(&dump).unwrap(),
            b"SELECT * FROM `target`.`table`;\n"
        );
        assert_eq!(
            std::fs::symlink_metadata(&dump)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );

        let victim = directory.path().join("victim.sql");
        let linked = directory.path().join("linked.mysql.sql");
        std::fs::write(&victim, b"SELECT * FROM `source`.`victim`;\n").unwrap();
        symlink(&victim, &linked).unwrap();

        assert!(
            rewrite_mysql_schema_qualifiers(&linked, "source", "target", 1024 * 1024)
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"SELECT * FROM `source`.`victim`;\n"
        );

        let malformed = directory.path().join("malformed.mysql.sql");
        let malformed_contents = b"SELECT * FROM `source`.`table` WHERE value='unterminated";
        std::fs::write(&malformed, malformed_contents).unwrap();
        assert!(
            rewrite_mysql_schema_qualifiers(&malformed, "source", "target", 1024 * 1024)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&malformed).unwrap(), malformed_contents);

        let ambiguous = directory.path().join("ambiguous.mysql.sql");
        let ambiguous_contents = b"SELECT `source`.`id` FROM `other`.`orders` AS `source`;\n";
        std::fs::write(&ambiguous, ambiguous_contents).unwrap();
        assert!(
            rewrite_mysql_schema_qualifiers(&ambiguous, "source", "target", 1024 * 1024)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&ambiguous).unwrap(), ambiguous_contents);

        assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".mysql-schema-rewrite-")
        }));
    }
}
