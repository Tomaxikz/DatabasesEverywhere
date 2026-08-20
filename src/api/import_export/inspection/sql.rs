//! Streaming SQL parser used by uploaded-dump inspection.

use std::{collections::VecDeque, io::Read};

use super::{
    CatalogBuilder, InspectionError, MAX_ARCHIVE_DEPTH, MAX_IDENTIFIER_BYTES,
    MAX_SQL_TOKENS_PER_STATEMENT, Protocol,
};

enum SqlToken {
    Identifier(String),
    OversizedIdentifier,
    Dot,
    Semicolon,
    Other,
}

const MAX_CAPTURED_COMMENT_BYTES: usize = 256;
const MAX_DOLLAR_TAG_BYTES: usize = 64;
const SQL_READ_BUFFER_BYTES: usize = 64 * 1024;
const TABLE_MODIFIERS: &[&str] = &[
    "OR",
    "REPLACE",
    "TEMP",
    "TEMPORARY",
    "UNLOGGED",
    "GLOBAL",
    "LOCAL",
];
const NAMESPACE_MODIFIERS: &[&str] = &["OR", "REPLACE", "TEMP", "TEMPORARY"];

pub(super) fn inspect_sql_reader<R: Read>(
    reader: R,
    protocol: Protocol,
    catalog: &mut CatalogBuilder,
) -> Result<(), InspectionError> {
    let mut lexer = SqlLexer::new(reader, protocol);
    let mut statement = Statement::default();
    while let Some(event) = lexer.next_event()? {
        match event {
            LexEvent::Comment(comment) => catalog.observe_comment(&comment),
            LexEvent::Token(SqlToken::Semicolon) => {
                let copy_data = statement.finish(protocol, catalog)?;
                if copy_data {
                    lexer.skip_postgres_copy_data()?;
                }
            }
            LexEvent::Token(token) => statement.push(token),
        }
    }
    statement.finish(protocol, catalog)?;
    Ok(())
}

enum LexEvent {
    Token(SqlToken),
    Comment(Vec<u8>),
}

struct SqlLexer<R> {
    input: ByteInput<R>,
    backslash_strings: bool,
}

impl<R: Read> SqlLexer<R> {
    fn new(reader: R, protocol: Protocol) -> Self {
        Self {
            input: ByteInput::new(reader),
            backslash_strings: matches!(
                protocol,
                Protocol::Mariadb | Protocol::Mysql | Protocol::Clickhouse
            ),
        }
    }

    fn next_event(&mut self) -> Result<Option<LexEvent>, InspectionError> {
        loop {
            let Some(byte) = self.input.next()? else {
                return Ok(None);
            };
            if byte == 0 {
                return Err(InspectionError::Invalid(
                    "SQL dump contains binary data outside a supported dump section",
                ));
            }
            if byte.is_ascii_whitespace() {
                continue;
            }
            if byte == b'-' && self.input.peek()? == Some(b'-') {
                self.input.next()?;
                return Ok(Some(LexEvent::Comment(self.read_line_comment()?)));
            }
            if byte == b'#' {
                return Ok(Some(LexEvent::Comment(self.read_line_comment()?)));
            }
            if byte == b'/' && self.input.peek()? == Some(b'*') {
                self.input.next()?;
                return Ok(Some(LexEvent::Comment(self.read_block_comment()?)));
            }
            if byte == b'\'' {
                self.skip_string(self.backslash_strings)?;
                return Ok(Some(LexEvent::Token(SqlToken::Other)));
            }
            if matches!(byte, b'"' | b'`') {
                let identifier = self.read_quoted_identifier(byte)?;
                return Ok(Some(LexEvent::Token(
                    identifier.map_or(SqlToken::OversizedIdentifier, SqlToken::Identifier),
                )));
            }
            if byte == b'$'
                && let Some(delimiter) = self.try_dollar_delimiter()?
            {
                self.skip_dollar_string(&delimiter)?;
                return Ok(Some(LexEvent::Token(SqlToken::Other)));
            }
            if is_word_byte(byte) {
                let identifier = self.read_word(byte)?;
                if identifier
                    .as_deref()
                    .is_some_and(|word| word.eq_ignore_ascii_case("E"))
                    && self.input.peek()? == Some(b'\'')
                {
                    self.input.next()?;
                    self.skip_string(true)?;
                    return Ok(Some(LexEvent::Token(SqlToken::Other)));
                }
                return Ok(Some(LexEvent::Token(
                    identifier.map_or(SqlToken::OversizedIdentifier, SqlToken::Identifier),
                )));
            }
            return Ok(Some(LexEvent::Token(match byte {
                b'.' => SqlToken::Dot,
                b';' => SqlToken::Semicolon,
                _ => SqlToken::Other,
            })));
        }
    }

    fn read_line_comment(&mut self) -> Result<Vec<u8>, InspectionError> {
        let mut comment = Vec::with_capacity(128);
        while let Some(byte) = self.input.next()? {
            if byte == b'\n' {
                break;
            }
            if comment.len() < MAX_CAPTURED_COMMENT_BYTES {
                comment.push(byte.to_ascii_lowercase());
            }
        }
        Ok(comment)
    }

    fn read_block_comment(&mut self) -> Result<Vec<u8>, InspectionError> {
        let mut comment = Vec::with_capacity(128);
        let mut depth = 1_usize;
        while let Some(byte) = self.input.next()? {
            if byte == b'/' && self.input.peek()? == Some(b'*') {
                self.input.next()?;
                depth += 1;
                if depth > MAX_ARCHIVE_DEPTH {
                    return Err(InspectionError::Limit("SQL comment nesting is too deep"));
                }
                continue;
            }
            if byte == b'*' && self.input.peek()? == Some(b'/') {
                self.input.next()?;
                depth -= 1;
                if depth == 0 {
                    return Ok(comment);
                }
                continue;
            }
            if comment.len() < MAX_CAPTURED_COMMENT_BYTES {
                comment.push(byte.to_ascii_lowercase());
            }
        }
        Err(InspectionError::Invalid(
            "SQL dump has an unterminated comment",
        ))
    }

    fn skip_string(&mut self, backslash_escapes: bool) -> Result<(), InspectionError> {
        while let Some(byte) = self.input.next()? {
            match byte {
                b'\\' if backslash_escapes => {
                    self.input.next()?;
                }
                b'\'' if self.input.peek()? == Some(b'\'') => {
                    self.input.next()?;
                }
                b'\'' => return Ok(()),
                _ => {}
            }
        }
        Err(InspectionError::Invalid(
            "SQL dump has an unterminated string",
        ))
    }

    fn read_quoted_identifier(&mut self, quote: u8) -> Result<Option<String>, InspectionError> {
        let mut bytes = Vec::new();
        let mut oversized = false;
        while let Some(byte) = self.input.next()? {
            if byte == quote {
                if self.input.peek()? == Some(quote) {
                    self.input.next()?;
                    push_identifier_byte(&mut bytes, quote, &mut oversized)?;
                    continue;
                }
                if oversized {
                    return Ok(None);
                }
                return String::from_utf8(bytes).map(Some).map_err(|_| {
                    InspectionError::Invalid("SQL dump contains a non-UTF-8 object identifier")
                });
            }
            push_identifier_byte(&mut bytes, byte, &mut oversized)?;
        }
        Err(InspectionError::Invalid(
            "SQL dump has an unterminated quoted identifier",
        ))
    }

    fn read_word(&mut self, first: u8) -> Result<Option<String>, InspectionError> {
        let mut bytes = Vec::with_capacity(16);
        let mut oversized = false;
        push_identifier_byte(&mut bytes, first, &mut oversized)?;
        while self.input.peek()?.is_some_and(is_word_byte) {
            let byte = self.input.next()?.expect("peeked byte exists");
            push_identifier_byte(&mut bytes, byte, &mut oversized)?;
        }
        if oversized {
            return Ok(None);
        }
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| InspectionError::Invalid("SQL dump contains an invalid SQL token"))
    }

    fn try_dollar_delimiter(&mut self) -> Result<Option<Vec<u8>>, InspectionError> {
        let mut delimiter = vec![b'$'];
        for index in 0..=MAX_DOLLAR_TAG_BYTES {
            let Some(byte) = self.input.peek_n(index)? else {
                return Ok(None);
            };
            if byte == b'$' {
                for _ in 0..=index {
                    delimiter.push(self.input.next()?.expect("peeked byte exists"));
                }
                return Ok(Some(delimiter));
            }
            if !(byte.is_ascii_alphanumeric() || byte == b'_') {
                return Ok(None);
            }
        }
        Ok(None)
    }

    fn skip_dollar_string(&mut self, delimiter: &[u8]) -> Result<(), InspectionError> {
        let mut matched = 0_usize;
        while let Some(byte) = self.input.next()? {
            if byte == delimiter[matched] {
                matched += 1;
                if matched == delimiter.len() {
                    return Ok(());
                }
            } else {
                matched = usize::from(byte == delimiter[0]);
            }
        }
        Err(InspectionError::Invalid(
            "SQL dump has an unterminated dollar-quoted string",
        ))
    }

    fn skip_postgres_copy_data(&mut self) -> Result<(), InspectionError> {
        let mut line = Vec::with_capacity(64);
        loop {
            let Some(byte) = self.input.next()? else {
                return Err(InspectionError::Invalid(
                    "PostgreSQL COPY data is missing its terminator",
                ));
            };
            if byte == b'\n' {
                if line.strip_suffix(b"\r").unwrap_or(&line) == b"\\." {
                    return Ok(());
                }
                line.clear();
            } else if line.len() < 3 {
                line.push(byte);
            }
        }
    }
}

fn push_identifier_byte(
    bytes: &mut Vec<u8>,
    byte: u8,
    oversized: &mut bool,
) -> Result<(), InspectionError> {
    if byte == 0 || byte.is_ascii_control() {
        return Err(InspectionError::Invalid(
            "SQL object identifier contains a control character",
        ));
    }
    if bytes.len() < MAX_IDENTIFIER_BYTES {
        bytes.push(byte);
    } else {
        *oversized = true;
    }
    Ok(())
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'-')
}

struct ByteInput<R> {
    reader: R,
    buffer: Box<[u8]>,
    start: usize,
    end: usize,
    lookahead: VecDeque<u8>,
}

impl<R: Read> ByteInput<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: vec![0_u8; SQL_READ_BUFFER_BYTES].into_boxed_slice(),
            start: 0,
            end: 0,
            lookahead: VecDeque::with_capacity(MAX_DOLLAR_TAG_BYTES + 1),
        }
    }

    fn next(&mut self) -> Result<Option<u8>, InspectionError> {
        if let Some(byte) = self.lookahead.pop_front() {
            return Ok(Some(byte));
        }
        self.next_buffer_byte()
    }

    fn peek(&mut self) -> Result<Option<u8>, InspectionError> {
        self.peek_n(0)
    }

    fn peek_n(&mut self, index: usize) -> Result<Option<u8>, InspectionError> {
        while self.lookahead.len() <= index {
            let Some(byte) = self.next_buffer_byte()? else {
                return Ok(None);
            };
            self.lookahead.push_back(byte);
        }
        Ok(self.lookahead.get(index).copied())
    }

    fn next_buffer_byte(&mut self) -> Result<Option<u8>, InspectionError> {
        if self.start == self.end {
            self.start = 0;
            self.end = self.reader.read(&mut self.buffer)?;
            if self.end == 0 {
                return Ok(None);
            }
        }
        let byte = self.buffer[self.start];
        self.start += 1;
        Ok(Some(byte))
    }
}

#[derive(Default)]
struct Statement {
    tokens: Vec<SqlToken>,
    previous_identifier_was_from: bool,
    copy_from_stdin: bool,
}

impl Statement {
    fn push(&mut self, token: SqlToken) {
        match &token {
            SqlToken::Identifier(identifier) => {
                if self.previous_identifier_was_from && identifier.eq_ignore_ascii_case("STDIN") {
                    self.copy_from_stdin = true;
                }
                self.previous_identifier_was_from = identifier.eq_ignore_ascii_case("FROM");
            }
            SqlToken::Other => {}
            _ => self.previous_identifier_was_from = false,
        }
        if self.tokens.len() < MAX_SQL_TOKENS_PER_STATEMENT {
            self.tokens.push(token);
        }
    }

    fn finish(
        &mut self,
        protocol: Protocol,
        catalog: &mut CatalogBuilder,
    ) -> Result<bool, InspectionError> {
        if self.tokens.is_empty() {
            return Ok(false);
        }
        let table = parse_create_table(&self.tokens)
            .or_else(|| parse_copy_table(&self.tokens))
            .or_else(|| parse_insert_table(&self.tokens));
        if let Some((namespace, name)) = table {
            catalog.add_table(namespace, name)?;
        } else if self
            .tokens
            .iter()
            .any(|token| matches!(token, SqlToken::OversizedIdentifier))
            && is_table_statement(&self.tokens)
        {
            catalog.add_unselectable_object();
        }
        if let Some(namespace) = parse_namespace(&self.tokens) {
            catalog.add_namespace(namespace)?;
        }
        let first_is_copy =
            identifier_at(&self.tokens, 0).is_some_and(|word| word.eq_ignore_ascii_case("COPY"));
        let copy_data = protocol == Protocol::Postgres && first_is_copy && self.copy_from_stdin;
        self.tokens.clear();
        self.previous_identifier_was_from = false;
        self.copy_from_stdin = false;
        Ok(copy_data)
    }
}

fn is_table_statement(tokens: &[SqlToken]) -> bool {
    identifier_at(tokens, 0).is_some_and(|word| is_any_keyword(word, &["CREATE", "COPY", "INSERT"]))
}

fn parse_create_table(tokens: &[SqlToken]) -> Option<(Option<String>, String)> {
    let mut index = 0;
    if !take_word(tokens, &mut index, "CREATE") {
        return None;
    }
    skip_modifiers(tokens, &mut index, TABLE_MODIFIERS);
    if !take_word(tokens, &mut index, "TABLE") {
        return None;
    }
    if take_word(tokens, &mut index, "IF") {
        let _ = take_word(tokens, &mut index, "NOT");
        let _ = take_word(tokens, &mut index, "EXISTS");
    }
    let _ = take_word(tokens, &mut index, "ONLY");
    parse_qualified_identifier(tokens, index)
}

fn parse_copy_table(tokens: &[SqlToken]) -> Option<(Option<String>, String)> {
    let mut index = 0;
    if !take_word(tokens, &mut index, "COPY") {
        return None;
    }
    let _ = take_word(tokens, &mut index, "ONLY");
    parse_qualified_identifier(tokens, index)
}

fn parse_insert_table(tokens: &[SqlToken]) -> Option<(Option<String>, String)> {
    let mut index = 0;
    if !take_word(tokens, &mut index, "INSERT") {
        return None;
    }
    let _ = take_word(tokens, &mut index, "IGNORE");
    if !take_word(tokens, &mut index, "INTO") {
        return None;
    }
    let _ = take_word(tokens, &mut index, "TABLE");
    parse_qualified_identifier(tokens, index)
}

fn parse_namespace(tokens: &[SqlToken]) -> Option<String> {
    let mut index = 0;
    if take_word(tokens, &mut index, "CREATE") {
        skip_modifiers(tokens, &mut index, NAMESPACE_MODIFIERS);
        if !(take_word(tokens, &mut index, "SCHEMA") || take_word(tokens, &mut index, "DATABASE")) {
            return None;
        }
        if take_word(tokens, &mut index, "IF") {
            let _ = take_word(tokens, &mut index, "NOT");
            let _ = take_word(tokens, &mut index, "EXISTS");
        }
        return identifier_at(tokens, index).map(str::to_string);
    }
    if take_word(tokens, &mut index, "USE") {
        return identifier_at(tokens, index).map(str::to_string);
    }
    None
}

fn parse_qualified_identifier(
    tokens: &[SqlToken],
    index: usize,
) -> Option<(Option<String>, String)> {
    let first = identifier_at(tokens, index)?.to_string();
    if matches!(tokens.get(index + 1), Some(SqlToken::Dot)) {
        let second = identifier_at(tokens, index + 2)?.to_string();
        Some((Some(first), second))
    } else {
        Some((None, first))
    }
}

fn identifier_at(tokens: &[SqlToken], index: usize) -> Option<&str> {
    match tokens.get(index) {
        Some(SqlToken::Identifier(identifier)) => Some(identifier),
        _ => None,
    }
}

fn skip_modifiers(tokens: &[SqlToken], index: &mut usize, modifiers: &[&str]) {
    while identifier_at(tokens, *index).is_some_and(|word| is_any_keyword(word, modifiers)) {
        *index += 1;
    }
}

fn is_any_keyword(word: &str, expected: &[&str]) -> bool {
    expected
        .iter()
        .any(|candidate| word.eq_ignore_ascii_case(candidate))
}

fn take_word(tokens: &[SqlToken], index: &mut usize, expected: &str) -> bool {
    if identifier_at(tokens, *index).is_some_and(|word| word.eq_ignore_ascii_case(expected)) {
        *index += 1;
        true
    } else {
        false
    }
}
