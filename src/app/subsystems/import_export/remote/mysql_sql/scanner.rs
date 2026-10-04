use std::io::{Read, Write};

use super::{
    MAX_QUOTED_IDENTIFIER_BYTES, MysqlSqlRewriteError,
    bounded::{BoundedInput, BoundedOutput, push_token_byte},
    context::{RewriteIdentifiers, SqlContext},
    qualifiers::{SourceTokenKind, handle_source_qualifier, read_delimited_identifier},
};

pub(super) fn rewrite_sql<R: Read, W: Write>(
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
        if special != Some(0) {
            let plain_length = special.unwrap_or(available_length);
            if executable_version_pending {
                let available = input.available()?;
                if available[..plain_length]
                    .iter()
                    .any(|byte| !byte.is_ascii_whitespace())
                {
                    executable_version_pending = false;
                }
            }
            copy_normal_prefix(input, output, context, plain_length)?;
            continue;
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
                if copy_executable_comment_marker(input, output)? {
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

pub(super) fn copy_executable_comment_marker<R: Read, W: Write>(
    input: &mut BoundedInput<R>,
    output: &mut BoundedOutput<W>,
) -> Result<bool, MysqlSqlRewriteError> {
    if input.peek_byte()? == Some(b'!') {
        let _ = input.next_byte()?;
        output.write_byte(b'!')?;
        return Ok(true);
    }
    if input.peek_byte()? == Some(b'M') && input.peek_nth_byte(1)? == Some(b'!') {
        let _ = input.next_byte()?;
        let _ = input.next_byte()?;
        output.write_bytes(b"M!")?;
        return Ok(true);
    }
    Ok(false)
}

pub(super) fn copy_available_prefix<R: Read, W: Write>(
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

pub(super) fn copy_normal_prefix<R: Read, W: Write>(
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

pub(super) fn find_normal_special(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|byte| {
        matches!(*byte, b'\'' | b'"' | b'`' | b'/' | b'-' | b'#' | b'*')
            || is_unquoted_identifier_byte(*byte)
    })
}

pub(super) fn is_unquoted_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$') || byte >= 0x80
}

pub(super) fn handle_unquoted_token<R: Read, W: Write>(
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

pub(super) fn copy_unquoted_token_remainder<R: Read, W: Write>(
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

pub(super) fn handle_double_quoted_token<R: Read, W: Write>(
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

pub(super) fn copy_quoted_string<R: Read, W: Write>(
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
        if special != Some(0) {
            copy_available_prefix(input, output, special.unwrap_or(available_length))?;
            continue;
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

pub(super) fn copy_line_comment<R: Read, W: Write>(
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
        if special != Some(0) {
            copy_available_prefix(input, output, special.unwrap_or(available_length))?;
            continue;
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

pub(super) fn copy_block_comment<R: Read, W: Write>(
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
        if star != Some(0) {
            copy_available_prefix(input, output, star.unwrap_or(available_length))?;
            continue;
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
