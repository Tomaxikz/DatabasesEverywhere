use super::*;

#[derive(Clone, Copy)]
pub(super) enum SourceTokenKind {
    Unquoted,
    Quoted,
    DoubleQuoted,
}

pub(super) fn handle_source_qualifier<R: Read, W: Write>(
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

pub(super) fn observe_unqualified_source(
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

pub(super) struct QualifiedIdentifier {
    pub(super) raw: Vec<u8>,
    pub(super) is_star: bool,
}

pub(super) fn read_qualified_identifier<R: Read>(
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

pub(super) fn is_qualified_identifier_start(byte: u8) -> bool {
    matches!(byte, b'`' | b'"' | b'*') || is_unquoted_identifier_byte(byte)
}

pub(super) fn read_qualifier_gap<R: Read>(
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

pub(super) fn read_gap_line_comment<R: Read>(
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

pub(super) fn read_gap_block_comment<R: Read>(
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

pub(super) struct DelimitedIdentifier {
    pub(super) raw: Vec<u8>,
    pub(super) decoded: Vec<u8>,
}

pub(super) fn read_delimited_identifier<R: Read>(
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
