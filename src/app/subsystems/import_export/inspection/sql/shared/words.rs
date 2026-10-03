use super::*;

pub(super) fn has_keyword(tokens: &[SqlToken], expected: &str) -> bool {
    tokens.iter().any(
        |token| matches!(token, SqlToken::Identifier(word) if word.eq_ignore_ascii_case(expected)),
    )
}

pub(super) fn has_keyword_sequence(tokens: &[SqlToken], expected: &[&str]) -> bool {
    tokens.windows(expected.len()).any(|window| {
        window.iter().zip(expected).all(|(token, expected)| {
            matches!(token, SqlToken::Identifier(word) if word.eq_ignore_ascii_case(expected))
        })
    })
}

pub(super) fn statement_words(statement: &Statement) -> Vec<String> {
    statement
        .tokens
        .iter()
        .filter_map(|token| match token {
            SqlToken::Identifier(word) => Some(word.to_ascii_uppercase()),
            _ => None,
        })
        .collect()
}

pub(super) fn create_object(words: &[String]) -> Option<&str> {
    let mut index = 1;
    while words.get(index).is_some_and(|word| {
        is_any_keyword(
            word,
            &[
                "OR",
                "REPLACE",
                "TEMP",
                "TEMPORARY",
                "UNLOGGED",
                "GLOBAL",
                "LOCAL",
                "UNIQUE",
            ],
        )
    }) {
        index += 1;
    }
    words.get(index).map(String::as_str)
}

pub(super) fn word_at_is(words: &[String], index: usize, expected: &str) -> bool {
    words
        .get(index)
        .is_some_and(|word| word.eq_ignore_ascii_case(expected))
}

pub(super) fn contains_any(words: &[String], expected: &[&str]) -> bool {
    words.iter().any(|word| is_any_keyword(word, expected))
}

pub(super) fn contains_sequence(words: &[String], expected: &[&str]) -> bool {
    words.windows(expected.len()).any(|window| {
        window
            .iter()
            .zip(expected)
            .all(|(word, expected)| word.eq_ignore_ascii_case(expected))
    })
}

pub(super) fn privileged_object_command(command: &str, words: &[String], objects: &[&str]) -> bool {
    is_any_keyword(command, &["CREATE", "ALTER", "DROP"])
        && words
            .iter()
            .skip(1)
            .any(|word| is_any_keyword(word, objects))
}

pub(super) fn qualified_identifiers(tokens: &[SqlToken]) -> Vec<(&str, &str)> {
    tokens
        .windows(3)
        .filter_map(|window| {
            if !matches!(window.get(1), Some(SqlToken::Dot)) {
                return None;
            }
            Some((
                super::super::identifier_at(window, 0)?,
                super::super::identifier_at(window, 2)?,
            ))
        })
        .collect()
}

pub(super) fn import_object_qualifiers(tokens: &[SqlToken]) -> Vec<(String, String)> {
    let mut objects = Vec::new();
    if let Some((Some(database), name)) =
        parse_create_table(tokens).or_else(|| parse_insert_table(tokens))
    {
        objects.push((database, name));
    }

    for (index, token) in tokens.iter().enumerate() {
        let SqlToken::Identifier(word) = token else {
            continue;
        };
        let precedes_object = matches!(
            word.to_ascii_uppercase().as_str(),
            "REFERENCES" | "UPDATE" | "FROM" | "INTO" | "TABLE" | "TABLES" | "ON" | "JOIN"
        );
        if !precedes_object {
            continue;
        }
        let mut object_index = index + 1;
        while super::super::identifier_at(tokens, object_index)
            .is_some_and(|word| is_any_keyword(word, &["IF", "NOT", "EXISTS", "ONLY", "IGNORE"]))
        {
            object_index += 1;
        }
        if let Some((Some(database), name)) = parse_qualified_identifier(tokens, object_index) {
            objects.push((database, name));
        }
    }
    objects.sort_unstable();
    objects.dedup();
    objects
}

pub(super) fn top_level_keyword(tokens: &[SqlToken], expected: &str) -> bool {
    let mut depth = 0_usize;
    for token in tokens {
        match token {
            SqlToken::OpenParen => depth = depth.saturating_add(1),
            SqlToken::CloseParen => depth = depth.saturating_sub(1),
            SqlToken::Identifier(word) if depth == 0 && word.eq_ignore_ascii_case(expected) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

pub(super) fn is_mysql_system_database(database: &str) -> bool {
    ["mysql", "sys", "performance_schema", "information_schema"]
        .into_iter()
        .any(|system| database.eq_ignore_ascii_case(system))
}

pub(super) fn is_postgres_system_schema(schema: &str) -> bool {
    schema.eq_ignore_ascii_case("information_schema")
        || schema.to_ascii_lowercase().starts_with("pg_")
}

pub(super) fn is_clickhouse_system_database(database: &str) -> bool {
    ["system", "information_schema", "INFORMATION_SCHEMA"]
        .into_iter()
        .any(|system| database.eq_ignore_ascii_case(system))
}
