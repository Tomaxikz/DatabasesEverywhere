use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum StatementKind {
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
pub(super) struct SqlContext {
    pub(super) statement: StatementKind,
    pub(super) object_expected: bool,
    pub(super) create_trigger: bool,
    pub(super) trigger_on_seen: bool,
    pub(super) table_list: bool,
    pub(super) parenthesis_depth: usize,
    pub(super) from_table_list_depths: HashSet<usize>,
}

impl SqlContext {
    pub(super) fn starts_routine_body(&self, word: &[u8]) -> bool {
        let is_trigger_row =
            word.eq_ignore_ascii_case(b"ROW") && self.create_trigger && self.trigger_on_seen;
        word.eq_ignore_ascii_case(b"BEGIN")
            || word.eq_ignore_ascii_case(b"THEN")
            || word.eq_ignore_ascii_case(b"ELSE")
            || word.eq_ignore_ascii_case(b"DO")
            || word.eq_ignore_ascii_case(b"LOOP")
            || word.eq_ignore_ascii_case(b"REPEAT")
            || is_trigger_row
    }

    pub(super) fn observe_word(&mut self, word: &[u8]) {
        if self.starts_routine_body(word) {
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
            self.from_table_list_depths.remove(&self.parenthesis_depth);
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
            if from_or_join {
                self.from_table_list_depths.insert(self.parenthesis_depth);
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
        } else if (word.eq_ignore_ascii_case(b"TO")
            && self.statement == StatementKind::Rename
            && self.table_list)
            || ((word.eq_ignore_ascii_case(b"VIEW")
                || word.eq_ignore_ascii_case(b"EVENT")
                || word.eq_ignore_ascii_case(b"PROCEDURE")
                || word.eq_ignore_ascii_case(b"FUNCTION"))
                && ddl)
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

    pub(super) fn observe_identifier_or_value(&mut self) {
        self.object_expected = false;
    }

    pub(super) fn observe_punctuation(&mut self, byte: u8) {
        if byte == b';' {
            *self = Self::default();
        } else if byte == b'(' {
            self.parenthesis_depth = self.parenthesis_depth.saturating_add(1);
            self.object_expected = false;
        } else if byte == b')' {
            self.from_table_list_depths.remove(&self.parenthesis_depth);
            self.parenthesis_depth = self.parenthesis_depth.saturating_sub(1);
            self.object_expected = false;
        } else if byte == b','
            && (self.table_list
                || self
                    .from_table_list_depths
                    .contains(&self.parenthesis_depth))
        {
            self.object_expected = true;
        } else if !byte.is_ascii_whitespace() {
            self.object_expected = false;
        }
    }
}

pub(super) fn statement_kind(word: &[u8]) -> StatementKind {
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

pub(super) fn is_object_modifier(word: &[u8]) -> bool {
    word.eq_ignore_ascii_case(b"IF")
        || word.eq_ignore_ascii_case(b"NOT")
        || word.eq_ignore_ascii_case(b"EXISTS")
        || word.eq_ignore_ascii_case(b"ONLY")
}

pub(super) fn is_from_clause_boundary(word: &[u8]) -> bool {
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

pub(super) struct RewriteIdentifiers<'a> {
    pub(super) source_database: &'a [u8],
    pub(super) quoted_target_database: &'a [u8],
    pub(super) double_quoted_target_database: &'a [u8],
}
