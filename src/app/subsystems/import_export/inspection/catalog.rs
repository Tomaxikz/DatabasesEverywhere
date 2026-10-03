use super::*;

#[derive(Default)]
pub(super) struct DialectHints {
    pub(super) postgres: bool,
    pub(super) mysql: bool,
    pub(super) clickhouse: bool,
}

pub(super) struct CatalogBuilder {
    pub(super) protocol: Protocol,
    pub(super) namespaces: BTreeSet<String>,
    pub(super) objects: BTreeMap<String, DumpSelectableObject>,
    pub(super) observed_objects: BTreeSet<String>,
    pub(super) unselectable: usize,
    pub(super) truncated: bool,
    pub(super) hints: DialectHints,
}

impl CatalogBuilder {
    pub(super) fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            namespaces: BTreeSet::new(),
            objects: BTreeMap::new(),
            observed_objects: BTreeSet::new(),
            unselectable: 0,
            truncated: false,
            hints: DialectHints::default(),
        }
    }

    pub(super) fn add_namespace(&mut self, namespace: String) -> Result<(), InspectionError> {
        if !portable_identifier(&namespace, MAX_IDENTIFIER_BYTES) {
            return Ok(());
        }
        self.namespaces.insert(namespace);
        if self.namespaces.len() > MAX_NAMESPACES {
            self.namespaces.pop_last();
            self.truncated = true;
        }
        Ok(())
    }

    pub(super) fn add_table(
        &mut self,
        namespace: Option<String>,
        name: String,
    ) -> Result<(), InspectionError> {
        let observed_key = match &namespace {
            Some(namespace) => format!("{namespace}.{name}"),
            None => name.clone(),
        };
        if self.observed_objects.contains(&observed_key) {
            return Ok(());
        }
        if self.observed_objects.len() == MAX_OBJECTS {
            self.truncated = true;
            return Ok(());
        }
        self.observed_objects.insert(observed_key.clone());
        let names_are_portable = portable_identifier(&name, MAX_IDENTIFIER_BYTES)
            && namespace
                .as_deref()
                .is_none_or(|value| portable_identifier(value, MAX_IDENTIFIER_BYTES));
        if !names_are_portable {
            self.unselectable = self.unselectable.saturating_add(1);
            return Ok(());
        }
        if let Some(namespace) = &namespace {
            self.add_namespace(namespace.clone())?;
        }
        let selection_key = if self.protocol.engine().family().is_columnar() {
            name.clone()
        } else {
            observed_key
        };
        self.objects
            .entry(selection_key.clone())
            .or_insert(DumpSelectableObject {
                kind: DumpObjectKind::Table,
                name,
                namespace,
                selection_key,
            });
        Ok(())
    }

    pub(super) fn add_unselectable_object(&mut self) {
        if self.observed_objects.len() == MAX_OBJECTS {
            self.truncated = true;
            return;
        }
        let key = format!("#unselectable-{}", self.unselectable);
        if self.observed_objects.insert(key) {
            self.unselectable = self.unselectable.saturating_add(1);
        }
    }

    pub(super) fn observe_comment(&mut self, comment: &[u8]) {
        if contains_ascii_case_insensitive(comment, b"postgresql database dump") {
            self.hints.postgres = true;
        }
        if contains_ascii_case_insensitive(comment, b"mysql dump")
            || contains_ascii_case_insensitive(comment, b"mariadb dump")
        {
            self.hints.mysql = true;
        }
        if contains_ascii_case_insensitive(comment, b"databaseseverywhere clickhouse logical dump")
        {
            self.hints.clickhouse = true;
        }
    }

    pub(super) fn validate_dialect(&self) -> Result<(), InspectionError> {
        let mismatch = match self.protocol.engine().family() {
            EngineFamily::Postgres => self.hints.mysql || self.hints.clickhouse,
            EngineFamily::Mysql => self.hints.postgres || self.hints.clickhouse,
            EngineFamily::Columnar => self.hints.postgres || self.hints.mysql,
            _ => false,
        };
        let ambiguous = [self.hints.postgres, self.hints.mysql, self.hints.clickhouse]
            .into_iter()
            .filter(|hint| *hint)
            .count()
            > 1;
        if mismatch || ambiguous {
            Err(InspectionError::Invalid(
                "dump content does not match the target database protocol",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn finish(
        self,
        sha256: String,
        source_size_bytes: u64,
        format: DumpArchiveFormat,
    ) -> DumpInspection {
        DumpInspection {
            protocol: self.protocol,
            sha256,
            source_size_bytes,
            detected_archive_format: format,
            selection_kind: DumpSelectionKind::Tables,
            selective_supported: false,
            catalog_complete: !self.truncated,
            namespaces: self.namespaces.into_iter().collect(),
            objects: self.objects.into_values().collect(),
            unselectable_object_count: self.unselectable,
            selective_unavailable_reason: Some(
                "uploaded logical dumps can be previewed, but safe object-level filtering is not available yet; import the complete dump"
                    .to_string(),
            ),
        }
    }
}

pub(super) fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}
