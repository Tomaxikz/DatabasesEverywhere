use super::*;

pub(in crate::api::import_export) async fn resolve_upload_source_database_catalog(
    state: &AppState,
    instance_id: &str,
    source: &ImportSourceOptions,
    source_database: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let ImportSourceOptions::Upload { upload_id, .. } = source else {
        return Ok(source_database.map(str::to_owned));
    };
    let upload = state
        .import_uploads
        .repository()
        .get(instance_id, upload_id)
        .await
        .map_err(upload_storage_error)?
        .ok_or(ApiError::NotFound)?;
    if upload.protocol != Protocol::Mongodb {
        return Ok(source_database.map(str::to_owned));
    }
    let catalog = upload
        .catalog_json
        .as_deref()
        .map(serde_json::from_str::<DumpInspection>)
        .transpose()
        .map_err(|_| ApiError::Runtime("stored upload catalog is invalid".to_string()))?;
    if catalog
        .as_ref()
        .is_some_and(|catalog| catalog.protocol != upload.protocol)
    {
        return Err(ApiError::Runtime(
            "stored upload catalog protocol is invalid".to_string(),
        ));
    }
    resolve_mongodb_source_database(catalog.as_ref(), source_database)
}

fn resolve_mongodb_source_database(
    catalog: Option<&DumpInspection>,
    source_database: Option<&str>,
) -> Result<Option<String>, ApiError> {
    if let Some(source_database) = source_database {
        if catalog.is_some_and(|catalog| {
            catalog.catalog_complete
                && !catalog.namespaces.is_empty()
                && !catalog
                    .namespaces
                    .iter()
                    .any(|database| database == source_database)
        }) {
            return Err(ApiError::Conflict(
                "source.source_database does not match a source database detected in the uploaded MongoDB archive"
                    .to_string(),
            ));
        }
        return Ok(Some(source_database.to_string()));
    }

    let Some(catalog) = catalog else {
        return Err(manual_source_database_required(
            "inspect the upload or provide source.source_database",
        ));
    };
    if !catalog.catalog_complete || catalog.namespaces.is_empty() {
        return Err(manual_source_database_required(
            "discovery was empty or incomplete; provide source.source_database",
        ));
    }
    if catalog.namespaces.len() != 1 {
        return Err(manual_source_database_required(
            "multiple source databases were detected; choose one in source.source_database",
        ));
    }
    let database = &catalog.namespaces[0];
    crate::api::remote_import::validate_mongodb_database_name(
        "source.source_database",
        database,
        false,
    )
    .map_err(|_| {
        ApiError::Runtime("stored upload catalog contains an invalid database".to_string())
    })?;
    Ok(Some(database.clone()))
}

fn manual_source_database_required(reason: &str) -> ApiError {
    ApiError::Conflict(format!(
        "MongoDB upload imports need an unambiguous source database: {reason}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::import_export::inspection::DumpSelectionKind;

    fn catalog(namespaces: &[&str], complete: bool) -> DumpInspection {
        DumpInspection {
            protocol: Protocol::Mongodb,
            sha256: "0".repeat(64),
            source_size_bytes: 1,
            detected_archive_format: DumpArchiveFormat::Gzip,
            selection_kind: DumpSelectionKind::Collections,
            selective_supported: false,
            catalog_complete: complete,
            namespaces: namespaces
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            objects: Vec::new(),
            unselectable_object_count: 0,
            selective_unavailable_reason: None,
        }
    }

    #[test]
    fn one_complete_candidate_is_inferred() {
        assert_eq!(
            resolve_mongodb_source_database(Some(&catalog(&["tenant"], true)), None).unwrap(),
            Some("tenant".to_string())
        );
    }

    #[test]
    fn multiple_candidates_require_an_explicit_choice() {
        assert!(matches!(
            resolve_mongodb_source_database(Some(&catalog(&["alpha", "beta"], true)), None),
            Err(ApiError::Conflict(_))
        ));
    }

    #[test]
    fn empty_incomplete_or_missing_discovery_requires_manual_input() {
        for catalog in [
            Some(catalog(&[], true)),
            Some(catalog(&["detected"], false)),
            None,
        ] {
            assert!(matches!(
                resolve_mongodb_source_database(catalog.as_ref(), None),
                Err(ApiError::Conflict(_))
            ));
        }
    }

    #[test]
    fn provided_database_must_match_a_complete_nonempty_catalog() {
        let catalog = catalog(&["alpha", "beta"], true);
        assert_eq!(
            resolve_mongodb_source_database(Some(&catalog), Some("alpha")).unwrap(),
            Some("alpha".to_string())
        );
        assert!(matches!(
            resolve_mongodb_source_database(Some(&catalog), Some("gamma")),
            Err(ApiError::Conflict(_))
        ));
    }

    #[test]
    fn provided_database_is_the_fallback_for_inconclusive_discovery() {
        for catalog in [
            Some(catalog(&[], true)),
            Some(catalog(&["hint"], false)),
            None,
        ] {
            assert_eq!(
                resolve_mongodb_source_database(catalog.as_ref(), Some("manual")).unwrap(),
                Some("manual".to_string())
            );
        }
    }
}
