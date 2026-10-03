use super::*;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(super) struct QdrantAlias {
    pub(super) alias_name: String,
    pub(super) collection_name: String,
}

pub(super) fn selected_collections(
    collections: Vec<String>,
    selection: &ImportExportSelection,
) -> Result<Vec<String>, ApiError> {
    let available = collections.into_iter().collect::<HashSet<_>>();
    let excluded = selection.exclude.iter().collect::<HashSet<_>>();
    let selected = if selection.mode == SelectionMode::Full {
        available
            .into_iter()
            .filter(|name| !excluded.contains(name))
            .collect::<Vec<_>>()
    } else {
        let missing = selection
            .include
            .iter()
            .filter(|name| !available.contains(*name))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(ApiError::BadRequest(
                "remote qdrant source is missing one or more selected collections".to_string(),
            ));
        }
        selection
            .include
            .iter()
            .filter(|name| !excluded.contains(*name))
            .cloned()
            .collect::<Vec<_>>()
    };
    let mut selected = selected;
    selected.sort();
    Ok(selected)
}

pub(super) fn check_qdrant_names(
    source_collections: &HashSet<String>,
    source_aliases: &[QdrantAlias],
    target_collections: &[String],
    target_aliases: &[QdrantAlias],
) -> Result<(), ApiError> {
    let target_alias_names = target_aliases
        .iter()
        .map(|alias| alias.alias_name.as_str())
        .collect::<HashSet<_>>();
    if let Some(collision) = source_collections
        .iter()
        .find(|collection| target_alias_names.contains(collection.as_str()))
    {
        return Err(ApiError::BadRequest(format!(
            "remote qdrant collection {collision} conflicts with an existing target alias; rename or remove the target alias before importing"
        )));
    }

    let target_collection_names = target_collections
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if let Some(collision) = source_aliases
        .iter()
        .find(|alias| target_collection_names.contains(alias.alias_name.as_str()))
    {
        return Err(ApiError::BadRequest(format!(
            "remote qdrant alias {} conflicts with an existing target collection; rename or remove the target collection before importing",
            collision.alias_name
        )));
    }
    Ok(())
}

pub(super) fn selected_aliases(
    aliases: Vec<QdrantAlias>,
    selected_collections: &HashSet<String>,
) -> Vec<QdrantAlias> {
    aliases
        .into_iter()
        .filter(|alias| selected_collections.contains(&alias.collection_name))
        .collect()
}

pub(super) fn desired_import_aliases(
    target_aliases: &[QdrantAlias],
    source_aliases: &[QdrantAlias],
    affected_collections: &HashSet<String>,
) -> Vec<QdrantAlias> {
    let mut desired = BTreeMap::new();
    for alias in target_aliases {
        if !affected_collections.contains(&alias.collection_name) {
            desired.insert(alias.alias_name.clone(), alias.collection_name.clone());
        }
    }
    // Source mappings intentionally win an alias-name conflict. This keeps every alias
    // selected from the source attached to the collection that was just imported.
    for alias in source_aliases {
        desired.insert(alias.alias_name.clone(), alias.collection_name.clone());
    }
    desired
        .into_iter()
        .map(|(alias_name, collection_name)| QdrantAlias {
            alias_name,
            collection_name,
        })
        .collect()
}

pub(super) fn alias_actions(current: &[QdrantAlias], desired: &[QdrantAlias]) -> Vec<Value> {
    let current = current
        .iter()
        .map(|alias| (&alias.alias_name, &alias.collection_name))
        .collect::<BTreeMap<_, _>>();
    let desired = desired
        .iter()
        .map(|alias| (&alias.alias_name, &alias.collection_name))
        .collect::<BTreeMap<_, _>>();
    let mut actions = Vec::new();
    for (alias_name, collection_name) in &current {
        if desired.get(alias_name) != Some(collection_name) {
            actions.push(json!({
                "delete_alias": {
                    "alias_name": alias_name,
                }
            }));
        }
    }
    for (alias_name, collection_name) in &desired {
        if current.get(alias_name) != Some(collection_name) {
            actions.push(json!({
                "create_alias": {
                    "alias_name": alias_name,
                    "collection_name": collection_name,
                }
            }));
        }
    }
    actions
}

pub(super) fn valid_qdrant_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && !name.contains('\0')
}
