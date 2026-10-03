use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

pub(crate) const MAX_SELECTION_ITEMS: usize = 512;
pub(crate) const MAX_SELECTION_FIELDS_PER_ITEM: usize = 512;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectionMode {
    #[default]
    Full,
    Selective,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ImportExportSelection {
    pub mode: SelectionMode,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    #[serde(deserialize_with = "deserialize_selection_fields")]
    pub fields: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SelectionFieldsInput {
    Map(HashMap<String, Vec<String>>),
    Sequence(Vec<serde::de::IgnoredAny>),
}

fn deserialize_selection_fields<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    match SelectionFieldsInput::deserialize(deserializer)? {
        SelectionFieldsInput::Map(fields) => Ok(fields),
        SelectionFieldsInput::Sequence(fields) if fields.is_empty() => Ok(HashMap::new()),
        SelectionFieldsInput::Sequence(_) => Err(D::Error::custom(
            "selection.fields must be an object or an empty array",
        )),
    }
}
