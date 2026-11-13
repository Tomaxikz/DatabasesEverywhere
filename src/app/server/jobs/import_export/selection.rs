use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use utoipa::openapi::{Array, ArrayBuilder, Object, ObjectBuilder, Type};

pub(crate) const MAX_SELECTION_ITEMS: usize = 512;
pub(crate) const MAX_SELECTION_FIELDS_PER_ITEM: usize = 512;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(default = "full")]
pub enum SelectionMode {
    #[default]
    Full,
    Selective,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ImportExportSelection {
    #[schema(inline)]
    pub mode: SelectionMode,
    #[schema(schema_with = selection_names_schema)]
    pub include: Vec<String>,
    #[schema(schema_with = selection_names_schema)]
    pub exclude: Vec<String>,
    #[serde(deserialize_with = "deserialize_selection_fields")]
    #[schema(schema_with = selection_fields_schema)]
    pub fields: HashMap<String, Vec<String>>,
}

fn selection_names_schema() -> Array {
    let name = ObjectBuilder::new()
        .schema_type(Type::String)
        .max_length(Some(257));
    ArrayBuilder::new()
        .items(name)
        .max_items(Some(MAX_SELECTION_ITEMS))
        .build()
}

fn selection_fields_schema() -> Object {
    let field = ObjectBuilder::new()
        .schema_type(Type::String)
        .max_length(Some(128));
    let fields = ArrayBuilder::new()
        .items(field)
        .max_items(Some(MAX_SELECTION_FIELDS_PER_ITEM));
    ObjectBuilder::new()
        .schema_type(Type::Object)
        .max_properties(Some(MAX_SELECTION_ITEMS))
        .additional_properties(Some(fields))
        .build()
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
