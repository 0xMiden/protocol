use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_core::{Felt, Word};
use semver::Version;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::super::{
    ArraySlotSchema,
    FeltSchema,
    MapSlotSchema,
    StorageSchema,
    StorageSlotSchema,
    StorageValueName,
    ValueSlotSchema,
    WordSchema,
    WordValue,
};
use super::schema::parse_storage_value_with_schema;
use crate::account::component::storage::type_registry::SCHEMA_TYPE_REGISTRY;
use crate::account::component::{AccountComponentMetadata, SchemaType};
use crate::account::{StorageArrayLength, StorageSlotName};
use crate::errors::ComponentMetadataError;

mod init_storage_data;
mod serde_impls;

#[cfg(test)]
mod tests;

// ACCOUNT COMPONENT METADATA TOML FROM/TO
// ================================================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawAccountComponentMetadata {
    name: String,
    description: String,
    version: Version,
    #[serde(rename = "storage")]
    #[serde(default)]
    storage: RawStorageSchema,
}

impl AccountComponentMetadata {
    /// Deserializes `toml_string` and validates the resulting [AccountComponentMetadata]
    ///
    /// # Errors
    ///
    /// - If deserialization fails
    /// - If the schema specifies storage slots with duplicates.
    /// - If the schema contains invalid slot definitions.
    pub fn from_toml(toml_string: &str) -> Result<Self, ComponentMetadataError> {
        let raw: RawAccountComponentMetadata = toml::from_str(toml_string)
            .map_err(ComponentMetadataError::TomlDeserializationError)?;

        if !raw.description.is_ascii() {
            return Err(ComponentMetadataError::InvalidSchema(
                "description must contain only ASCII characters".to_string(),
            ));
        }

        let RawStorageSchema { slots } = raw.storage;
        let mut fields = Vec::with_capacity(slots.len());

        for slot in slots {
            fields.push(slot.try_into_slot_schema()?);
        }

        let storage_schema = StorageSchema::new(fields)?;
        Ok(Self::new(raw.name)
            .with_description(raw.description)
            .with_version(raw.version)
            .with_storage_schema(storage_schema))
    }

    /// Serializes the account component metadata into a TOML string.
    pub fn to_toml(&self) -> Result<String, ComponentMetadataError> {
        let toml = toml::to_string(self).map_err(ComponentMetadataError::TomlSerializationError)?;
        Ok(toml)
    }
}

// ACCOUNT STORAGE SCHEMA SERIALIZATION
// ================================================================================================

/// TOML storage schema, with each slot declared in `[[storage.slots]]`.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawStorageSchema {
    #[serde(default)]
    slots: Vec<RawStorageSlotSchema>,
}

/// A TOML slot type:
/// - A type name such as `"word"` or `"u16"` for a simple value.
/// - Four [`FeltSchema`] descriptors for a composite value.
/// - `{ key = ..., value = ... }` for a map.
/// - `{ element = ..., length = N }` for an array.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum RawSlotType {
    Word(RawWordType),
    Map(RawMapType),
    Array(RawArrayType),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawArrayType {
    element: RawWordType,
    length: usize,
}

/// A word type descriptor.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum RawWordType {
    TypeIdentifier(SchemaType),
    FeltSchemaArray(Vec<FeltSchema>),
}

impl From<&WordSchema> for RawWordType {
    fn from(schema: &WordSchema) -> Self {
        match schema {
            WordSchema::Simple { r#type, .. } => Self::TypeIdentifier(r#type.clone()),
            WordSchema::Composite { value } => Self::FeltSchemaArray(value.to_vec()),
        }
    }
}

/// A map type descriptor.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawMapType {
    key: RawWordType,
    value: RawWordType,
}

// ACCOUNT STORAGE SCHEMA SERDE
// ================================================================================================

impl Serialize for StorageSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let slots = self
            .slots()
            .iter()
            .map(|(slot_name, schema)| RawStorageSlotSchema::from_slot(slot_name, schema))
            .collect();

        RawStorageSchema { slots }.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StorageSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // First, look at the raw representation
        let raw = RawStorageSchema::deserialize(deserializer)?;
        let mut fields = Vec::with_capacity(raw.slots.len());

        for slot in raw.slots {
            let (slot_name, schema) = slot.try_into_slot_schema().map_err(D::Error::custom)?;
            fields.push((slot_name, schema));
        }

        StorageSchema::new(fields).map_err(D::Error::custom)
    }
}

// ACCOUNT STORAGE SCHEMA SERDE HELPERS
// ================================================================================================

/// A TOML storage slot.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawStorageSlotSchema {
    /// The name of the storage slot, in `StorageSlotName` format (e.g.
    /// `my_project::module::slot`).
    name: String,
    #[serde(default)]
    description: Option<String>,
    /// Slot kind and element types.
    #[serde(rename = "type")]
    r#type: RawSlotType,
    /// The (overridable) default value for a simple word slot.
    #[serde(default)]
    default_value: Option<WordValue>,
    /// Default map entries, overridden or extended by initialization data.
    #[serde(default)]
    default_values: Option<Vec<RawMapEntrySchema>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_elements: Option<Vec<WordValue>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawMapEntrySchema {
    key: WordValue,
    value: WordValue,
}

impl RawStorageSlotSchema {
    // SERIALIZATION
    // --------------------------------------------------------------------------------------------

    fn from_slot(slot_name: &StorageSlotName, schema: &StorageSlotSchema) -> Self {
        match schema {
            StorageSlotSchema::Value(schema) => Self::from_value_slot(slot_name, schema),
            StorageSlotSchema::Map(schema) => Self::from_map_slot(slot_name, schema),
            StorageSlotSchema::Array(schema) => Self {
                name: slot_name.as_str().to_string(),
                description: schema.description().cloned(),
                r#type: RawSlotType::Array(RawArrayType {
                    element: schema.element().into(),
                    length: schema.length().as_usize(),
                }),
                default_value: None,
                default_values: None,
                default_elements: schema.default_values().map(|values| {
                    values
                        .iter()
                        .map(|word| WordValue::from_word(&schema.element().word_type(), *word))
                        .collect()
                }),
            },
        }
    }

    fn from_value_slot(slot_name: &StorageSlotName, schema: &ValueSlotSchema) -> Self {
        let word = schema.word();
        let (r#type, default_value) = match word {
            WordSchema::Simple { r#type, default_value } => (
                RawSlotType::Word(RawWordType::TypeIdentifier(r#type.clone())),
                default_value.map(|word| WordValue::from_word(r#type, word)),
            ),
            WordSchema::Composite { value } => {
                (RawSlotType::Word(RawWordType::FeltSchemaArray(value.to_vec())), None)
            },
        };

        Self {
            name: slot_name.as_str().to_string(),
            description: schema.description().cloned(),
            r#type,
            default_value,
            default_values: None,
            default_elements: None,
        }
    }

    fn from_map_slot(slot_name: &StorageSlotName, schema: &MapSlotSchema) -> Self {
        let default_values = schema.default_values().map(|default_values| {
            default_values
                .into_iter()
                .map(|(key, value)| RawMapEntrySchema {
                    key: WordValue::from_word(&schema.key_schema().word_type(), key),
                    value: WordValue::from_word(&schema.value_schema().word_type(), value),
                })
                .collect()
        });

        Self {
            name: slot_name.as_str().to_string(),
            description: schema.description().cloned(),
            r#type: RawSlotType::Map(RawMapType {
                key: schema.key_schema().into(),
                value: schema.value_schema().into(),
            }),
            default_value: None,
            default_values,
            default_elements: None,
        }
    }

    // DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Converts the raw representation into a tuple of the storage slot name and its schema.
    fn try_into_slot_schema(
        self,
    ) -> Result<(StorageSlotName, StorageSlotSchema), ComponentMetadataError> {
        let RawStorageSlotSchema {
            name,
            description,
            r#type,
            default_value,
            default_values,
            default_elements,
        } = self;

        let slot_name_raw = name;
        let slot_name = StorageSlotName::new(slot_name_raw.clone()).map_err(|err| {
            ComponentMetadataError::InvalidSchema(format!(
                "invalid storage slot name `{slot_name_raw}`: {err}"
            ))
        })?;

        let description = description.filter(|d| !d.trim().is_empty());

        let slot_prefix = StorageValueName::from_slot_name(&slot_name);

        if default_value.is_some() && default_values.is_some() {
            return Err(ComponentMetadataError::InvalidSchema(
                "storage slot schema cannot define both `default-value` and `default-values`"
                    .into(),
            ));
        }

        if default_elements.is_some() && !matches!(&r#type, RawSlotType::Array(_)) {
            return Err(ComponentMetadataError::InvalidSchema(
                "default-elements requires an array slot".into(),
            ));
        }
        match r#type {
            RawSlotType::Array(array_type) => {
                if default_value.is_some() || default_values.is_some() {
                    return Err(ComponentMetadataError::InvalidSchema(
                        "array slots use default-elements".into(),
                    ));
                }
                let length = StorageArrayLength::try_from(array_type.length)
                    .map_err(|err| ComponentMetadataError::InvalidSchema(err.to_string()))?;
                let element = Self::parse_word_schema(array_type.element, "type.element")?;
                let defaults = default_elements
                    .map(|values| {
                        values
                            .iter()
                            .map(|value| {
                                parse_storage_value_with_schema(&element, value, &slot_prefix)
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?;
                Ok((
                    slot_name,
                    StorageSlotSchema::Array(ArraySlotSchema::new(
                        description,
                        length,
                        element,
                        defaults,
                    )?),
                ))
            },
            RawSlotType::Map(map_type) => {
                if default_value.is_some() {
                    return Err(ComponentMetadataError::InvalidSchema(
                        "map slots cannot define `default-value`".into(),
                    ));
                }

                let RawMapType { key: key_type, value: value_type } = map_type;
                let key_schema = Self::parse_word_schema(key_type, "`type.key`")?;
                let value_schema = Self::parse_word_schema(value_type, "`type.value`")?;

                let default_values = default_values
                    .map(|entries| {
                        Self::parse_default_map_entries(
                            entries,
                            &key_schema,
                            &value_schema,
                            &slot_prefix,
                        )
                    })
                    .transpose()?;

                Ok((
                    slot_name,
                    StorageSlotSchema::Map(MapSlotSchema::new(
                        description,
                        default_values,
                        key_schema,
                        value_schema,
                    )),
                ))
            },

            RawSlotType::Word(word_type) => {
                if default_values.is_some() {
                    return Err(ComponentMetadataError::InvalidSchema(
                        "`default-values` can be specified only for map slots (use `type = { ... }`)"
                            .into(),
                    ));
                }

                match word_type {
                    RawWordType::TypeIdentifier(r#type) => {
                        if r#type.as_str() == "map" {
                            return Err(ComponentMetadataError::InvalidSchema(
                                "value slots cannot use `type = \"map\"`; use `type = { key = <key-type>, value = <value-type>}` instead"
                                    .into(),
                            ));
                        }

                        let word = default_value
                            .as_ref()
                            .map(|default_value| {
                                default_value.try_parse_as_typed_word(
                                    &r#type,
                                    &slot_prefix,
                                    "default value",
                                )
                            })
                            .transpose()?;

                        let word_schema = match word {
                            Some(word) => WordSchema::new_simple_with_default(r#type, word),
                            None => WordSchema::new_simple(r#type),
                        };

                        Ok((
                            slot_name,
                            StorageSlotSchema::Value(ValueSlotSchema::new(
                                description,
                                word_schema,
                            )),
                        ))
                    },

                    RawWordType::FeltSchemaArray(elements) => {
                        if default_value.is_some() {
                            return Err(ComponentMetadataError::InvalidSchema(
                                "composite word slots cannot define `default-value`".into(),
                            ));
                        }

                        let elements = Self::parse_felt_schema_array(elements, "word slot `type`")?;
                        Ok((
                            slot_name,
                            StorageSlotSchema::Value(ValueSlotSchema::new(
                                description,
                                WordSchema::new_value(elements),
                            )),
                        ))
                    },
                }
            },
        }
    }

    fn parse_word_schema(
        raw: RawWordType,
        label: &str,
    ) -> Result<WordSchema, ComponentMetadataError> {
        match raw {
            RawWordType::TypeIdentifier(r#type) => Ok(WordSchema::new_simple(r#type)),
            RawWordType::FeltSchemaArray(elements) => {
                let elements = Self::parse_felt_schema_array(elements, label)?;
                Ok(WordSchema::new_value(elements))
            },
        }
    }

    fn parse_felt_schema_array(
        elements: Vec<FeltSchema>,
        label: &str,
    ) -> Result<[FeltSchema; 4], ComponentMetadataError> {
        if elements.len() != 4 {
            return Err(ComponentMetadataError::InvalidSchema(format!(
                "{label} must be an array of 4 elements, got {}",
                elements.len()
            )));
        }
        Ok(elements.try_into().expect("length is 4"))
    }

    fn parse_default_map_entries(
        entries: Vec<RawMapEntrySchema>,
        key_schema: &WordSchema,
        value_schema: &WordSchema,
        slot_prefix: &StorageValueName,
    ) -> Result<BTreeMap<Word, Word>, ComponentMetadataError> {
        let mut map = BTreeMap::new();

        let parse = |schema: &WordSchema, raw: &WordValue, label: &str| {
            parse_storage_value_with_schema(schema, raw, slot_prefix).map_err(|err| {
                ComponentMetadataError::InvalidSchema(format!("invalid map `{label}`: {err}"))
            })
        };

        for (index, entry) in entries.into_iter().enumerate() {
            let key_label = format!("default-values[{index}].key");
            let value_label = format!("default-values[{index}].value");

            let key = parse(key_schema, &entry.key, &key_label)?;
            let value = parse(value_schema, &entry.value, &value_label)?;

            if map.insert(key, value).is_some() {
                return Err(ComponentMetadataError::InvalidSchema(format!(
                    "map storage slot `default-values[{index}]` contains a duplicate key"
                )));
            }
        }

        Ok(map)
    }
}

impl WordValue {
    pub(super) fn try_parse_as_typed_word(
        &self,
        schema_type: &SchemaType,
        slot_prefix: &StorageValueName,
        label: &str,
    ) -> Result<Word, ComponentMetadataError> {
        let word = match self {
            WordValue::FullyTyped(word) => *word,
            WordValue::Atomic(value) => SCHEMA_TYPE_REGISTRY
                .try_parse_word(schema_type, value)
                .map_err(ComponentMetadataError::StorageValueParsingError)?,
            WordValue::Elements(elements) => {
                let felts = elements
                    .iter()
                    .map(|element| {
                        SCHEMA_TYPE_REGISTRY.try_parse_felt(&SchemaType::native_felt(), element)
                    })
                    .collect::<Result<Vec<Felt>, _>>()
                    .map_err(ComponentMetadataError::StorageValueParsingError)?;
                let felts: [Felt; 4] = felts.try_into().expect("length is 4");
                Word::from(felts)
            },
        };

        WordSchema::new_simple(schema_type.clone()).validate_word_value(
            slot_prefix,
            label,
            word,
        )?;
        Ok(word)
    }

    pub(super) fn from_word(schema_type: &SchemaType, word: Word) -> Self {
        WordValue::Atomic(SCHEMA_TYPE_REGISTRY.display_word(schema_type, word).value().to_string())
    }
}
