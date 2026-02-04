use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_core::{Felt, Word};
use semver::Version;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::super::{
    FeltSchema,
    MapSlotSchema,
    StorageSchema,
    StorageSlotSchema,
    StorageValueName,
    ValueSlotSchema,
    WordSchema,
    WordValue,
};
use crate::account::component::storage::type_registry::SCHEMA_TYPE_REGISTRY;
use crate::account::component::{AccountComponentMetadata, SchemaTypeId};
use crate::account::{AccountType, StorageSlotName};
use crate::errors::AccountComponentTemplateError;

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
    supported_types: BTreeSet<AccountType>,
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
    pub fn from_toml(toml_string: &str) -> Result<Self, AccountComponentTemplateError> {
        let raw: RawAccountComponentMetadata = toml::from_str(toml_string)
            .map_err(AccountComponentTemplateError::TomlDeserializationError)?;

        if !raw.description.is_ascii() {
            return Err(AccountComponentTemplateError::InvalidSchema(
                "description must contain only ASCII characters".to_string(),
            ));
        }

        let RawStorageSchema { slots } = raw.storage;
        let mut fields = Vec::with_capacity(slots.len());

        for slot in slots {
            fields.push(slot.try_into_slot_schema()?);
        }

        let storage_schema = StorageSchema::new(fields)?;
        Ok(Self::new(
            raw.name,
            raw.description,
            raw.version,
            raw.supported_types,
            storage_schema,
        ))
    }

    /// Serializes the account component metadata into a TOML string.
    pub fn to_toml(&self) -> Result<String, AccountComponentTemplateError> {
        let toml =
            toml::to_string(self).map_err(AccountComponentTemplateError::TomlSerializationError)?;
        Ok(toml)
    }
}

// ACCOUNT STORAGE SCHEMA SERIALIZATION
// ================================================================================================

/// Raw TOML storage schema:
///
/// - `[[storage.slots]]` for both value and map slots.
///
/// Slot kind is inferred by the shape of the `type` field:
/// - `type = "..."` or `type = [ ... ]` => value slot
/// - `type = { ... }` => map slot
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawStorageSchema {
    #[serde(default)]
    slots: Vec<RawStorageSlotSchema>,
}

/// Storage slot type descriptor.
///
/// This field accepts either:
/// - a type identifier (e.g. `"word"`, `"u16"`, `"miden::standards::auth::falcon512_rpo::pub_key"`)
///   for simple word slots,
/// - an array of 4 [`FeltSchema`] descriptors for composite word slots, or
/// - a table `{ key = ..., value = ... }` for map slots.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum RawSlotType {
    Word(RawWordType),
    Map(RawMapType),
}

/// A word type descriptor.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum RawWordType {
    TypeIdentifier(SchemaTypeId),
    FeltSchemaArray(Vec<FeltSchema>),
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

/// Raw storage slot schemas contain the raw representation that can get deserialized from TOML.
/// Specifically, it expresses the different combination of fields that expose the different types
/// of slots.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawStorageSlotSchema {
    /// The name of the storage slot, in `StorageSlotName` format (e.g.
    /// `my_project::module::slot`).
    name: String,
    #[serde(default)]
    description: Option<String>,
    /// Slot type descriptor.
    ///
    /// - If `type = { ... }`, this is a map slot.
    /// - If `type = [ ... ]`, this is a composite word slot whose schema is described by 4
    ///   [`FeltSchema`] descriptors.
    /// - Otherwise, if `type = "..."`, this is a simple word slot whose value is supplied at
    ///   instantiation time unless `default-value` is set (or the type is `void`).
    #[serde(rename = "type")]
    r#type: RawSlotType,
    /// The (overridable) default value for a simple word slot.
    #[serde(default)]
    default_value: Option<WordValue>,
    /// Default map entries.
    ///
    /// These entries must be fully-specified values. If the map should be populated at
    /// instantiation time, omit `default-values` and provide entries via init storage data.
    #[serde(default)]
    default_values: Option<Vec<RawMapEntrySchema>>,
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

        let key_type = match schema.key_schema() {
            WordSchema::Simple { r#type, .. } => RawWordType::TypeIdentifier(r#type.clone()),
            WordSchema::Composite { value } => RawWordType::FeltSchemaArray(value.to_vec()),
        };

        let value_type = match schema.value_schema() {
            WordSchema::Simple { r#type, .. } => RawWordType::TypeIdentifier(r#type.clone()),
            WordSchema::Composite { value } => RawWordType::FeltSchemaArray(value.to_vec()),
        };

        Self {
            name: slot_name.as_str().to_string(),
            description: schema.description().cloned(),
            r#type: RawSlotType::Map(RawMapType { key: key_type, value: value_type }),
            default_value: None,
            default_values,
        }
    }

    // DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Converts the raw representation into a tuple of the storage slot name and its schema.
    fn try_into_slot_schema(
        self,
    ) -> Result<(StorageSlotName, StorageSlotSchema), AccountComponentTemplateError> {
        let RawStorageSlotSchema {
            name,
            description,
            r#type,
            default_value,
            default_values,
        } = self;

        let slot_name_raw = name;
        let slot_name = StorageSlotName::new(slot_name_raw.clone()).map_err(|err| {
            AccountComponentTemplateError::InvalidSchema(format!(
                "invalid storage slot name `{slot_name_raw}`: {err}"
            ))
        })?;

        let description =
            description.and_then(|d| if d.trim().is_empty() { None } else { Some(d) });

        let slot_prefix = StorageValueName::from_slot_name(&slot_name);

        if default_value.is_some() && default_values.is_some() {
            return Err(AccountComponentTemplateError::InvalidSchema(
                "storage slot schema cannot define both `default-value` and `default-values`"
                    .into(),
            ));
        }

        match r#type {
            RawSlotType::Map(map_type) => {
                if default_value.is_some() {
                    return Err(AccountComponentTemplateError::InvalidSchema(
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
                    return Err(AccountComponentTemplateError::InvalidSchema(
                        "`default-values` can be specified only for map slots (use `type = { ... }`)"
                            .into(),
                    ));
                }

                match word_type {
                    RawWordType::TypeIdentifier(r#type) => {
                        if r#type.as_str() == "map" {
                            return Err(AccountComponentTemplateError::InvalidSchema(
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
                            return Err(AccountComponentTemplateError::InvalidSchema(
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
    ) -> Result<WordSchema, AccountComponentTemplateError> {
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
    ) -> Result<[FeltSchema; 4], AccountComponentTemplateError> {
        if elements.len() != 4 {
            return Err(AccountComponentTemplateError::InvalidSchema(format!(
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
    ) -> Result<BTreeMap<Word, Word>, AccountComponentTemplateError> {
        let mut map = BTreeMap::new();

        let parse = |schema: &WordSchema, raw: &WordValue, label: &str| {
            super::schema::parse_storage_value_with_schema(schema, raw, slot_prefix).map_err(
                |err| {
                    AccountComponentTemplateError::InvalidSchema(format!(
                        "invalid map `{label}`: {err}"
                    ))
                },
            )
        };

        for (index, entry) in entries.into_iter().enumerate() {
            let key_label = format!("default-values[{index}].key");
            let value_label = format!("default-values[{index}].value");

            let key = parse(key_schema, &entry.key, &key_label)?;
            let value = parse(value_schema, &entry.value, &value_label)?;

            if map.insert(key, value).is_some() {
                return Err(AccountComponentTemplateError::InvalidSchema(format!(
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
        schema_type: &SchemaTypeId,
        slot_prefix: &StorageValueName,
        label: &str,
    ) -> Result<Word, AccountComponentTemplateError> {
        let word = match self {
            WordValue::FullyTyped(word) => *word,
            WordValue::Atomic(value) => SCHEMA_TYPE_REGISTRY
                .try_parse_word(schema_type, value)
                .map_err(AccountComponentTemplateError::StorageValueParsingError)?,
            WordValue::Elements(elements) => {
                let felts = elements
                    .iter()
                    .map(|element| {
                        SCHEMA_TYPE_REGISTRY.try_parse_felt(&SchemaTypeId::native_felt(), element)
                    })
                    .collect::<Result<Vec<Felt>, _>>()
                    .map_err(AccountComponentTemplateError::StorageValueParsingError)?;
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

    pub(super) fn from_word(schema_type: &SchemaTypeId, word: Word) -> Self {
        WordValue::Atomic(SCHEMA_TYPE_REGISTRY.display_word(schema_type, word).value().to_string())
    }
}
