use alloc::string::{String, ToString};

use serde::de::Error as _;
use serde::ser::{Error as SerError, SerializeStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::super::type_registry::SCHEMA_TYPE_REGISTRY;
use super::super::{FeltSchema, SchemaType, WordValue};

// FELT SCHEMA SERIALIZATION
// ================================================================================================

impl Serialize for FeltSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.felt_type() == SchemaType::void() {
            let mut state = serializer.serialize_struct("FeltSchema", 2)?;
            state.serialize_field("type", &SchemaType::void())?;
            if let Some(description) = self.description() {
                state.serialize_field("description", description)?;
            }
            return state.end();
        }

        let name = self.name().ok_or_else(|| {
            SerError::custom("invalid FeltSchema: non-void elements must have a name")
        })?;

        let mut state = serializer.serialize_struct("FeltSchema", 4)?;
        state.serialize_field("name", name)?;
        if let Some(description) = self.description() {
            state.serialize_field("description", description)?;
        }
        if self.felt_type() != SchemaType::native_felt() {
            state.serialize_field("type", &self.felt_type())?;
        }
        if let Some(default_value) = self.default_value() {
            state.serialize_field(
                "default-value",
                &SCHEMA_TYPE_REGISTRY.display_felt(&self.felt_type(), default_value),
            )?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for FeltSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case", deny_unknown_fields)]
        struct RawFeltSchema {
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            description: Option<String>,
            #[serde(default, rename = "default-value")]
            default_value: Option<String>,
            #[serde(default, rename = "type")]
            r#type: Option<SchemaType>,
        }

        let raw = RawFeltSchema::deserialize(deserializer)?;

        let felt_type = raw.r#type.unwrap_or_else(SchemaType::native_felt);

        let description = raw.description.and_then(|description| {
            if description.trim().is_empty() {
                None
            } else {
                Some(description)
            }
        });

        if felt_type == SchemaType::void() {
            if raw.name.is_some() {
                return Err(D::Error::custom("`type = \"void\"` elements must omit `name`"));
            }
            if raw.default_value.is_some() {
                return Err(D::Error::custom(
                    "`type = \"void\"` elements cannot define `default-value`",
                ));
            }

            let schema = FeltSchema::new_void();
            return Ok(match description {
                Some(description) => schema.with_description(description),
                None => schema,
            });
        }

        let Some(name) = raw.name else {
            return Err(D::Error::custom("non-void elements must define `name`"));
        };

        let default_value = raw
            .default_value
            .map(|default_value| {
                SCHEMA_TYPE_REGISTRY.try_parse_felt(&felt_type, &default_value).map_err(|err| {
                    D::Error::custom(format!(
                        "failed to parse {felt_type} as Felt for `default-value`: {err}"
                    ))
                })
            })
            .transpose()?;

        let mut schema = FeltSchema::new_typed(felt_type, name);
        if let Some(default_value) = default_value {
            schema = schema.with_default(default_value);
        }
        Ok(match description {
            Some(description) => schema.with_description(description),
            None => schema,
        })
    }
}

// WORD VALUE SERIALIZATION
// ================================================================================================

impl Serialize for WordValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            WordValue::Atomic(value) => serializer.serialize_str(value),
            WordValue::Elements(elements) => elements.serialize(serializer),
            WordValue::FullyTyped(word) => serializer.serialize_str(&word.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for WordValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawWordValue {
            Atomic(String),
            Elements([String; 4]),
        }

        match RawWordValue::deserialize(deserializer)? {
            RawWordValue::Atomic(value) => Ok(WordValue::Atomic(value)),
            RawWordValue::Elements(elements) => Ok(WordValue::Elements(elements)),
        }
    }
}
