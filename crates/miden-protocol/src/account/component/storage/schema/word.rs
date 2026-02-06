use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use miden_core::utils::{ByteReader, ByteWriter, Deserializable, Serializable};
use miden_processor::DeserializationError;

use super::super::type_registry::{SCHEMA_TYPE_REGISTRY, SchemaRequirement, SchemaTypeId};
use super::super::{InitStorageData, StorageValueName};
use super::FeltSchema;
use crate::account::StorageSlotName;
use crate::errors::AccountComponentTemplateError;
use crate::{Felt, FieldElement, Word};

// WORD SCHEMA
// ================================================================================================

/// Defines how a word slot is described within the component's storage schema.
///
/// Each word schema can either describe a whole-word typed value supplied at instantiation time
/// (`Simple`) or a composite word that explicitly defines each felt element (`Composite`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum WordSchema {
    /// A whole-word typed value supplied at instantiation time.
    Simple {
        r#type: SchemaTypeId,
        default_value: Option<Word>,
    },
    /// A composed word that may mix defaults and typed fields.
    Composite { value: [FeltSchema; 4] },
}

impl WordSchema {
    pub fn new_simple(r#type: SchemaTypeId) -> Self {
        WordSchema::Simple { r#type, default_value: None }
    }

    pub fn new_simple_with_default(r#type: SchemaTypeId, default_value: Word) -> Self {
        WordSchema::Simple {
            r#type,
            default_value: Some(default_value),
        }
    }

    pub fn new_value(value: impl Into<[FeltSchema; 4]>) -> Self {
        WordSchema::Composite { value: value.into() }
    }

    pub fn value(&self) -> Option<&[FeltSchema; 4]> {
        match self {
            WordSchema::Composite { value } => Some(value),
            WordSchema::Simple { .. } => None,
        }
    }

    /// Returns the schema type identifier associated with whole-word init-supplied values.
    pub fn word_type(&self) -> SchemaTypeId {
        match self {
            WordSchema::Simple { r#type, .. } => r#type.clone(),
            WordSchema::Composite { .. } => SchemaTypeId::native_word(),
        }
    }

    pub(super) fn collect_init_value_requirements(
        &self,
        value_name: StorageValueName,
        description: Option<String>,
        requirements: &mut BTreeMap<StorageValueName, SchemaRequirement>,
    ) -> Result<(), AccountComponentTemplateError> {
        match self {
            WordSchema::Simple { r#type, default_value } => {
                if *r#type == SchemaTypeId::void() {
                    return Ok(());
                }

                let default_value = default_value.map(|word| {
                    SCHEMA_TYPE_REGISTRY.display_word(r#type, word).value().to_string()
                });

                if requirements
                    .insert(
                        value_name.clone(),
                        SchemaRequirement {
                            description,
                            r#type: r#type.clone(),
                            default_value,
                        },
                    )
                    .is_some()
                {
                    return Err(AccountComponentTemplateError::DuplicateInitValueName(value_name));
                }

                Ok(())
            },
            WordSchema::Composite { value } => {
                for felt in value.iter() {
                    felt.collect_init_value_requirements(value_name.clone(), requirements)?;
                }
                Ok(())
            },
        }
    }

    /// Validates that the defined word type exists and its inner felts (if any) are valid.
    pub(super) fn validate(&self) -> Result<(), AccountComponentTemplateError> {
        let type_exists = SCHEMA_TYPE_REGISTRY.contains_word_type(&self.word_type());
        if !type_exists {
            return Err(AccountComponentTemplateError::InvalidType(
                self.word_type().to_string(),
                "Word".into(),
            ));
        }

        if let WordSchema::Simple {
            r#type,
            default_value: Some(default_value),
        } = self
        {
            SCHEMA_TYPE_REGISTRY
                .validate_word_value(r#type, *default_value)
                .map_err(AccountComponentTemplateError::StorageValueParsingError)?;
        }

        if let Some(felts) = self.value() {
            for felt in felts {
                felt.validate()?;
            }
        }

        Ok(())
    }

    /// Builds a [`Word`] from the provided initialization data according to this schema.
    ///
    /// For simple schemas, expects a direct slot value (not map or field entries).
    /// For composite schemas, either parses a single value or builds the word from individual
    /// felt entries.
    pub(crate) fn try_build_word(
        &self,
        init_storage_data: &InitStorageData,
        slot_name: &StorageSlotName,
    ) -> Result<Word, AccountComponentTemplateError> {
        let slot_prefix = StorageValueName::from_slot_name(slot_name);
        let slot_value = init_storage_data.slot_value_entry(slot_name);
        let has_fields = init_storage_data.has_field_entries_for_slot(slot_name);

        if init_storage_data.map_entries(slot_name).is_some() {
            return Err(AccountComponentTemplateError::InvalidInitStorageValue(
                slot_prefix,
                "expected a value, got a map".into(),
            ));
        }

        match self {
            WordSchema::Simple { r#type, default_value } => {
                if has_fields {
                    return Err(AccountComponentTemplateError::InvalidInitStorageValue(
                        slot_prefix,
                        "expected a value, got field entries".into(),
                    ));
                }
                match slot_value {
                    Some(value) => {
                        super::parse_storage_value_with_schema(self, value, &slot_prefix)
                    },
                    None => {
                        if *r#type == SchemaTypeId::void() {
                            Ok(Word::empty())
                        } else {
                            default_value.as_ref().copied().ok_or_else(|| {
                                AccountComponentTemplateError::InitValueNotProvided(slot_prefix)
                            })
                        }
                    },
                }
            },
            WordSchema::Composite { value } => {
                if let Some(value) = slot_value {
                    if has_fields {
                        return Err(AccountComponentTemplateError::InvalidInitStorageValue(
                            slot_prefix,
                            "expected a single value, got both value and field entries".into(),
                        ));
                    }
                    return super::parse_storage_value_with_schema(self, value, &slot_prefix);
                }

                let mut result = [Felt::ZERO; 4];
                for (index, felt_schema) in value.iter().enumerate() {
                    result[index] = felt_schema.try_build_felt(init_storage_data, slot_name)?;
                }
                Ok(Word::from(result))
            },
        }
    }

    pub(crate) fn validate_word_value(
        &self,
        slot_prefix: &StorageValueName,
        label: &str,
        word: Word,
    ) -> Result<(), AccountComponentTemplateError> {
        match self {
            WordSchema::Simple { r#type, .. } => {
                SCHEMA_TYPE_REGISTRY.validate_word_value(r#type, word).map_err(|err| {
                    AccountComponentTemplateError::InvalidInitStorageValue(
                        slot_prefix.clone(),
                        format!("{label} does not match `{}`: {err}", r#type),
                    )
                })
            },
            WordSchema::Composite { value } => {
                for (index, felt_schema) in value.iter().enumerate() {
                    let felt_type = felt_schema.felt_type();
                    SCHEMA_TYPE_REGISTRY.validate_felt_value(&felt_type, word[index]).map_err(
                        |err| {
                            AccountComponentTemplateError::InvalidInitStorageValue(
                                slot_prefix.clone(),
                                format!("{label}[{index}] does not match `{felt_type}`: {err}"),
                            )
                        },
                    )?;
                }

                Ok(())
            },
        }
    }

    pub(super) fn write_into_with_optional_defaults<W: ByteWriter>(
        &self,
        target: &mut W,
        include_defaults: bool,
    ) {
        match self {
            WordSchema::Simple { r#type, default_value } => {
                target.write_u8(0);
                target.write(r#type);
                let default_value = if include_defaults { *default_value } else { None };
                target.write(default_value);
            },
            WordSchema::Composite { value } => {
                target.write_u8(1);
                for felt in value.iter() {
                    felt.write_into_with_optional_defaults(target, include_defaults);
                }
            },
        }
    }
}

impl Serializable for WordSchema {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.write_into_with_optional_defaults(target, true);
    }
}

impl Deserializable for WordSchema {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag = source.read_u8()?;
        match tag {
            0 => {
                let r#type = SchemaTypeId::read_from(source)?;
                let default_value = Option::<Word>::read_from(source)?;
                Ok(WordSchema::Simple { r#type, default_value })
            },
            1 => {
                let value = <[FeltSchema; 4]>::read_from(source)?;
                Ok(WordSchema::Composite { value })
            },
            other => Err(DeserializationError::InvalidValue(format!(
                "unknown tag '{other}' for WordSchema"
            ))),
        }
    }
}

impl From<[FeltSchema; 4]> for WordSchema {
    fn from(value: [FeltSchema; 4]) -> Self {
        WordSchema::new_value(value)
    }
}

impl From<[Felt; 4]> for WordSchema {
    fn from(value: [Felt; 4]) -> Self {
        WordSchema::new_simple_with_default(SchemaTypeId::native_word(), Word::from(value))
    }
}
