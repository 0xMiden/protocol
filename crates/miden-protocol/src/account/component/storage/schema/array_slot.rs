use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::super::type_registry::SCHEMA_TYPE_REGISTRY;
use super::super::{InitStorageData, StorageValueName};
use super::{WordSchema, parse_storage_value_with_schema, validate_description_ascii};
use crate::Word;
use crate::account::{StorageArray, StorageArrayLength, StorageSlotName};
use crate::errors::ComponentMetadataError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// ARRAY SLOT SCHEMA
// ================================================================================================

/// An array schema with a fixed length and a shared word schema.
/// Defaults must specify the whole array; element defaults are not supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArraySlotSchema {
    description: Option<String>,
    length: StorageArrayLength,
    element: WordSchema,
    default_values: Option<Vec<Word>>,
}

impl ArraySlotSchema {
    pub fn new(
        description: Option<String>,
        length: StorageArrayLength,
        element: WordSchema,
        default_values: Option<Vec<Word>>,
    ) -> Result<Self, ComponentMetadataError> {
        let schema = Self {
            description,
            length,
            element,
            default_values,
        };
        schema.validate()?;
        Ok(schema)
    }

    pub fn description(&self) -> Option<&String> {
        self.description.as_ref()
    }

    pub fn length(&self) -> StorageArrayLength {
        self.length
    }

    pub fn element(&self) -> &WordSchema {
        &self.element
    }

    pub fn default_values(&self) -> Option<&[Word]> {
        self.default_values.as_deref()
    }

    pub fn try_build_array(
        &self,
        init: &InitStorageData,
        name: &StorageSlotName,
    ) -> Result<StorageArray, ComponentMetadataError> {
        let value_name = StorageValueName::from_slot_name(name);
        if init.has_value_entries_for_slot(name) || init.map_entries(name).is_some() {
            return Err(ComponentMetadataError::InvalidInitStorageValue(
                value_name,
                "expected an array".into(),
            ));
        }
        let values = if let Some(values) = init.array_values(name) {
            values
                .iter()
                .map(|value| parse_storage_value_with_schema(&self.element, value, &value_name))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            self.default_values
                .clone()
                .ok_or_else(|| ComponentMetadataError::InitValueNotProvided(value_name.clone()))?
        };
        if values.len() != self.length.as_usize() {
            return Err(ComponentMetadataError::InvalidInitStorageValue(
                value_name,
                "array values must match the declared length".into(),
            ));
        }
        Ok(StorageArray::new(values)?)
    }

    pub(super) fn write_into_with_optional_defaults<W: ByteWriter>(
        &self,
        target: &mut W,
        include_defaults: bool,
    ) {
        target.write(&self.description);
        target.write(self.length);
        self.element.write_into_with_optional_defaults(target, include_defaults);
        let defaults = if include_defaults {
            self.default_values.as_ref()
        } else {
            None
        };
        target.write(defaults);
    }

    fn validate(&self) -> Result<(), ComponentMetadataError> {
        if let Some(description) = &self.description {
            validate_description_ascii(description)?;
        }
        self.element.validate()?;
        let has_element_defaults = match &self.element {
            WordSchema::Simple { default_value, .. } => default_value.is_some(),
            WordSchema::Composite { value } => {
                value.iter().any(|field| field.default_value().is_some())
            },
        };
        if has_element_defaults {
            return Err(ComponentMetadataError::InvalidSchema(
                "array defaults must be supplied as complete arrays".into(),
            ));
        }
        if let Some(values) = &self.default_values {
            if values.len() != self.length.as_usize() {
                return Err(ComponentMetadataError::InvalidSchema(
                    "array defaults must match the declared length".into(),
                ));
            }
            for &word in values {
                match &self.element {
                    WordSchema::Simple { r#type, .. } => SCHEMA_TYPE_REGISTRY
                        .validate_word_value(r#type, word)
                        .map_err(ComponentMetadataError::StorageValueParsingError)?,
                    WordSchema::Composite { value } => {
                        for (field, felt) in value.iter().zip(word) {
                            SCHEMA_TYPE_REGISTRY
                                .validate_felt_value(&field.felt_type(), felt)
                                .map_err(ComponentMetadataError::StorageValueParsingError)?;
                        }
                    },
                }
            }
        }
        Ok(())
    }
}

impl Serializable for ArraySlotSchema {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.write_into_with_optional_defaults(target, true);
    }
}

impl Deserializable for ArraySlotSchema {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::new(source.read()?, source.read()?, source.read()?, source.read()?)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}
