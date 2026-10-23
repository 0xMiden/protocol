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

/// Describes a fixed-length array whose elements share a word schema.
///
/// Defaults must specify the whole array; defaults on the element schema are not supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArraySlotSchema {
    description: Option<String>,
    length: StorageArrayLength,
    element: WordSchema,
    default_values: Option<Vec<Word>>,
}

impl ArraySlotSchema {
    /// Creates a schema, validating the element type and any default values.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The description contains non-ASCII characters.
    /// - The element schema is invalid or has defaults of its own.
    /// - The default array does not match the declared length or element schema.
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

    /// Returns the optional description of the array slot.
    pub fn description(&self) -> Option<&String> {
        self.description.as_ref()
    }

    /// Returns the array length in words.
    pub fn length(&self) -> StorageArrayLength {
        self.length
    }

    /// Returns the schema shared by every word in the array.
    pub fn element(&self) -> &WordSchema {
        &self.element
    }

    /// Returns the complete default array, if one is provided.
    pub fn default_values(&self) -> Option<&[Word]> {
        self.default_values.as_deref()
    }

    /// Builds an array from initialization data, falling back to the complete default array.
    ///
    /// Initialization data must provide every word; it is not merged with the defaults.
    ///
    /// # Errors
    ///
    /// Returns an error if the slot has value or map entries, the array is missing, or its values
    /// do not match the declared length and element schema.
    pub fn try_build_array(
        &self,
        init_storage_data: &InitStorageData,
        slot_name: &StorageSlotName,
    ) -> Result<StorageArray, ComponentMetadataError> {
        let value_name = StorageValueName::from_slot_name(slot_name);
        if init_storage_data.has_value_entries_for_slot(slot_name)
            || init_storage_data.map_entries(slot_name).is_some()
        {
            return Err(ComponentMetadataError::InvalidInitStorageValue(
                value_name,
                "expected an array".into(),
            ));
        }
        let values = if let Some(values) = init_storage_data.array_values(slot_name) {
            if values.len() != self.length.as_usize() {
                return Err(ComponentMetadataError::InvalidInitStorageValue(
                    value_name,
                    "array values must match the declared length".into(),
                ));
            }
            values
                .iter()
                .map(|value| parse_storage_value_with_schema(&self.element, value, &value_name))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            self.default_values
                .clone()
                .ok_or_else(|| ComponentMetadataError::InitValueNotProvided(value_name.clone()))?
        };
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
