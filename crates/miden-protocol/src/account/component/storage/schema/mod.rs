use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use miden_core::utils::{ByteReader, ByteWriter, Deserializable, Serializable};
use miden_processor::DeserializationError;

use super::type_registry::SchemaRequirement;
use super::{InitStorageData, StorageValueName};
use crate::account::{StorageSlot, StorageSlotName};
use crate::crypto::utils::bytes_to_elements_with_padding;
use crate::errors::ComponentMetadataError;
use crate::{Hasher, Word};

mod felt;
pub use felt::FeltSchema;

mod map_slot;
pub use map_slot::MapSlotSchema;

mod parse;
pub(crate) use parse::parse_storage_value_with_schema;

mod slot;
pub use slot::StorageSlotSchema;

mod value_slot;
pub use value_slot::ValueSlotSchema;

mod word;
pub use word::WordSchema;

#[cfg(test)]
mod tests;

// STORAGE SCHEMA
// ================================================================================================

/// Describes the storage schema of an account component in terms of its named storage slots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StorageSchema {
    slots: BTreeMap<StorageSlotName, StorageSlotSchema>,
}

impl StorageSchema {
    /// Creates a new [`StorageSchema`].
    ///
    /// # Errors
    /// - If `fields` contains duplicate slot names.
    /// - If any slot schema is invalid.
    /// - If multiple schema fields map to the same init value name.
    pub fn new(
        slots: impl IntoIterator<Item = (StorageSlotName, StorageSlotSchema)>,
    ) -> Result<Self, ComponentMetadataError> {
        let mut map = BTreeMap::new();
        for (slot_name, schema) in slots {
            if map.insert(slot_name.clone(), schema).is_some() {
                return Err(ComponentMetadataError::DuplicateSlotName(slot_name));
            }
        }

        let schema = Self { slots: map };
        schema.validate()?;
        Ok(schema)
    }

    /// Returns an iterator over `(slot_name, schema)` pairs in slot-id order.
    pub fn iter(&self) -> impl Iterator<Item = (&StorageSlotName, &StorageSlotSchema)> {
        self.slots.iter()
    }

    /// Returns a reference to the underlying slots map.
    pub fn slots(&self) -> &BTreeMap<StorageSlotName, StorageSlotSchema> {
        &self.slots
    }

    /// Builds the initial [`StorageSlot`]s for this schema using the provided initialization data.
    pub fn build_storage_slots(
        &self,
        init_storage_data: &InitStorageData,
    ) -> Result<Vec<StorageSlot>, ComponentMetadataError> {
        self.slots
            .iter()
            .map(|(slot_name, schema)| schema.try_build_storage_slot(slot_name, init_storage_data))
            .collect()
    }

    /// Returns a commitment to this storage schema definition.
    ///
    /// The commitment is computed over the serialized schema and does not include defaults.
    pub fn commitment(&self) -> Word {
        let mut bytes = Vec::new();
        self.write_into_with_optional_defaults(&mut bytes, false);
        let elements = bytes_to_elements_with_padding(&bytes);
        Hasher::hash_elements(&elements)
    }

    /// Returns init-value requirements for the entire schema.
    ///
    /// The returned map includes both required values (no `default_value`) and optional values
    /// (with `default_value`), and excludes map entries.
    pub fn schema_requirements(
        &self,
    ) -> Result<BTreeMap<StorageValueName, SchemaRequirement>, ComponentMetadataError> {
        let mut requirements = BTreeMap::new();
        for (slot_name, schema) in self.slots.iter() {
            schema.collect_init_value_requirements(slot_name, &mut requirements)?;
        }
        Ok(requirements)
    }

    /// Serializes the schema, optionally ignoring the default values (used for committing to a
    /// schema definition).
    fn write_into_with_optional_defaults<W: ByteWriter>(
        &self,
        target: &mut W,
        include_defaults: bool,
    ) {
        target.write_u16(self.slots.len() as u16);
        for (slot_name, schema) in self.slots.iter() {
            target.write(slot_name);
            schema.write_into_with_optional_defaults(target, include_defaults);
        }
    }

    /// Validates schema-level invariants across all slots.
    fn validate(&self) -> Result<(), ComponentMetadataError> {
        let mut init_values = BTreeMap::new();

        for (slot_name, schema) in self.slots.iter() {
            schema.validate()?;
            schema.collect_init_value_requirements(slot_name, &mut init_values)?;
        }

        Ok(())
    }
}

impl Serializable for StorageSchema {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.write_into_with_optional_defaults(target, true);
    }
}

impl Deserializable for StorageSchema {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_entries = source.read_u16()? as usize;
        let mut fields = BTreeMap::new();

        for _ in 0..num_entries {
            let slot_name = StorageSlotName::read_from(source)?;
            let schema = StorageSlotSchema::read_from(source)?;

            if fields.insert(slot_name.clone(), schema).is_some() {
                return Err(DeserializationError::InvalidValue(format!(
                    "duplicate slot name in storage schema: {slot_name}",
                )));
            }
        }

        let schema = StorageSchema::new(fields)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
        Ok(schema)
    }
}

pub(super) fn validate_description_ascii(description: &str) -> Result<(), ComponentMetadataError> {
    if description.is_ascii() {
        Ok(())
    } else {
        Err(ComponentMetadataError::InvalidSchema(
            "description must contain only ASCII characters".to_string(),
        ))
    }
}
