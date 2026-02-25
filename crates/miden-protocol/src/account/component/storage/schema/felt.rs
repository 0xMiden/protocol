use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use miden_core::utils::{ByteReader, ByteWriter, Deserializable, Serializable};
use miden_processor::DeserializationError;

use super::super::type_registry::{SCHEMA_TYPE_REGISTRY, SchemaRequirement, SchemaType};
use super::super::{InitStorageData, StorageValueName, WordValue};
use super::validate_description_ascii;
use crate::account::StorageSlotName;
use crate::errors::ComponentMetadataError;
use crate::{Felt, FieldElement};

// FELT SCHEMA
// ================================================================================================

/// Supported element schema descriptors for a component's storage entries.
///
/// Each felt element in a composed word slot is typed, can have an optional default value, and can
/// optionally be named to allow overriding at instantiation time.
///
/// To avoid non-overridable constants, unnamed elements are allowed only when `type = "void"`,
/// which always evaluates to `0` and does not require init data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeltSchema {
    name: Option<String>,
    description: Option<String>,
    r#type: SchemaType,
    default_value: Option<Felt>,
}

impl FeltSchema {
    /// Creates a new required typed felt field.
    pub fn new_typed(r#type: SchemaType, name: impl Into<String>) -> Self {
        FeltSchema {
            name: Some(name.into()),
            description: None,
            r#type,
            default_value: None,
        }
    }

    /// Creates a new typed felt field with a default value.
    pub fn new_typed_with_default(
        r#type: SchemaType,
        name: impl Into<String>,
        default_value: Felt,
    ) -> Self {
        FeltSchema {
            name: Some(name.into()),
            description: None,
            r#type,
            default_value: Some(default_value),
        }
    }

    /// Creates an unnamed `void` felt element.
    pub fn new_void() -> Self {
        FeltSchema {
            name: None,
            description: None,
            r#type: SchemaType::void(),
            default_value: None,
        }
    }

    /// Creates a new required felt field typed as [`SchemaType::native_felt()`].
    pub fn felt(name: impl Into<String>) -> Self {
        Self::new_typed(SchemaType::native_felt(), name)
    }

    /// Creates a new required felt field typed as [`SchemaType::native_word()`].
    pub fn word(name: impl Into<String>) -> Self {
        Self::new_typed(SchemaType::native_word(), name)
    }

    /// Creates a new required felt field typed as [`SchemaType::u8()`].
    pub fn u8(name: impl Into<String>) -> Self {
        Self::new_typed(SchemaType::u8(), name)
    }

    /// Creates a new required felt field typed as [`SchemaType::u16()`].
    pub fn u16(name: impl Into<String>) -> Self {
        Self::new_typed(SchemaType::u16(), name)
    }

    /// Creates a new required felt field typed as [`SchemaType::u32()`].
    pub fn u32(name: impl Into<String>) -> Self {
        Self::new_typed(SchemaType::u32(), name)
    }

    /// Sets the default value of the [`FeltSchema`] and returns `self`.
    pub fn with_default(self, default_value: Felt) -> Self {
        FeltSchema {
            default_value: Some(default_value),
            ..self
        }
    }

    /// Sets the description of the [`FeltSchema`] and returns `self`.
    pub fn with_description(self, description: impl Into<String>) -> Self {
        FeltSchema {
            description: Some(description.into()),
            ..self
        }
    }

    /// Returns the felt type.
    pub fn felt_type(&self) -> SchemaType {
        self.r#type.clone()
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn description(&self) -> Option<&String> {
        self.description.as_ref()
    }

    pub fn default_value(&self) -> Option<Felt> {
        self.default_value
    }

    pub(super) fn collect_init_value_requirements(
        &self,
        slot_prefix: StorageValueName,
        requirements: &mut BTreeMap<StorageValueName, SchemaRequirement>,
    ) -> Result<(), ComponentMetadataError> {
        if self.r#type == SchemaType::void() {
            return Ok(());
        }

        let Some(name) = self.name.as_deref() else {
            return Err(ComponentMetadataError::InvalidSchema(
                "non-void felt elements must be named".into(),
            ));
        };
        let value_name =
            StorageValueName::from_slot_name_with_suffix(slot_prefix.slot_name(), name)
                .map_err(|err| ComponentMetadataError::InvalidSchema(err.to_string()))?;

        let default_value = self
            .default_value
            .map(|felt| SCHEMA_TYPE_REGISTRY.display_felt(&self.r#type, felt));

        if requirements
            .insert(
                value_name.clone(),
                SchemaRequirement {
                    description: self.description.clone(),
                    r#type: self.r#type.clone(),
                    default_value,
                },
            )
            .is_some()
        {
            return Err(ComponentMetadataError::DuplicateInitValueName(value_name));
        }

        Ok(())
    }

    /// Attempts to convert the [`FeltSchema`] into a [`Felt`].
    ///
    /// If the schema variant is typed, the value is retrieved from `init_storage_data`,
    /// identified by its key. Otherwise, the returned value is just the inner element.
    pub(crate) fn try_build_felt(
        &self,
        init_storage_data: &InitStorageData,
        slot_name: &StorageSlotName,
    ) -> Result<Felt, ComponentMetadataError> {
        let value_name = match self.name.as_deref() {
            Some(name) => Some(
                StorageValueName::from_slot_name_with_suffix(slot_name, name)
                    .map_err(|err| ComponentMetadataError::InvalidSchema(err.to_string()))?,
            ),
            None => None,
        };

        if let Some(value_name) = value_name.clone()
            && let Some(raw_value) = init_storage_data.value_entry(&value_name)
        {
            match raw_value {
                WordValue::Atomic(raw) => {
                    let felt = SCHEMA_TYPE_REGISTRY
                        .try_parse_felt(&self.r#type, raw)
                        .map_err(ComponentMetadataError::StorageValueParsingError)?;
                    return Ok(felt);
                },
                WordValue::Elements(_) => {
                    return Err(ComponentMetadataError::InvalidInitStorageValue(
                        value_name,
                        "expected an atomic value, got a 4-element array".into(),
                    ));
                },
                WordValue::FullyTyped(_) => {
                    return Err(ComponentMetadataError::InvalidInitStorageValue(
                        value_name,
                        "expected an atomic value, got a word".into(),
                    ));
                },
            }
        }

        if self.r#type == SchemaType::void() {
            return Ok(Felt::ZERO);
        }

        if let Some(default_value) = self.default_value {
            return Ok(default_value);
        }

        let Some(value_name) = value_name else {
            return Err(ComponentMetadataError::InvalidSchema(
                "non-void felt elements must be named".into(),
            ));
        };

        Err(ComponentMetadataError::InitValueNotProvided(value_name))
    }

    /// Validates that the defined felt type exists.
    pub(super) fn validate(&self) -> Result<(), ComponentMetadataError> {
        if let Some(description) = self.description.as_deref() {
            validate_description_ascii(description)?;
        }

        let type_exists = SCHEMA_TYPE_REGISTRY.contains_felt_type(&self.felt_type());
        if !type_exists {
            return Err(ComponentMetadataError::InvalidType(
                self.felt_type().to_string(),
                "Felt".into(),
            ));
        }

        if self.r#type == SchemaType::void() {
            if self.name.is_some() {
                return Err(ComponentMetadataError::InvalidSchema(
                    "void felt elements must be unnamed".into(),
                ));
            }
            if self.default_value.is_some() {
                return Err(ComponentMetadataError::InvalidSchema(
                    "void felt elements cannot define `default-value`".into(),
                ));
            }
            return Ok(());
        }

        if self.name.is_none() {
            return Err(ComponentMetadataError::InvalidSchema(
                "non-void felt elements must be named".into(),
            ));
        }

        if let Some(value) = self.default_value {
            SCHEMA_TYPE_REGISTRY
                .validate_felt_value(&self.felt_type(), value)
                .map_err(ComponentMetadataError::StorageValueParsingError)?;
        }
        Ok(())
    }

    pub(super) fn write_into_with_optional_defaults<W: ByteWriter>(
        &self,
        target: &mut W,
        include_defaults: bool,
    ) {
        target.write(&self.name);
        target.write(&self.description);
        target.write(&self.r#type);
        let default_value = if include_defaults { self.default_value } else { None };
        target.write(default_value);
    }
}

impl Serializable for FeltSchema {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.write_into_with_optional_defaults(target, true);
    }
}

impl Deserializable for FeltSchema {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name = Option::<String>::read_from(source)?;
        let description = Option::<String>::read_from(source)?;
        let r#type = SchemaType::read_from(source)?;
        let default_value = Option::<Felt>::read_from(source)?;
        Ok(FeltSchema { name, description, r#type, default_value })
    }
}
