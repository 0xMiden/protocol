use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use miden_core::utils::{ByteReader, ByteWriter, Deserializable, Serializable};
use miden_processor::DeserializationError;

use super::super::type_registry::{SCHEMA_TYPE_REGISTRY, SchemaRequirement, SchemaTypeId};
use super::super::{InitStorageData, StorageValueName, WordValue};
use super::validate_description_ascii;
use crate::account::StorageSlotName;
use crate::errors::AccountComponentTemplateError;
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
    r#type: SchemaTypeId,
    default_value: Option<Felt>,
}

impl FeltSchema {
    /// Creates a new required typed felt field.
    pub fn new_typed(r#type: SchemaTypeId, name: impl Into<String>) -> Self {
        FeltSchema {
            name: Some(name.into()),
            description: None,
            r#type,
            default_value: None,
        }
    }

    /// Creates a new typed felt field with a default value.
    pub fn new_typed_with_default(
        r#type: SchemaTypeId,
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
            r#type: SchemaTypeId::void(),
            default_value: None,
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
    pub fn felt_type(&self) -> SchemaTypeId {
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
    ) -> Result<(), AccountComponentTemplateError> {
        if self.r#type == SchemaTypeId::void() {
            return Ok(());
        }

        let Some(name) = self.name.as_deref() else {
            return Err(AccountComponentTemplateError::InvalidSchema(
                "non-void felt elements must be named".into(),
            ));
        };
        let value_name =
            StorageValueName::from_slot_name_with_suffix(slot_prefix.slot_name(), name)
                .map_err(|err| AccountComponentTemplateError::InvalidSchema(err.to_string()))?;

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
            return Err(AccountComponentTemplateError::DuplicateInitValueName(value_name));
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
    ) -> Result<Felt, AccountComponentTemplateError> {
        let value_name = match self.name.as_deref() {
            Some(name) => Some(
                StorageValueName::from_slot_name_with_suffix(slot_name, name)
                    .map_err(|err| AccountComponentTemplateError::InvalidSchema(err.to_string()))?,
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
                        .map_err(AccountComponentTemplateError::StorageValueParsingError)?;
                    return Ok(felt);
                },
                WordValue::Elements(_) => {
                    return Err(AccountComponentTemplateError::InvalidInitStorageValue(
                        value_name,
                        "expected an atomic value, got a 4-element array".into(),
                    ));
                },
                WordValue::FullyTyped(_) => {
                    return Err(AccountComponentTemplateError::InvalidInitStorageValue(
                        value_name,
                        "expected an atomic value, got a word".into(),
                    ));
                },
            }
        }

        if self.r#type == SchemaTypeId::void() {
            return Ok(Felt::ZERO);
        }

        if let Some(default_value) = self.default_value {
            return Ok(default_value);
        }

        let Some(value_name) = value_name else {
            return Err(AccountComponentTemplateError::InvalidSchema(
                "non-void felt elements must be named".into(),
            ));
        };

        Err(AccountComponentTemplateError::InitValueNotProvided(value_name))
    }

    /// Validates that the defined felt type exists.
    pub(super) fn validate(&self) -> Result<(), AccountComponentTemplateError> {
        if let Some(description) = self.description.as_deref() {
            validate_description_ascii(description)?;
        }

        let type_exists = SCHEMA_TYPE_REGISTRY.contains_felt_type(&self.felt_type());
        if !type_exists {
            return Err(AccountComponentTemplateError::InvalidType(
                self.felt_type().to_string(),
                "Felt".into(),
            ));
        }

        if self.r#type == SchemaTypeId::void() {
            if self.name.is_some() {
                return Err(AccountComponentTemplateError::InvalidSchema(
                    "void felt elements must be unnamed".into(),
                ));
            }
            if self.default_value.is_some() {
                return Err(AccountComponentTemplateError::InvalidSchema(
                    "void felt elements cannot define `default-value`".into(),
                ));
            }
            return Ok(());
        }

        if self.name.is_none() {
            return Err(AccountComponentTemplateError::InvalidSchema(
                "non-void felt elements must be named".into(),
            ));
        }

        if let Some(value) = self.default_value {
            SCHEMA_TYPE_REGISTRY
                .validate_felt_value(&self.felt_type(), value)
                .map_err(AccountComponentTemplateError::StorageValueParsingError)?;
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
        let r#type = SchemaTypeId::read_from(source)?;
        let default_value = Option::<Felt>::read_from(source)?;
        Ok(FeltSchema { name, description, r#type, default_value })
    }
}
