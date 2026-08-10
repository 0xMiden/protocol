use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use miden_mast_package::{Package, SectionId};
use semver::Version;

use super::{SchemaRequirement, StorageSchema, StorageValueName};
use crate::account::StorageSlotName;
use crate::errors::AccountError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// COMPONENT DEPENDENCY
// ================================================================================================

/// A requirement that an [`AccountComponent`](super::AccountComponent) places on the account it is
/// installed on, beyond what the component itself provides.
///
/// A component may read state that another component owns: the standard owner-gated policies, for
/// example, read the owner from a storage slot installed by the ownership component. Nothing in
/// the component's own code or storage schema records that expectation, so an account can be built
/// without the providing component and every procedure that reads the missing state then aborts at
/// runtime.
///
/// Declaring the requirement here through
/// [`AccountComponentMetadata::with_dependency`] moves that failure to account construction: the
/// account is only built if every declared dependency is satisfied.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ComponentDependency {
    /// A storage slot the component accesses but does not install itself. Any component installed
    /// on the same account may provide it.
    StorageSlot(StorageSlotName),
}

// ACCOUNT COMPONENT METADATA
// ================================================================================================

/// Represents the full component metadata configuration.
///
/// An account component metadata describes the component alongside its storage layout.
/// The storage layout can declare typed values which must be provided at instantiation time via
/// [InitStorageData](`super::storage::InitStorageData`). These can appear either at the slot level
/// (a singular word slot) or inside composed words as typed fields.
///
/// When the `std` feature is enabled, this struct allows for serialization and deserialization to
/// and from a TOML file.
///
/// # Guarantees
///
/// - The metadata's storage schema does not contain duplicate slot names.
/// - Each init-time value name uniquely identifies a single value. The expected init-time metadata
///   can be retrieved with [AccountComponentMetadata::schema_requirements()], which returns a map
///   from keys to [SchemaRequirement] (which indicates the expected value type and optional
///   defaults).
///
/// # Example
///
/// ```
/// use std::collections::BTreeMap;
///
/// use miden_protocol::account::StorageSlotName;
/// use miden_protocol::account::component::{
///     AccountComponentMetadata,
///     FeltSchema,
///     InitStorageData,
///     SchemaType,
///     StorageSchema,
///     StorageSlotSchema,
///     StorageValueName,
///     ValueSlotSchema,
///     WordSchema,
///     WordValue,
/// };
///
/// let slot_name = StorageSlotName::new("demo::test_value")?;
///
/// let word = WordSchema::new_value([
///     FeltSchema::new_void(),
///     FeltSchema::new_void(),
///     FeltSchema::new_void(),
///     FeltSchema::felt("foo"),
/// ]);
///
/// let storage_schema = StorageSchema::new([(
///     slot_name.clone(),
///     StorageSlotSchema::Value(ValueSlotSchema::new(Some("demo slot".into()), word)),
/// )])?;
///
/// let metadata = AccountComponentMetadata::new("test name")
///     .with_description("description of the component")
///     .with_storage_schema(storage_schema);
///
/// // Init value keys are derived from slot name: `demo::test_value.foo`.
/// let value_name = StorageValueName::from_slot_name_with_suffix(&slot_name, "foo")?;
/// let mut init_storage_data = InitStorageData::default();
/// init_storage_data.set_value(value_name, WordValue::Atomic("300".into()))?;
///
/// let storage_slots = metadata.storage_schema().build_storage_slots(&init_storage_data)?;
/// assert_eq!(storage_slots.len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "std", serde(rename_all = "kebab-case"))]
pub struct AccountComponentMetadata {
    /// The human-readable name of the component.
    name: String,

    /// A brief description of what this component is and how it works.
    description: String,

    /// The version of the component using semantic versioning.
    /// This can be used to track and manage component upgrades.
    version: Version,

    /// Storage schema defining the component's storage layout, defaults, and init-supplied values.
    #[cfg_attr(feature = "std", serde(rename = "storage"))]
    storage_schema: StorageSchema,

    /// Requirements the component places on the account it is installed on, checked when the
    /// account is built from its components.
    #[cfg_attr(feature = "std", serde(default, skip_serializing_if = "Vec::is_empty"))]
    dependencies: Vec<ComponentDependency>,
}

impl AccountComponentMetadata {
    /// Create a new [AccountComponentMetadata] with the given name.
    ///
    /// Other fields are initialized to sensible defaults:
    /// - `description`: empty string
    /// - `version`: 1.0.0
    /// - `storage_schema`: default (empty)
    /// - `dependencies`: empty
    ///
    /// Use the `with_*` mutator methods to customize these fields.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            version: Version::new(1, 0, 0),
            storage_schema: StorageSchema::default(),
            dependencies: Vec::new(),
        }
    }

    /// Sets the description of the component.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Sets the version of the component.
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// Sets the storage schema of the component.
    pub fn with_storage_schema(mut self, schema: StorageSchema) -> Self {
        self.storage_schema = schema;
        self
    }

    /// Adds a [`ComponentDependency`] the account must satisfy for this component to work.
    ///
    /// Account construction rejects an account that installs this component without satisfying
    /// the dependency.
    pub fn with_dependency(mut self, dependency: ComponentDependency) -> Self {
        self.dependencies.push(dependency);
        self
    }

    /// Returns the init-time values requirements for this schema.
    ///
    /// These values are used for initializing storage slot values or storage map entries. For a
    /// full example, refer to the docs for [AccountComponentMetadata].
    ///
    /// Types for returned init values are inferred based on their location in the storage layout.
    pub fn schema_requirements(&self) -> BTreeMap<StorageValueName, SchemaRequirement> {
        self.storage_schema.schema_requirements().expect("storage schema is validated")
    }

    /// Returns the name of the account component.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the description of the account component.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the semantic version of the account component.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Returns the storage schema of the component.
    pub fn storage_schema(&self) -> &StorageSchema {
        &self.storage_schema
    }

    /// Returns the requirements the component places on the account it is installed on.
    pub fn dependencies(&self) -> &[ComponentDependency] {
        &self.dependencies
    }
}

impl TryFrom<&Package> for AccountComponentMetadata {
    type Error = AccountError;

    fn try_from(package: &Package) -> Result<Self, Self::Error> {
        package
            .sections
            .iter()
            .find_map(|section| {
                (section.id == SectionId::ACCOUNT_COMPONENT_METADATA).then(|| {
                    AccountComponentMetadata::read_from_bytes(&section.data).map_err(|err| {
                        AccountError::other_with_source(
                            "failed to deserialize account component metadata",
                            err,
                        )
                    })
                })
            })
            .transpose()?
            .ok_or_else(|| {
                AccountError::other(
                    "package does not contain account component metadata section - packages without explicit metadata may be intended for other purposes (e.g., note scripts, transaction scripts)",
                )
            })
    }
}

// SERIALIZATION
// ================================================================================================

/// Tag written before a [`ComponentDependency`] to identify its variant.
const STORAGE_SLOT_DEPENDENCY_TAG: u8 = 0;

impl Serializable for ComponentDependency {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            ComponentDependency::StorageSlot(slot_name) => {
                STORAGE_SLOT_DEPENDENCY_TAG.write_into(target);
                slot_name.write_into(target);
            },
        }
    }
}

impl Deserializable for ComponentDependency {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match u8::read_from(source)? {
            STORAGE_SLOT_DEPENDENCY_TAG => {
                Ok(ComponentDependency::StorageSlot(StorageSlotName::read_from(source)?))
            },
            tag => Err(DeserializationError::InvalidValue(format!(
                "unknown component dependency tag {tag}"
            ))),
        }
    }
}

impl Serializable for AccountComponentMetadata {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.name.write_into(target);
        self.description.write_into(target);
        self.version.to_string().write_into(target);
        self.storage_schema.write_into(target);
        self.dependencies.write_into(target);
    }
}

impl Deserializable for AccountComponentMetadata {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name = String::read_from(source)?;
        let description = String::read_from(source)?;
        if !description.is_ascii() {
            return Err(DeserializationError::InvalidValue(
                "description must contain only ASCII characters".to_string(),
            ));
        }
        let version = semver::Version::from_str(&String::read_from(source)?)
            .map_err(|err: semver::Error| DeserializationError::InvalidValue(err.to_string()))?;
        let storage_schema = StorageSchema::read_from(source)?;
        let dependencies = Vec::<ComponentDependency>::read_from(source)?;

        Ok(Self {
            name,
            description,
            version,
            storage_schema,
            dependencies,
        })
    }
}
