use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use core::str::FromStr;

use miden_crypto::utils::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use miden_mast_package::{Package, SectionId};
use semver::Version;

use super::{AccountStorageSchema, AccountType, SchemaRequirement, StorageValueName};
use crate::AccountError;

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
/// - The schema cannot contain protocol-reserved slot names.
/// - Each init-time value name uniquely identifies a single value. The expected init-time
///   requirements can be retrieved with [AccountComponentMetadata::schema_requirements()], which
///   returns a map from keys to [SchemaRequirement] (which indicates the expected value type and
///   optional defaults).
///
/// # Example
///
/// ```
/// use std::collections::BTreeSet;
///
/// use miden_protocol::account::StorageSlotName;
/// use miden_protocol::account::component::{
///     AccountComponentMetadata,
///     AccountStorageSchema,
///     FeltSchema,
///     InitStorageData,
///     SchemaTypeId,
///     StorageSlotSchema,
///     StorageValueName,
///     ValueSlotSchema,
///     WordSchema,
/// };
/// use semver::Version;
///
/// let slot_name = StorageSlotName::new("demo::test_value")?;
///
/// let word = WordSchema::new_value([
///     FeltSchema::new_void(),
///     FeltSchema::new_void(),
///     FeltSchema::new_void(),
///     FeltSchema::new_typed(SchemaTypeId::native_felt(), "foo"),
/// ]);
///
/// let storage_schema = AccountStorageSchema::new([(
///     slot_name.clone(),
///     StorageSlotSchema::Value(ValueSlotSchema::new(Some("demo slot".into()), word)),
/// )])?;
///
/// let metadata = AccountComponentMetadata::new(
///     "test name".into(),
///     "description of the component".into(),
///     Version::parse("0.1.0")?,
///     BTreeSet::new(),
///     storage_schema,
/// );
///
/// // Init value keys are derived from slot name: `demo::test_value.foo`.
/// let init_storage_data = InitStorageData::new(
///     [(StorageValueName::from_slot_name(&slot_name).with_suffix("foo")?, "300".into())],
///     [],
/// );
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

    /// A set of supported target account types for this component.
    supported_types: BTreeSet<AccountType>,

    /// Storage schema defining the component's storage layout, defaults, and init-supplied values.
    #[cfg_attr(feature = "std", serde(rename = "storage"))]
    storage_schema: AccountStorageSchema,
}

impl AccountComponentMetadata {
    /// Create a new [AccountComponentMetadata].
    pub fn new(
        name: String,
        description: String,
        version: Version,
        targets: BTreeSet<AccountType>,
        storage_schema: AccountStorageSchema,
    ) -> Self {
        Self {
            name,
            description,
            version,
            supported_types: targets,
            storage_schema,
        }
    }

    /// Returns the init-time value requirements for this schema.
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

    /// Returns the account types supported by the component.
    pub fn supported_types(&self) -> &BTreeSet<AccountType> {
        &self.supported_types
    }

    /// Returns the storage schema of the component.
    pub fn storage_schema(&self) -> &AccountStorageSchema {
        &self.storage_schema
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

impl Serializable for AccountComponentMetadata {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.name.write_into(target);
        self.description.write_into(target);
        self.version.to_string().write_into(target);
        self.supported_types.write_into(target);
        self.storage_schema.write_into(target);
    }
}

impl Deserializable for AccountComponentMetadata {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            name: String::read_from(source)?,
            description: String::read_from(source)?,
            version: semver::Version::from_str(&String::read_from(source)?).map_err(
                |err: semver::Error| DeserializationError::InvalidValue(err.to_string()),
            )?,
            supported_types: BTreeSet::<AccountType>::read_from(source)?,
            storage_schema: AccountStorageSchema::read_from(source)?,
        })
    }
}
