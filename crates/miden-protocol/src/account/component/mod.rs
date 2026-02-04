use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_mast_package::{MastArtifact, Package};

mod metadata;
pub use metadata::*;

pub mod storage;
pub use storage::*;

mod code;
pub use code::AccountComponentCode;

use crate::account::{AccountType, StorageSlot};
use crate::assembly::Path;
use crate::errors::AccountError;
use crate::{MastForest, Word};

// ACCOUNT COMPONENT
// ================================================================================================

/// An [`AccountComponent`] defines a [`Library`](miden_assembly::Library) of code and the initial
/// value and types of the [`StorageSlot`]s it accesses.
///
/// One or more components can be used to built [`AccountCode`](crate::account::AccountCode) and
/// [`AccountStorage`](crate::account::AccountStorage).
///
/// Each component is independent of other components and can only access its own storage slots.
/// Each component defines its own storage layout starting at index 0 up to the length of the
/// storage slots vector.
///
/// Components define the [`AccountType`]s they support, meaning whether the component can be used
/// to instantiate an account of that type. For example, a component implementing a fungible faucet
/// would only specify support for [`AccountType::FungibleFaucet`]. Using it to instantiate a
/// regular account would fail. By default, the set of supported types is empty, so each component
/// is forced to explicitly define what it supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountComponent {
    pub(super) code: AccountComponentCode,
    pub(super) storage_slots: Vec<StorageSlot>,
    pub(super) metadata: Option<AccountComponentMetadata>,
    pub(super) supported_types: BTreeSet<AccountType>,
}

impl AccountComponent {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`AccountComponent`] constructed from the provided `library` and
    /// `storage_slots`.
    ///
    /// All procedures exported from the provided code will become members of the account's public
    /// interface when added to an [`AccountCode`](crate::account::AccountCode).
    ///
    /// # Errors
    ///
    /// The following list of errors is exhaustive and can be relied upon for `expect`ing the call
    /// to this function. It is recommended that custom components ensure these conditions by design
    /// or in their fallible constructors.
    ///
    /// Returns an error if:
    /// - The number of given [`StorageSlot`]s exceeds 255.
    pub fn new(
        code: impl Into<AccountComponentCode>,
        storage_slots: Vec<StorageSlot>,
    ) -> Result<Self, AccountError> {
        // Check that we have less than 256 storage slots.
        u8::try_from(storage_slots.len())
            .map_err(|_| AccountError::StorageTooManySlots(storage_slots.len() as u64))?;

        Ok(Self {
            code: code.into(),
            storage_slots,
            metadata: None,
            supported_types: BTreeSet::new(),
        })
    }

    /// Creates an [`AccountComponent`] from a [`Package`] using [`InitStorageData`].
    ///
    /// This method provides type safety by leveraging the component's metadata to validate
    /// storage initialization data. The package must contain explicit account component metadata.
    ///
    /// # Arguments
    ///
    /// * `package` - The package containing the [`Library`](miden_assembly::Library) and account
    ///   component metadata
    /// * `init_storage_data` - The initialization data for storage slots
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The package does not contain a library artifact
    /// - The package does not contain account component metadata
    /// - The metadata cannot be deserialized from the package
    /// - The storage initialization fails due to invalid or missing data
    /// - The component creation fails
    pub fn from_package(
        package: &Package,
        init_storage_data: &InitStorageData,
    ) -> Result<Self, AccountError> {
        let metadata = AccountComponentMetadata::try_from(package)?;
        let library = match &package.mast {
            MastArtifact::Library(library) => library.as_ref().clone(),
            MastArtifact::Executable(_) => {
                return Err(AccountError::other(
                    "expected Package to contain a library, but got an executable",
                ));
            },
        };

        let component_code = AccountComponentCode::from(library);
        Self::from_library(&component_code, &metadata, init_storage_data)
    }

    /// Creates an [`AccountComponent`] from an [`AccountComponentCode`] and
    /// [`AccountComponentMetadata`].
    ///
    /// This method provides type safety by leveraging the component's metadata to validate
    /// the passed storage initialization data ([`InitStorageData`]).
    ///
    /// # Arguments
    ///
    /// * `library` - The component's assembled code
    /// * `account_component_metadata` - The component's metadata, which describes the storage
    ///   layout
    /// * `init_storage_data` - The initialization data for storage slots
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The package does not contain a library artifact
    /// - The package does not contain account component metadata
    /// - The metadata cannot be deserialized from the package
    /// - The storage initialization fails due to invalid or missing data
    /// - The component creation fails
    pub fn from_library(
        library: &AccountComponentCode,
        account_component_metadata: &AccountComponentMetadata,
        init_storage_data: &InitStorageData,
    ) -> Result<Self, AccountError> {
        let storage_slots = account_component_metadata
            .storage_schema()
            .build_storage_slots(init_storage_data)
            .map_err(|err| {
                AccountError::other_with_source("failed to instantiate account component", err)
            })?;

        Ok(AccountComponent::new(library.clone(), storage_slots)?
            .with_metadata(account_component_metadata.clone()))
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of storage slots accessible from this component.
    pub fn storage_size(&self) -> u8 {
        u8::try_from(self.storage_slots.len())
            .expect("storage slots len should fit in u8 per the constructor")
    }

    /// Returns a reference to the underlying [`AccountComponentCode`] of this component.
    pub fn component_code(&self) -> &AccountComponentCode {
        &self.code
    }

    /// Returns a reference to the underlying [`MastForest`] of this component.
    pub fn mast_forest(&self) -> &MastForest {
        self.code.mast_forest()
    }

    /// Returns a slice of the underlying [`StorageSlot`]s of this component.
    pub fn storage_slots(&self) -> &[StorageSlot] {
        self.storage_slots.as_slice()
    }

    /// Returns the component metadata, if any.
    pub fn metadata(&self) -> Option<&AccountComponentMetadata> {
        self.metadata.as_ref()
    }

    /// Returns the storage schema associated with this component, if any.
    pub fn storage_schema(&self) -> Option<&StorageSchema> {
        self.metadata.as_ref().map(AccountComponentMetadata::storage_schema)
    }

    /// Returns a reference to the supported [`AccountType`]s.
    pub fn supported_types(&self) -> &BTreeSet<AccountType> {
        &self.supported_types
    }

    /// Returns `true` if this component supports the given `account_type`, `false` otherwise.
    pub fn supports_type(&self, account_type: AccountType) -> bool {
        self.supported_types.contains(&account_type)
    }

    /// Returns a vector of tuples (digest, is_auth) for all procedures in this component.
    pub fn get_procedures(&self) -> Vec<(Word, bool)> {
        let mut procedures = Vec::new();
        for module in self.code.as_library().module_infos() {
            for (_, procedure_info) in module.procedures() {
                let is_auth = procedure_info.name.starts_with("auth_");
                procedures.push((procedure_info.digest, is_auth));
            }
        }
        procedures
    }

    /// Returns the digest of the procedure with the specified path, or `None` if it was not found
    /// in this component's library or its library path is malformed.
    pub fn get_procedure_root_by_path(&self, proc_name: impl AsRef<Path>) -> Option<Word> {
        self.code.as_library().get_procedure_root_by_path(proc_name)
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds `supported_type` to the set of [`AccountType`]s supported by this component.
    ///
    /// This function has the semantics of [`BTreeSet::insert`], i.e. adding a type twice is fine
    /// and it can be called multiple times with different account types.
    pub fn with_supported_type(mut self, supported_type: AccountType) -> Self {
        self.supported_types.insert(supported_type);
        self
    }

    /// Overwrites any previously set supported types with the given set.
    ///
    /// This can be used to reset the supported types of a component to a chosen set, which may be
    /// useful after cloning an existing component.
    pub fn with_supported_types(mut self, supported_types: BTreeSet<AccountType>) -> Self {
        self.supported_types = supported_types;
        self
    }

    /// Attaches metadata to this component for downstream schema commitments and introspection.
    pub fn with_metadata(mut self, metadata: AccountComponentMetadata) -> Self {
        self.supported_types = metadata.supported_types().clone();
        self.metadata = Some(metadata);
        self
    }

    /// Sets the [`AccountType`]s supported by this component to all account types.
    pub fn with_supports_all_types(mut self) -> Self {
        self.supported_types.extend([
            AccountType::FungibleFaucet,
            AccountType::NonFungibleFaucet,
            AccountType::RegularAccountImmutableCode,
            AccountType::RegularAccountUpdatableCode,
        ]);
        self
    }
}

impl From<AccountComponent> for AccountComponentCode {
    fn from(component: AccountComponent) -> Self {
        component.code
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;
    use alloc::string::ToString;
    use alloc::sync::Arc;

    use miden_assembly::Assembler;
    use miden_core::utils::Serializable;
    use miden_mast_package::{
        MastArtifact,
        Package,
        PackageKind,
        PackageManifest,
        Section,
        SectionId,
    };
    use semver::Version;

    use super::*;
    use crate::testing::account_code::CODE;

    #[test]
    fn test_extract_metadata_from_package() {
        // Create a simple library for testing
        let library = Assembler::default().assemble_library([CODE]).unwrap();

        // Test with metadata
        let metadata = AccountComponentMetadata::new(
            "test_component".to_string(),
            "A test component".to_string(),
            Version::new(1, 0, 0),
            BTreeSet::from_iter([AccountType::RegularAccountImmutableCode]),
            StorageSchema::default(),
        );

        let metadata_bytes = metadata.to_bytes();
        let package_with_metadata = Package {
            name: "test_package".to_string(),
            mast: MastArtifact::Library(Arc::new(library.clone())),
            manifest: PackageManifest::new(None),
            kind: PackageKind::AccountComponent,
            sections: vec![Section::new(
                SectionId::ACCOUNT_COMPONENT_METADATA,
                metadata_bytes.clone(),
            )],
            version: Default::default(),
            description: None,
        };

        let extracted_metadata =
            AccountComponentMetadata::try_from(&package_with_metadata).unwrap();
        assert_eq!(extracted_metadata.name(), "test_component");
        assert!(
            extracted_metadata
                .supported_types()
                .contains(&AccountType::RegularAccountImmutableCode)
        );

        // Test without metadata - should fail
        let package_without_metadata = Package {
            name: "test_package_no_metadata".to_string(),
            mast: MastArtifact::Library(Arc::new(library)),
            manifest: PackageManifest::new(None),
            kind: PackageKind::AccountComponent,
            sections: vec![], // No metadata section
            version: Default::default(),
            description: None,
        };

        let result = AccountComponentMetadata::try_from(&package_without_metadata);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("package does not contain account component metadata"));
    }

    #[test]
    fn test_from_library_with_init_data() {
        // Create a simple library for testing
        let library = Assembler::default().assemble_library([CODE]).unwrap();
        let component_code = AccountComponentCode::from(library.clone());

        // Create metadata for the component
        let metadata = AccountComponentMetadata::new(
            "test_component".to_string(),
            "A test component".to_string(),
            Version::new(1, 0, 0),
            BTreeSet::from_iter([
                AccountType::RegularAccountImmutableCode,
                AccountType::RegularAccountUpdatableCode,
            ]),
            StorageSchema::default(),
        );

        // Test with empty init data - this tests the complete workflow:
        // Library + Metadata -> AccountComponent
        let init_data = InitStorageData::default();
        let component =
            AccountComponent::from_library(&component_code, &metadata, &init_data).unwrap();

        // Verify the component was created correctly
        assert_eq!(component.storage_size(), 0);
        assert!(component.supports_type(AccountType::RegularAccountImmutableCode));
        assert!(component.supports_type(AccountType::RegularAccountUpdatableCode));
        assert!(!component.supports_type(AccountType::FungibleFaucet));

        // Test without metadata - should fail
        let package_without_metadata = Package {
            name: "test_package_no_metadata".to_string(),
            mast: MastArtifact::Library(Arc::new(library)),
            kind: PackageKind::AccountComponent,
            manifest: PackageManifest::new(None),
            sections: vec![], // No metadata section
            version: Default::default(),
            description: None,
        };

        let result = AccountComponent::from_package(&package_without_metadata, &init_data);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("package does not contain account component metadata"));
    }
}
