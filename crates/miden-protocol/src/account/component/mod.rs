use alloc::vec::Vec;

use miden_mast_package::Package;
use miden_processor::mast::MastNodeExt;

mod metadata;
pub use metadata::*;

pub mod storage;
pub use storage::*;

mod code;
pub use code::AccountComponentCode;

use crate::MastForest;
use crate::account::{AccountProcedureRoot, StorageSlot};
use crate::assembly::Path;
use crate::errors::AccountError;

/// The attribute name used to mark the authentication procedure in an account component.
const AUTH_SCRIPT_ATTRIBUTE: &str = "auth_script";

/// The attribute name used to mark a procedure as a member of an account component's interface.
const ACCOUNT_PROCEDURE_ATTRIBUTE: &str = "account_procedure";

// ACCOUNT COMPONENT
// ================================================================================================

/// An [`AccountComponent`] defines a [`Package`](crate::assembly::Package) of code and the initial
/// value and types of the [`StorageSlot`]s it accesses.
///
/// One or more components can be used to build [`AccountCode`](crate::account::AccountCode) and
/// [`AccountStorage`](crate::account::AccountStorage).
///
/// Each component is independent of other components and can only access its own storage slots.
/// Each component defines its own storage layout starting at index 0 up to the length of the
/// storage slots vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountComponent {
    pub(super) code: AccountComponentCode,
    pub(super) storage_slots: Vec<StorageSlot>,
    pub(super) metadata: AccountComponentMetadata,
}

impl AccountComponent {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`AccountComponent`] constructed from the provided `library`,
    /// `storage_slots`, and `metadata`.
    ///
    /// Procedures exported from the provided code that are marked with the `@account_procedure`
    /// attribute or with `@auth_script` will become members of the account's public interface when
    /// added to an [`AccountCode`](crate::account::AccountCode).
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
        metadata: AccountComponentMetadata,
    ) -> Result<Self, AccountError> {
        // Check that we have less than 256 storage slots.
        u8::try_from(storage_slots.len())
            .map_err(|_| AccountError::StorageTooManySlots(storage_slots.len() as u64))?;

        Ok(Self {
            code: code.into(),
            storage_slots,
            metadata,
        })
    }

    /// Creates an [`AccountComponent`] from a [`Package`] using [`InitStorageData`].
    ///
    /// This method provides type safety by leveraging the component's metadata to validate
    /// storage initialization data. The package must contain explicit account component metadata.
    ///
    /// # Arguments
    ///
    /// * `package` - The package containing the account component metadata
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
        let library = package.clone();

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
    /// * `metadata` - The component's metadata, which describes the storage layout
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
        metadata: &AccountComponentMetadata,
        init_storage_data: &InitStorageData,
    ) -> Result<Self, AccountError> {
        let storage_slots = metadata
            .storage_schema()
            .build_storage_slots(init_storage_data)
            .map_err(|err| {
                AccountError::other_with_source("failed to instantiate account component", err)
            })?;

        AccountComponent::new(library.clone(), storage_slots, metadata.clone())
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

    /// Returns the component metadata.
    pub fn metadata(&self) -> &AccountComponentMetadata {
        &self.metadata
    }

    /// Returns the storage schema associated with this component.
    pub fn storage_schema(&self) -> &StorageSchema {
        self.metadata.storage_schema()
    }

    /// Returns an iterator over ([`AccountProcedureRoot`], is_auth) for all interface procedures
    /// in this component.
    ///
    /// A procedure is considered an authentication procedure if it has the `@auth_script`
    /// attribute. A procedure is part of the component interface if it has either the
    /// `@account_procedure` or `@auth_script` attributes.
    pub fn procedures(&self) -> impl Iterator<Item = (AccountProcedureRoot, bool)> + '_ {
        self.code.exports().map(|proc_export| {
            // When the export has a node id, use the forest node digest as the source of truth.
            // This keeps procedure roots tied to the actual component MAST forest.
            let digest = if let Some(node) = proc_export.node {
                self.code
                    .mast_forest()
                    .get_node_by_id(node)
                    .expect("export node not in the forest")
                    .digest()
            } else {
                proc_export.digest
            };
            let is_auth = proc_export.attributes.has(AUTH_SCRIPT_ATTRIBUTE);
            (AccountProcedureRoot::from_raw(digest), is_auth)
        })
    }

    /// Returns the [`AccountProcedureRoot`] of the procedure with the specified path, or `None`
    /// if it was not found in this component's library.
    pub fn get_procedure_root_by_path(
        &self,
        proc_name: impl AsRef<Path>,
    ) -> Option<AccountProcedureRoot> {
        self.code.get_procedure_root_by_path(proc_name)
    }

    /// Returns `true` if `root` is the procedure root of any procedure exported by this
    /// component.
    pub fn has_procedure(&self, root: AccountProcedureRoot) -> bool {
        self.procedures().any(|(proc_root, _)| proc_root == root)
    }
}

impl From<AccountComponent> for AccountComponentCode {
    fn from(component: AccountComponent) -> Self {
        component.code
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_mast_package::{Section, SectionId};
    use semver::Version;

    use super::*;
    use crate::testing::account_code::CODE;
    use crate::testing::assembler::assemble_test_library;
    use crate::utils::serde::Serializable;

    #[test]
    fn test_extract_metadata_from_package() {
        // Create a simple library for testing
        let library =
            assemble_test_library("test-extract-metadata", "test::extract_metadata", CODE);

        // Test with metadata
        let metadata = AccountComponentMetadata::new("test_component")
            .with_description("A test component")
            .with_version(Version::new(1, 0, 0));

        let metadata_bytes = metadata.to_bytes();
        let mut package_with_metadata = library.clone();
        package_with_metadata
            .sections
            .push(Section::new(SectionId::ACCOUNT_COMPONENT_METADATA, metadata_bytes.clone()));

        let extracted_metadata =
            AccountComponentMetadata::try_from(&package_with_metadata).unwrap();
        assert_eq!(extracted_metadata.name(), "test_component");

        // Test without metadata - should fail
        let package_without_metadata = library;

        let result = AccountComponentMetadata::try_from(&package_without_metadata);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("package does not contain account component metadata"));
    }

    #[test]
    fn test_from_library_with_init_data() {
        // Create a simple library for testing
        let library =
            assemble_test_library("test-from-library-init-data", "test::from_library", CODE);
        let component_code = AccountComponentCode::from(library.clone());

        // Create metadata for the component
        let metadata = AccountComponentMetadata::new("test_component")
            .with_description("A test component")
            .with_version(Version::new(1, 0, 0));

        // Test with empty init data - this tests the complete workflow:
        // Package + Metadata -> AccountComponent
        let init_data = InitStorageData::default();
        let component =
            AccountComponent::from_library(&component_code, &metadata, &init_data).unwrap();

        // Verify the component was created correctly
        assert_eq!(component.storage_size(), 0);

        // Test without metadata - should fail
        let package_without_metadata = library;

        let result = AccountComponent::from_package(&package_without_metadata, &init_data);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("package does not contain account component metadata"));
    }
}
