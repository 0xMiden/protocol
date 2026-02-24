use alloc::collections::BTreeMap;

use miden_protocol::Word;
use miden_protocol::account::component::{AccountComponentMetadata, StorageSchema};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::{AccountError, ComponentMetadataError};
use miden_protocol::utils::sync::LazyLock;

use crate::account::components::storage_schema_library;

pub static SCHEMA_COMMITMENT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::metadata::storage_schema")
        .expect("storage slot name should be valid")
});

/// An [`AccountComponent`] exposing the account storage schema commitment.
///
/// The [`AccountSchemaCommitment`] component can be constructed from a list of [`StorageSchema`],
/// from which a commitment is computed and then inserted into the [`SCHEMA_COMMITMENT_SLOT_NAME`]
/// slot.
///
/// It reexports the `get_schema_commitment` procedure from
/// `miden::standards::metadata::storage_schema`.
///
/// ## Storage Layout
///
/// - [`Self::schema_commitment_slot`]: Storage schema commitment.
pub struct AccountSchemaCommitment {
    schema_commitment: Word,
}

impl AccountSchemaCommitment {
    /// Creates a new [`AccountSchemaCommitment`] component from storage schemas.
    ///
    /// The input schemas are merged into a single schema before the final commitment is computed.
    ///
    /// # Errors
    ///
    /// Returns an error if the schemas contain conflicting definitions for the same slot name.
    pub fn new<'a>(
        schemas: impl IntoIterator<Item = &'a StorageSchema>,
    ) -> Result<Self, ComponentMetadataError> {
        Ok(Self {
            schema_commitment: compute_schema_commitment(schemas)?,
        })
    }

    /// Creates a new [`AccountSchemaCommitment`] component from a [`StorageSchema`].
    pub fn from_schema(storage_schema: &StorageSchema) -> Result<Self, ComponentMetadataError> {
        Self::new(core::slice::from_ref(storage_schema))
    }

    /// Returns the [`StorageSlotName`] where the schema commitment is stored.
    pub fn schema_commitment_slot() -> &'static StorageSlotName {
        &SCHEMA_COMMITMENT_SLOT_NAME
    }
}

impl From<AccountSchemaCommitment> for AccountComponent {
    fn from(schema_commitment: AccountSchemaCommitment) -> Self {
        let metadata = AccountComponentMetadata::new("miden::metadata::schema_commitment")
            .with_description("Component exposing the account storage schema commitment")
            .with_supports_all_types();

        AccountComponent::new(
            storage_schema_library(),
            vec![StorageSlot::with_value(
                AccountSchemaCommitment::schema_commitment_slot().clone(),
                schema_commitment.schema_commitment,
            )],
            metadata,
        )
        .expect(
            "AccountSchemaCommitment component should satisfy the requirements of a valid account component",
        )
    }
}

// ACCOUNT BUILDER EXTENSION
// ================================================================================================

/// An extension trait for [`AccountBuilder`] that provides a convenience method for building an
/// account with an [`AccountSchemaCommitment`] component.
pub trait AccountBuilderSchemaCommitmentExt {
    /// Builds an [`Account`] out of the configured builder after computing the storage schema
    /// commitment from all components currently in the builder and adding an
    /// [`AccountSchemaCommitment`] component.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The components' storage schemas contain conflicting definitions for the same slot name.
    /// - [`AccountBuilder::build`] fails.
    fn build_with_schema_commitment(self) -> Result<Account, AccountError>;
}

impl AccountBuilderSchemaCommitmentExt for AccountBuilder {
    fn build_with_schema_commitment(self) -> Result<Account, AccountError> {
        let schema_commitment =
            AccountSchemaCommitment::new(self.storage_schemas()).map_err(|err| {
                AccountError::other_with_source("failed to compute account schema commitment", err)
            })?;

        self.with_component(schema_commitment).build()
    }
}

// HELPERS
// ================================================================================================

/// Computes the schema commitment.
///
/// The account schema commitment is computed from the merged schema commitment.
/// If the passed list of schemas is empty, [`Word::empty()`] is returned.
fn compute_schema_commitment<'a>(
    schemas: impl IntoIterator<Item = &'a StorageSchema>,
) -> Result<Word, ComponentMetadataError> {
    let mut schemas = schemas.into_iter().peekable();
    if schemas.peek().is_none() {
        return Ok(Word::empty());
    }

    let mut merged_slots = BTreeMap::new();

    for schema in schemas {
        for (slot_name, slot_schema) in schema.iter() {
            match merged_slots.get(slot_name) {
                None => {
                    merged_slots.insert(slot_name.clone(), slot_schema.clone());
                },
                // Slot exists, check if the schema is the same before erroring
                Some(existing) => {
                    if existing != slot_schema {
                        return Err(ComponentMetadataError::InvalidSchema(format!(
                            "conflicting definitions for storage slot `{slot_name}`",
                        )));
                    }
                },
            }
        }
    }

    let merged_schema = StorageSchema::new(merged_slots)?;

    Ok(merged_schema.commitment())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::account::AccountBuilder;
    use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
    use miden_protocol::account::component::AccountComponentMetadata;

    use super::{AccountBuilderSchemaCommitmentExt, AccountSchemaCommitment};
    use crate::account::auth::{AuthSingleSig, NoAuth};

    #[test]
    fn storage_schema_commitment_is_order_independent() {
        let toml_a = r#"
            name = "Component A"
            description = "Component A schema"
            version = "0.1.0"
            supported-types = []

            [[storage.slots]]
            name = "test::slot_a"
            type = "word"
        "#;

        let toml_b = r#"
            name = "Component B"
            description = "Component B schema"
            version = "0.1.0"
            supported-types = []

            [[storage.slots]]
            name = "test::slot_b"
            description = "description is committed to"
            type = "word"
        "#;

        let metadata_a = AccountComponentMetadata::from_toml(toml_a).unwrap();
        let metadata_b = AccountComponentMetadata::from_toml(toml_b).unwrap();

        let schema_a = metadata_a.storage_schema().clone();
        let schema_b = metadata_b.storage_schema().clone();

        // Create one component for each of two different accounts, but switch orderings
        let component_a =
            AccountSchemaCommitment::new(&[schema_a.clone(), schema_b.clone()]).unwrap();
        let component_b = AccountSchemaCommitment::new(&[schema_b, schema_a]).unwrap();

        let account_a = AccountBuilder::new([1u8; 32])
            .with_auth_component(NoAuth)
            .with_component(component_a)
            .build()
            .unwrap();

        let account_b = AccountBuilder::new([2u8; 32])
            .with_auth_component(NoAuth)
            .with_component(component_b)
            .build()
            .unwrap();

        let slot_name = AccountSchemaCommitment::schema_commitment_slot();
        let commitment_a = account_a.storage().get_item(slot_name).unwrap();
        let commitment_b = account_b.storage().get_item(slot_name).unwrap();

        assert_eq!(commitment_a, commitment_b);
    }

    #[test]
    fn storage_schema_commitment_is_empty_for_no_schemas() {
        let component = AccountSchemaCommitment::new(&[]).unwrap();

        assert_eq!(component.schema_commitment, Word::empty());
    }

    #[test]
    fn build_with_schema_commitment_adds_schema_commitment_component() {
        let auth_component = AuthSingleSig::new(
            PublicKeyCommitment::from(Word::empty()),
            AuthScheme::EcdsaK256Keccak,
        );

        let account = AccountBuilder::new([1u8; 32])
            .with_auth_component(auth_component)
            .build_with_schema_commitment()
            .unwrap();

        // The auth component has 2 slots (public key and scheme ID) and the schema commitment adds
        // 1 more.
        assert_eq!(account.storage().num_slots(), 3);

        // The auth component's public key slot should be accessible.
        assert!(account.storage().get_item(AuthSingleSig::public_key_slot()).is_ok());

        // The schema commitment slot should be non-empty since we have a component with a schema.
        let slot_name = AccountSchemaCommitment::schema_commitment_slot();
        let commitment = account.storage().get_item(slot_name).unwrap();
        assert_ne!(commitment, Word::empty());
    }
}
