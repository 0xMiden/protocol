use alloc::collections::BTreeMap;

use miden_protocol::Word;
use miden_protocol::account::component::{AccountComponentMetadata, StorageSchema};
use miden_protocol::account::{AccountComponent, StorageSlot, StorageSlotName};
use miden_protocol::errors::ComponentMetadataError;
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
    /// Creates a new [`AccountSchemaCommitment`] component from a list of storage schemas.
    ///
    /// The input schemas are merged into a single schema before the final commitment is computed.
    ///
    /// # Errors
    ///
    /// Returns an error if the schemas contain conflicting definitions for the same slot name.
    pub fn new(schemas: &[StorageSchema]) -> Result<Self, ComponentMetadataError> {
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

/// Computes the schema commitment.
///
/// The account schema commitment is computed from the merged schema commitment.
/// If the passed list of schemas is empty, [`Word::empty()`] is returned.
fn compute_schema_commitment(schemas: &[StorageSchema]) -> Result<Word, ComponentMetadataError> {
    if schemas.is_empty() {
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
    use miden_protocol::account::component::AccountComponentMetadata;

    use super::AccountSchemaCommitment;
    use crate::account::auth::NoAuth;

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
}
