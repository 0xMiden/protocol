use alloc::collections::BTreeSet;
use alloc::vec;

use miden_protocol::account::component::{
    AccountComponentMetadata,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{AccountComponent, AccountType, StorageSlotName};
use miden_protocol::note::NoteScriptRoot;

use super::{NetworkAccountNoteAllowlist, NetworkAccountNoteAllowlistError};
use crate::account::components::network_account_auth_library;

// AUTH NETWORK ACCOUNT
// ================================================================================================

/// An [`AccountComponent`] implementing an authentication scheme that restricts what notes an
/// account can consume to a fixed allowlist of note script roots, and forbids transaction scripts
/// from running against the account.
///
/// This is intended for network-owned accounts (e.g. the AggLayer bridge or a network faucet)
/// whose only legitimate inputs are a known, finite set of system-issued notes.
///
/// The component exports a single auth procedure, `auth_network_transaction`, that rejects the
/// transaction unless:
/// - no transaction script was executed, and
/// - every consumed input note has a script root present in the component's allowlist.
///
/// The allowlist is stored in the standardized [`NetworkAccountNoteAllowlist`] slot so off-chain
/// services can identify a network account by checking for this slot.
///
/// The allowlist is fixed at account creation; there is intentionally no procedure to mutate it
/// after deployment.
pub struct AuthNetworkAccount {
    allowlist: NetworkAccountNoteAllowlist,
}

impl AuthNetworkAccount {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::auth::network_account";

    /// Creates a new [`AuthNetworkAccount`] component with the provided list of allowed
    /// input-note script roots.
    ///
    /// # Errors
    ///
    /// Returns an error if `allowed_script_roots` is empty since the account could not consume any
    /// notes.
    pub fn with_allowlist(
        allowed_script_roots: BTreeSet<NoteScriptRoot>,
    ) -> Result<Self, NetworkAccountNoteAllowlistError> {
        Ok(Self {
            allowlist: NetworkAccountNoteAllowlist::new(allowed_script_roots)?,
        })
    }

    /// Returns the storage slot holding the allowlist of allowed input-note script roots.
    pub fn allowed_note_scripts_slot() -> &'static StorageSlotName {
        NetworkAccountNoteAllowlist::slot_name()
    }

    /// Returns the storage slot schema for the allowlist slot.
    pub fn allowed_note_scripts_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        NetworkAccountNoteAllowlist::slot_schema()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![NetworkAccountNoteAllowlist::slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, AccountType::all())
            .with_description(
                "Authentication component that restricts input notes to a fixed allowlist of \
                 note script roots and forbids tx scripts",
            )
            .with_storage_schema(storage_schema)
    }
}

impl From<AuthNetworkAccount> for AccountComponent {
    fn from(component: AuthNetworkAccount) -> Self {
        let storage_slots = vec![component.allowlist.into_storage_slot()];
        let metadata = AuthNetworkAccount::component_metadata();

        AccountComponent::new(network_account_auth_library(), storage_slots, metadata).expect(
            "AuthNetworkAccount component should satisfy the requirements of a valid \
                 account component",
        )
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountBuilder, StorageSlotContent};

    use super::*;
    use crate::account::wallets::BasicWallet;

    #[test]
    fn auth_network_account_component_builds() {
        let root_a = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let root_b = NoteScriptRoot::from_array([5, 6, 7, 8]);

        let _account = AccountBuilder::new([0; 32])
            .with_auth_component(
                AuthNetworkAccount::with_allowlist(BTreeSet::from_iter([root_a, root_b]))
                    .expect("non-empty allowlist should construct"),
            )
            .with_component(BasicWallet)
            .build()
            .expect("account building with AuthNetworkAccount failed");
    }

    #[test]
    fn auth_network_account_with_empty_allowlist_is_rejected() {
        let result = AuthNetworkAccount::with_allowlist(BTreeSet::new());
        assert!(matches!(result, Err(NetworkAccountNoteAllowlistError::EmptyAllowlist)));
    }

    #[test]
    fn auth_network_account_uses_standardized_allowlist_slot() {
        let root_a = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let component: AccountComponent =
            AuthNetworkAccount::with_allowlist(BTreeSet::from_iter([root_a]))
                .expect("non-empty allowlist should construct")
                .into();

        let storage_slots = component.storage_slots();
        assert_eq!(storage_slots.len(), 1);
        assert_eq!(storage_slots[0].name(), NetworkAccountNoteAllowlist::slot_name());

        let StorageSlotContent::Map(_) = storage_slots[0].content() else {
            panic!("allowlist slot must be a map");
        };
    }
}
