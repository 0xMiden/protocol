use alloc::vec::Vec;

use miden_protocol::account::component::{
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountType,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::components::network_account_auth_library;

// CONSTANTS
// ================================================================================================

static ALLOWED_NOTE_SCRIPTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::network_account::allowed_note_scripts")
        .expect("storage slot name should be valid")
});

// A flag value used as the storage map entry for each allowed script root. Its only job is to be
// distinguishable from the storage map's default empty word, letting the MASM allowlist check
// detect "this key is present" without caring about its contents. Any non-empty word would serve;
// we pick `[1, 0, 0, 0]` for readability when inspecting storage.
const ALLOWED_FLAG: Word = Word::new([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]);

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
/// The allowlist is stored in a storage map at a well-known slot (see
/// [`Self::allowed_note_scripts_slot`]) so off-chain services can identify a network account by
/// inspecting its storage.
///
/// The allowlist is fixed at account creation; there is intentionally no procedure to mutate it
/// after deployment.
pub struct AuthNetworkAccount {
    allowed_script_roots: Vec<Word>,
}

impl AuthNetworkAccount {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::auth::network_account";

    /// Creates a new [`AuthNetworkAccount`] component with the provided list of allowed
    /// input-note script roots.
    pub fn new(allowed_script_roots: Vec<Word>) -> Self {
        Self { allowed_script_roots }
    }

    /// Returns the storage slot holding the allowlist of allowed input-note script roots.
    pub fn allowed_note_scripts_slot() -> &'static StorageSlotName {
        &ALLOWED_NOTE_SCRIPTS_SLOT_NAME
    }

    /// Returns the storage slot schema for the allowlist slot.
    pub fn allowed_note_scripts_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::allowed_note_scripts_slot().clone(),
            StorageSlotSchema::map(
                "Allowed input note script roots",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![Self::allowed_note_scripts_slot_schema()])
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
        let map_entries = component
            .allowed_script_roots
            .into_iter()
            .map(|root| (StorageMapKey::new(root), ALLOWED_FLAG));

        let storage_slots = vec![StorageSlot::with_map(
            AuthNetworkAccount::allowed_note_scripts_slot().clone(),
            StorageMap::with_entries(map_entries)
                .expect("allowlist entries should produce a valid storage map"),
        )];

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
    use miden_protocol::account::{AccountBuilder, StorageMapKey};

    use super::*;
    use crate::account::wallets::BasicWallet;

    #[test]
    fn auth_network_account_component_builds() {
        let root_a = Word::from([1u32, 2, 3, 4]);
        let root_b = Word::from([5u32, 6, 7, 8]);

        let _account = AccountBuilder::new([0; 32])
            .with_auth_component(AuthNetworkAccount::new(vec![root_a, root_b]))
            .with_component(BasicWallet)
            .build()
            .expect("account building with AuthNetworkAccount failed");
    }

    #[test]
    fn auth_network_account_with_empty_allowlist_builds() {
        let _account = AccountBuilder::new([0; 32])
            .with_auth_component(AuthNetworkAccount::new(Vec::new()))
            .with_component(BasicWallet)
            .build()
            .expect("account building with empty allowlist failed");
    }

    #[test]
    fn allowlist_storage_contains_expected_entries() {
        use miden_protocol::account::StorageSlotContent;

        let root_a = Word::from([1u32, 2, 3, 4]);
        let root_b = Word::from([5u32, 6, 7, 8]);

        let component: AccountComponent = AuthNetworkAccount::new(vec![root_a, root_b]).into();

        let storage_slots = component.storage_slots();
        assert_eq!(storage_slots.len(), 1);

        let StorageSlotContent::Map(map) = storage_slots[0].content() else {
            panic!("allowlist slot must be a map");
        };

        assert_eq!(
            map.get(&StorageMapKey::new(root_a)),
            ALLOWED_FLAG,
            "root_a should resolve to the flag value"
        );
        assert_eq!(
            map.get(&StorageMapKey::new(root_b)),
            ALLOWED_FLAG,
            "root_b should resolve to the flag value"
        );
    }
}
