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

use crate::account::components::network_account_library;

// CONSTANTS
// ================================================================================================

static WHITELIST_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::network_account::whitelist")
        .expect("storage slot name should be valid")
});

// A "sentinel value" is a placeholder value whose only job is to be distinguishable from a known
// default, letting readers of the data detect a condition (here: "this key is present"). We call
// this constant a sentinel because we only ever check whether the stored value differs from the
// empty word; its actual contents carry no information.
//
// Storage maps treat an empty word (`[0, 0, 0, 0]`) as "key absent", so the MASM presence check
// compares the looked-up value against the empty word. Any non-empty word would serve as the
// sentinel; we pick `[1, 0, 0, 0]` for readability when inspecting storage.
const WHITELIST_SENTINEL: Word =
    Word::new([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]);

// NETWORK ACCOUNT
// ================================================================================================

/// An [`AccountComponent`] implementing the authentication scheme used by network-owned accounts
/// such as network faucets and the AggLayer bridge.
///
/// The component exports a single auth procedure, `auth_tx_network_account`, that rejects the
/// transaction unless:
/// - no transaction script was executed, and
/// - every consumed input note has a script root present in the component's whitelist.
///
/// The whitelist is stored in a storage map at a well-known slot (see [`Self::whitelist_slot`])
/// so off-chain services can identify a network account by inspecting its storage.
///
/// The whitelist is fixed at account creation; there is intentionally no procedure to mutate it
/// after deployment.
pub struct NetworkAccount {
    allowed_script_roots: Vec<Word>,
}

impl NetworkAccount {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::auth::network_account";

    /// Creates a new [`NetworkAccount`] component with the provided list of allowed input-note
    /// script roots.
    pub fn new(allowed_script_roots: Vec<Word>) -> Self {
        Self { allowed_script_roots }
    }

    /// Returns the storage slot holding the whitelist of allowed input-note script roots.
    pub fn whitelist_slot() -> &'static StorageSlotName {
        &WHITELIST_SLOT_NAME
    }

    /// Returns the storage slot schema for the whitelist slot.
    pub fn whitelist_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::whitelist_slot().clone(),
            StorageSlotSchema::map(
                "Allowed input-note script roots",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![Self::whitelist_slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, AccountType::all())
            .with_description(
                "Authentication component for network accounts that restricts input notes to a \
                 fixed whitelist and forbids tx scripts",
            )
            .with_storage_schema(storage_schema)
    }
}

impl From<NetworkAccount> for AccountComponent {
    fn from(network_account: NetworkAccount) -> Self {
        let map_entries = network_account
            .allowed_script_roots
            .into_iter()
            .map(|root| (StorageMapKey::new(root), WHITELIST_SENTINEL));

        let storage_slots = vec![StorageSlot::with_map(
            NetworkAccount::whitelist_slot().clone(),
            StorageMap::with_entries(map_entries)
                .expect("whitelist entries should produce a valid storage map"),
        )];

        let metadata = NetworkAccount::component_metadata();

        AccountComponent::new(network_account_library(), storage_slots, metadata).expect(
            "NetworkAccount component should satisfy the requirements of a valid account component",
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
    fn network_account_component_builds() {
        let root_a = Word::from([1u32, 2, 3, 4]);
        let root_b = Word::from([5u32, 6, 7, 8]);

        let _account = AccountBuilder::new([0; 32])
            .with_auth_component(NetworkAccount::new(vec![root_a, root_b]))
            .with_component(BasicWallet)
            .build()
            .expect("account building with NetworkAccount failed");
    }

    #[test]
    fn network_account_with_empty_whitelist_builds() {
        let _account = AccountBuilder::new([0; 32])
            .with_auth_component(NetworkAccount::new(Vec::new()))
            .with_component(BasicWallet)
            .build()
            .expect("account building with empty NetworkAccount whitelist failed");
    }

    #[test]
    fn whitelist_storage_contains_expected_entries() {
        use miden_protocol::account::StorageSlotContent;

        let root_a = Word::from([1u32, 2, 3, 4]);
        let root_b = Word::from([5u32, 6, 7, 8]);

        let component: AccountComponent = NetworkAccount::new(vec![root_a, root_b]).into();

        let storage_slots = component.storage_slots();
        assert_eq!(storage_slots.len(), 1);

        let StorageSlotContent::Map(map) = storage_slots[0].content() else {
            panic!("whitelist slot must be a map");
        };

        assert_eq!(
            map.get(&StorageMapKey::new(root_a)),
            WHITELIST_SENTINEL,
            "root_a should resolve to the sentinel value"
        );
        assert_eq!(
            map.get(&StorageMapKey::new(root_b)),
            WHITELIST_SENTINEL,
            "root_b should resolve to the sentinel value"
        );
    }
}
