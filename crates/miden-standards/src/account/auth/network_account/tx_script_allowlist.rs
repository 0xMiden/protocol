use alloc::collections::BTreeSet;

use miden_protocol::account::component::{SchemaType, StorageSlotSchema};
use miden_protocol::account::{
    AccountStorage,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotContent,
    StorageSlotName,
};
use miden_protocol::transaction::TransactionScriptRoot;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

// CONSTANTS
// ================================================================================================

static SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::network_account::allowed_tx_scripts")
        .expect("storage slot name should be valid")
});

// A flag value used as the storage map entry for each allowed script root. Its only job is to be
// distinguishable from the storage map's default empty word, letting the MASM allowlist check
// detect "this key is present" without caring about its contents. Any non-empty word would serve;
// we pick `[1, 0, 0, 0]` for readability when inspecting storage.
const ALLOWED_FLAG: Word = Word::new([Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]);

// NETWORK ACCOUNT TX SCRIPT ALLOWLIST
// ================================================================================================

/// A standardized storage slot holding the allowlist of transaction script roots that a network
/// account is willing to execute.
///
/// A network account has no signature gate, so any transaction script that runs against it is a
/// code path the account owner must have pre-approved. This allowlist is that approval: a
/// transaction that executes no tx script is always allowed, but any other tx script must have its
/// root present here. An empty allowlist therefore reproduces the strictest behavior of permitting
/// no transaction scripts at all.
///
/// A root pins the script's code but not its `TX_SCRIPT_ARGS` or advice inputs, which the
/// transaction submitter controls; only input-closed scripts should be allowlisted (see the
/// [`AuthNetworkAccount`](super::AuthNetworkAccount) docs).
///
/// The slot is a [`StorageMap`] keyed by tx script root; any non-empty value marks a root as
/// allowed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkAccountTxScriptAllowlist {
    allowed_script_roots: BTreeSet<TransactionScriptRoot>,
}

impl NetworkAccountTxScriptAllowlist {
    /// Creates a new allowlist from the provided list of allowed transaction script roots.
    ///
    /// An empty set is permitted and means the account allows no transaction scripts.
    pub fn new(allowed_script_roots: BTreeSet<TransactionScriptRoot>) -> Self {
        Self { allowed_script_roots }
    }

    /// Returns the [`StorageSlotName`] of the standardized allowlist slot.
    pub fn slot_name() -> &'static StorageSlotName {
        &SLOT_NAME
    }

    /// Returns the allowed transaction script roots in this allowlist.
    pub fn allowed_script_roots(&self) -> &BTreeSet<TransactionScriptRoot> {
        &self.allowed_script_roots
    }

    /// Consumes this allowlist and returns the allowed transaction script roots.
    pub fn into_allowed_script_roots(self) -> BTreeSet<TransactionScriptRoot> {
        self.allowed_script_roots
    }

    /// Returns the schema entry for the allowlist slot.
    pub fn slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::slot_name().clone(),
            StorageSlotSchema::map(
                "Allowed transaction script roots",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Consumes this allowlist and returns the [`StorageSlot`] suitable for inclusion in an
    /// [`AccountComponent`](miden_protocol::account::AccountComponent)'s storage layout.
    pub fn into_storage_slot(self) -> StorageSlot {
        let entries = self
            .allowed_script_roots
            .into_iter()
            .map(|root| (StorageMapKey::new(root.as_word()), ALLOWED_FLAG));

        let storage_map = StorageMap::with_entries(entries)
            .expect("allowlist entries should produce a valid storage map");

        StorageSlot::with_map(Self::slot_name().clone(), storage_map)
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl TryFrom<&AccountStorage> for NetworkAccountTxScriptAllowlist {
    type Error = NetworkAccountTxScriptAllowlistError;

    /// Reconstructs a [`NetworkAccountTxScriptAllowlist`] from account storage by reading the
    /// allowlist slot and collecting its keys.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The standardized allowlist slot is not present in storage.
    /// - The slot is present but is not a [`StorageSlotContent::Map`].
    fn try_from(storage: &AccountStorage) -> Result<Self, Self::Error> {
        let slot = storage
            .get(Self::slot_name())
            .ok_or(NetworkAccountTxScriptAllowlistError::SlotNotFound)?;

        let StorageSlotContent::Map(map) = slot.content() else {
            return Err(NetworkAccountTxScriptAllowlistError::UnexpectedSlotType);
        };

        // Only entries with a non-empty value mark a root as allowed, matching the MASM check
        // (`word::eqz`), so the reconstructed view agrees with on-chain enforcement.
        let allowed_script_roots = map
            .entries()
            .filter(|(_key, value)| **value != Word::empty())
            .map(|(key, _value)| TransactionScriptRoot::from_raw(key.as_word()))
            .collect();

        Ok(Self::new(allowed_script_roots))
    }
}

// NETWORK ACCOUNT TX SCRIPT ALLOWLIST ERROR
// ================================================================================================

/// Errors that can occur when reconstructing a [`NetworkAccountTxScriptAllowlist`] from storage.
#[derive(Debug, thiserror::Error)]
pub enum NetworkAccountTxScriptAllowlistError {
    #[error(
        "network account tx script allowlist storage slot {} not found in account storage",
        NetworkAccountTxScriptAllowlist::slot_name()
    )]
    SlotNotFound,
    #[error(
        "network account tx script allowlist storage slot {} must be a map",
        NetworkAccountTxScriptAllowlist::slot_name()
    )]
    UnexpectedSlotType,
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountBuilder, StorageSlotContent};

    use super::*;
    use crate::account::auth::network_account::AuthNetworkAccount;
    use crate::account::wallets::BasicWallet;

    #[test]
    fn allowlist_storage_slot_contains_expected_entries() {
        let root_a = TransactionScriptRoot::from_array([1, 2, 3, 4]);
        let root_b = TransactionScriptRoot::from_array([5, 6, 7, 8]);

        let slot = NetworkAccountTxScriptAllowlist::new(BTreeSet::from_iter([root_a, root_b]))
            .into_storage_slot();

        assert_eq!(slot.name(), NetworkAccountTxScriptAllowlist::slot_name());

        let StorageSlotContent::Map(map) = slot.content() else {
            panic!("allowlist slot must be a map");
        };

        assert_eq!(
            map.get(&StorageMapKey::new(root_a.as_word())),
            ALLOWED_FLAG,
            "root_a should resolve to the flag value"
        );
        assert_eq!(
            map.get(&StorageMapKey::new(root_b.as_word())),
            ALLOWED_FLAG,
            "root_b should resolve to the flag value"
        );
    }

    #[test]
    fn empty_allowlist_is_allowed() {
        let slot = NetworkAccountTxScriptAllowlist::new(BTreeSet::new()).into_storage_slot();
        let StorageSlotContent::Map(map) = slot.content() else {
            panic!("allowlist slot must be a map");
        };
        assert_eq!(map.entries().count(), 0);
    }

    #[test]
    fn allowlist_round_trips_through_account_storage() {
        let root_a = TransactionScriptRoot::from_array([1, 2, 3, 4]);
        let root_b = TransactionScriptRoot::from_array([5, 6, 7, 8]);
        let original_roots = BTreeSet::from_iter([root_a, root_b]);

        let account = AccountBuilder::new([0; 32])
            .with_auth_component(
                AuthNetworkAccount::with_allowlist(BTreeSet::from_iter([
                    miden_protocol::note::NoteScriptRoot::from_array([9, 9, 9, 9]),
                ]))
                .expect("non-empty note allowlist should construct")
                .with_allowed_tx_scripts(original_roots.clone()),
            )
            .with_component(BasicWallet)
            .build()
            .expect("account building with AuthNetworkAccount failed");

        let allowlist = NetworkAccountTxScriptAllowlist::try_from(account.storage())
            .expect("allowlist should be reconstructable from account storage");

        let actual: BTreeSet<TransactionScriptRoot> =
            allowlist.allowed_script_roots().iter().copied().collect();

        assert_eq!(actual, original_roots);
    }
}
