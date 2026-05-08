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
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

// CONSTANTS
// ================================================================================================

static SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::network_account::allowed_note_scripts")
        .expect("storage slot name should be valid")
});

// A flag value used as the storage map entry for each allowed script root. Its only job is to be
// distinguishable from the storage map's default empty word, letting the MASM allowlist check
// detect "this key is present" without caring about its contents. Any non-empty word would serve;
// we pick `[1, 0, 0, 0]` for readability when inspecting storage.
const ALLOWED_FLAG: Word = Word::new([Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]);

// NETWORK ACCOUNT NOTE ALLOWLIST
// ================================================================================================

/// A standardized storage slot holding the allowlist of input-note script roots that a network
/// account is willing to consume.
///
/// The presence of this slot is what defines an account as a "network account": it is the
/// abstraction shared by every network-account component, so off-chain services (like the network
/// transaction builder) can identify a network account and filter notes by inspecting account
/// storage for this slot, independent of which component the account uses.
///
/// The slot is a [`StorageMap`] keyed by note script root; any non-empty value marks a root as
/// allowed.
#[derive(Debug, Clone)]
pub struct NetworkAccountNoteAllowlist {
    allowed_script_roots: BTreeSet<NoteScriptRoot>,
}

impl NetworkAccountNoteAllowlist {
    /// Creates a new allowlist from the provided list of allowed input-note script roots.
    ///
    /// # Errors
    ///
    /// Returns an error if `allowed_script_roots` is empty since the account could not consume any
    /// notes.
    pub fn new(
        allowed_script_roots: BTreeSet<NoteScriptRoot>,
    ) -> Result<Self, NetworkAccountNoteAllowlistError> {
        if allowed_script_roots.is_empty() {
            return Err(NetworkAccountNoteAllowlistError::EmptyAllowlist);
        }

        Ok(Self { allowed_script_roots })
    }

    /// Returns the [`StorageSlotName`] of the standardized allowlist slot.
    pub fn slot_name() -> &'static StorageSlotName {
        &SLOT_NAME
    }

    /// Returns the allowed input-note script roots in this allowlist.
    pub fn allowed_script_roots(&self) -> &BTreeSet<NoteScriptRoot> {
        &self.allowed_script_roots
    }

    /// Returns the schema entry for the allowlist slot.
    pub fn slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::slot_name().clone(),
            StorageSlotSchema::map(
                "Allowed input note script roots",
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

impl TryFrom<&AccountStorage> for NetworkAccountNoteAllowlist {
    type Error = NetworkAccountNoteAllowlistError;

    /// Reconstructs a [`NetworkAccountNoteAllowlist`] from account storage by reading the
    /// allowlist slot and collecting its keys.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The standardized allowlist slot is not present in storage.
    /// - The slot is present but is not a [`StorageSlotContent::Map`].
    fn try_from(storage: &AccountStorage) -> Result<Self, Self::Error> {
        let slot = storage
            .get(Self::slot_name())
            .ok_or(NetworkAccountNoteAllowlistError::SlotNotFound)?;

        let StorageSlotContent::Map(map) = slot.content() else {
            return Err(NetworkAccountNoteAllowlistError::UnexpectedSlotType);
        };

        let allowed_script_roots = map
            .entries()
            .map(|(key, _value)| NoteScriptRoot::from_raw(key.as_word()))
            .collect();

        Self::new(allowed_script_roots)
    }
}

// NETWORK ACCOUNT NOTE ALLOWLIST ERROR
// ================================================================================================

/// Errors that can occur when constructing a [`NetworkAccountNoteAllowlist`] or reconstructing one
/// from storage.
#[derive(Debug, thiserror::Error)]
pub enum NetworkAccountNoteAllowlistError {
    #[error(
        "network account allowlist must contain at least one allowed note script root: an empty \
         allowlist would prevent the account from consuming any notes"
    )]
    EmptyAllowlist,
    #[error(
        "network account allowlist storage slot {} not found in account storage",
        NetworkAccountNoteAllowlist::slot_name()
    )]
    SlotNotFound,
    #[error(
        "network account allowlist storage slot {} must be a map",
        NetworkAccountNoteAllowlist::slot_name()
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
        let root_a = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let root_b = NoteScriptRoot::from_array([5, 6, 7, 8]);

        let slot = NetworkAccountNoteAllowlist::new(BTreeSet::from_iter([root_a, root_b]))
            .expect("non-empty allowlist should construct")
            .into_storage_slot();

        assert_eq!(slot.name(), NetworkAccountNoteAllowlist::slot_name());

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
    fn empty_allowlist_is_rejected() {
        let result = NetworkAccountNoteAllowlist::new(BTreeSet::new());
        assert!(matches!(result, Err(NetworkAccountNoteAllowlistError::EmptyAllowlist)));
    }

    #[test]
    fn allowlist_round_trips_through_account_storage() {
        use alloc::collections::BTreeSet;

        let root_a = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let root_b = NoteScriptRoot::from_array([5, 6, 7, 8]);
        let root_c = NoteScriptRoot::from_array([9, 10, 11, 12]);
        let original_roots = BTreeSet::from_iter([root_a, root_b, root_c]);

        let account = AccountBuilder::new([0; 32])
            .with_auth_component(
                AuthNetworkAccount::with_allowlist(original_roots.clone())
                    .expect("non-empty allowlist should construct"),
            )
            .with_component(BasicWallet)
            .build()
            .expect("account building with AuthNetworkAccount failed");

        let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())
            .expect("allowlist should be reconstructable from account storage");

        // The map's ordering is determined by the StorageMapKey, so compare as sets.
        let expected: BTreeSet<NoteScriptRoot> = original_roots.into_iter().collect();
        let actual: BTreeSet<NoteScriptRoot> =
            allowlist.allowed_script_roots().iter().copied().collect();

        assert_eq!(actual, expected);
    }
}
