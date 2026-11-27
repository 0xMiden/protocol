use alloc::vec::Vec;

use crate::Word;
use crate::account::{StorageSlot, StorageSlotName};
use crate::utils::sync::LazyLock;

// CONSTANTS
// ================================================================================================

static ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_SLOT_NAME: LazyLock<StorageSlotName> =
    LazyLock::new(|| {
        StorageSlotName::new("miden::protocol::faucet::callback::on_before_asset_added_to_account")
            .expect("storage slot name should be valid")
    });

static ON_BEFORE_NOTE_SEALED_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::protocol::faucet::callback::on_before_note_sealed")
        .expect("storage slot name should be valid")
});

// ASSET CALLBACKS
// ================================================================================================

/// Configures the callback procedure roots for asset callbacks.
///
/// ## Storage Layout
///
/// - [`Self::on_before_asset_added_to_account_slot()`]: Stores the procedure root of the
///   `on_before_asset_added_to_account` callback. This storage slot is only added if the callback
///   procedure root is not the empty word.
/// - [`Self::on_before_note_sealed_slot()`]: Stores the procedure root of the
///   `on_before_note_sealed` callback. This storage slot is only added if the callback procedure
///   root is not the empty word.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetCallbacks {
    on_before_asset_added_to_account: Word,
    on_before_note_sealed: Word,
}

impl AssetCallbacks {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AssetCallbacks`] with all callbacks set to the empty word.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `on_before_asset_added_to_account` callback procedure root.
    pub fn on_before_asset_added_to_account(mut self, proc_root: Word) -> Self {
        self.on_before_asset_added_to_account = proc_root;
        self
    }

    /// Sets the `on_before_note_sealed` callback procedure root.
    pub fn on_before_note_sealed(mut self, proc_root: Word) -> Self {
        self.on_before_note_sealed = proc_root;
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the `on_before_asset_added_to_account` callback
    /// procedure root is stored.
    pub fn on_before_asset_added_to_account_slot() -> &'static StorageSlotName {
        &ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the `on_before_note_sealed` callback procedure root
    /// is stored.
    pub fn on_before_note_sealed_slot() -> &'static StorageSlotName {
        &ON_BEFORE_NOTE_SEALED_SLOT_NAME
    }

    /// Returns the names of all protocol-reserved asset callback storage slots.
    pub fn slot_names() -> [&'static StorageSlotName; 2] {
        [
            Self::on_before_asset_added_to_account_slot(),
            Self::on_before_note_sealed_slot(),
        ]
    }

    /// Returns the procedure root of the `on_before_asset_added_to_account` callback.
    pub fn on_before_asset_added_to_account_proc_root(&self) -> Word {
        self.on_before_asset_added_to_account
    }

    /// Returns the procedure root of the `on_before_note_sealed` callback.
    pub fn on_before_note_sealed_proc_root(&self) -> Word {
        self.on_before_note_sealed
    }

    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let mut slots = Vec::new();

        if !self.on_before_asset_added_to_account.is_empty() {
            slots.push(StorageSlot::with_value(
                AssetCallbacks::on_before_asset_added_to_account_slot().clone(),
                self.on_before_asset_added_to_account,
            ));
        }

        if !self.on_before_note_sealed.is_empty() {
            slots.push(StorageSlot::with_value(
                AssetCallbacks::on_before_note_sealed_slot().clone(),
                self.on_before_note_sealed,
            ));
        }

        slots
    }
}
