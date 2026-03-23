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

static ON_BEFORE_ASSET_ADDED_TO_NOTE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::protocol::faucet::callback::on_before_asset_added_to_note")
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
/// - [`Self::on_before_asset_added_to_note_slot()`]: Stores the procedure root of the
///   `on_before_asset_added_to_note` callback. This storage slot is only added if the callback
///   procedure root is not the empty word.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetCallbacks {
    on_before_asset_added_to_account: Word,
    on_before_asset_added_to_note: Word,
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

    /// Sets the `on_before_asset_added_to_note` callback procedure root.
    pub fn on_before_asset_added_to_note(mut self, proc_root: Word) -> Self {
        self.on_before_asset_added_to_note = proc_root;
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the `on_before_asset_added_to_account` callback
    /// procedure root is stored.
    pub fn on_before_asset_added_to_account_slot() -> &'static StorageSlotName {
        &ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the `on_before_asset_added_to_note` callback
    /// procedure root is stored.
    pub fn on_before_asset_added_to_note_slot() -> &'static StorageSlotName {
        &ON_BEFORE_ASSET_ADDED_TO_NOTE_SLOT_NAME
    }

    /// Returns the procedure root of the `on_before_asset_added_to_account` callback.
    pub fn on_before_asset_added_to_account_proc_root(&self) -> Word {
        self.on_before_asset_added_to_account
    }

    /// Returns the procedure root of the `on_before_asset_added_to_note` callback.
    pub fn on_before_asset_added_to_note_proc_root(&self) -> Word {
        self.on_before_asset_added_to_note
    }

    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let mut slots = Vec::new();

        if !self.on_before_asset_added_to_account.is_empty() {
            slots.push(StorageSlot::with_value(
                AssetCallbacks::on_before_asset_added_to_account_slot().clone(),
                self.on_before_asset_added_to_account,
            ));
        }

        if !self.on_before_asset_added_to_note.is_empty() {
            slots.push(StorageSlot::with_value(
                AssetCallbacks::on_before_asset_added_to_note_slot().clone(),
                self.on_before_asset_added_to_note,
            ));
        }

        slots
    }
}
