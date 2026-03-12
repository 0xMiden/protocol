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

// ASSET CALLBACKS
// ================================================================================================

/// Configures the callback procedure root for the `on_before_asset_added_to_account` callback.
///
/// ## Storage Layout
///
/// - [`Self::on_before_asset_added_to_account_slot()`]: Stores the procedure root of the
///   `on_before_asset_added_to_account` callback. This storage slot is only added if the callback
///   procedure root is not the empty word.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetCallbacks {
    on_before_asset_added_to_account: Word,
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

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the callback procedure root is stored.
    pub fn on_before_asset_added_to_account_slot() -> &'static StorageSlotName {
        &ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_SLOT_NAME
    }

    /// Returns the procedure root of the `on_before_asset_added_to_account` callback.
    pub fn on_before_asset_added_to_account_proc_root(&self) -> Word {
        self.on_before_asset_added_to_account
    }

    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let mut slots = Vec::new();

        if !self.on_before_asset_added_to_account.is_empty() {
            slots.push(StorageSlot::with_value(
                AssetCallbacks::on_before_asset_added_to_account_slot().clone(),
                self.on_before_asset_added_to_account,
            ));
        }

        slots
    }
}
