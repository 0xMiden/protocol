use alloc::vec::Vec;

use crate::Word;
use crate::account::{StorageSlot, StorageSlotName};
use crate::utils::sync::LazyLock;

// CONSTANTS
// ================================================================================================

static ON_ASSET_ADDED_TO_ACCOUNT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::protocol::faucet::callbacks::on_asset_added_to_account")
        .expect("storage slot name should be valid")
});

// ASSET CALLBACKS
// ================================================================================================

/// Configures the callback procedure root for the `on_asset_added_to_account` callback.
///
/// ## Storage Layout
///
/// - [`Self::slot`]: Stores the procedure root of the `on_asset_added_to_account` callback.
///
/// [`AssetCallbacksFlag::Enabled`]: crate::asset::AssetCallbacksFlag::Enabled
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetCallbacks {
    on_asset_added_to_account: Option<Word>,
}

impl AssetCallbacks {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AssetCallbacks`] with all callbacks set to `None`.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_asset_added_to_account(mut self, proc_root: Word) -> Self {
        self.on_asset_added_to_account = Some(proc_root);
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the callback procedure root is stored.
    pub fn on_asset_added_to_account_slot() -> &'static StorageSlotName {
        &ON_ASSET_ADDED_TO_ACCOUNT_SLOT_NAME
    }

    /// Returns the procedure root of the `on_asset_added_to_account` callback.
    pub fn on_asset_added_proc_root(&self) -> Option<Word> {
        self.on_asset_added_to_account
    }

    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let mut slots = Vec::new();

        if let Some(on_asset_added_to_account) = self.on_asset_added_to_account {
            slots.push(StorageSlot::with_value(
                AssetCallbacks::on_asset_added_to_account_slot().clone(),
                on_asset_added_to_account,
            ));
        }

        slots
    }
}
