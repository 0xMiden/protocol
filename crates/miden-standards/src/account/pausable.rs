use alloc::vec::Vec;

use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{AccountComponent, AccountType, StorageSlot, StorageSlotName};
use miden_protocol::asset::AssetCallbacks;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::components::pausable_library;
use crate::procedure_digest;

// PAUSABLE ACCOUNT COMPONENT
// ================================================================================================

static IS_PAUSED_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::utils::pausable::is_paused")
        .expect("storage slot name should be valid")
});

procedure_digest!(
    PAUSABLE_IS_PAUSED,
    Pausable::NAME,
    Pausable::IS_PAUSED_PROC_NAME,
    pausable_library
);

procedure_digest!(PAUSABLE_PAUSE, Pausable::NAME, Pausable::PAUSE_PROC_NAME, pausable_library);

procedure_digest!(PAUSABLE_UNPAUSE, Pausable::NAME, Pausable::UNPAUSE_PROC_NAME, pausable_library);

procedure_digest!(
    PAUSABLE_ON_BEFORE_ASSET_ADDED_TO_ACCOUNT,
    Pausable::NAME,
    Pausable::ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_PROC_NAME,
    pausable_library
);

procedure_digest!(
    PAUSABLE_ON_BEFORE_ASSET_ADDED_TO_NOTE,
    Pausable::NAME,
    Pausable::ON_BEFORE_ASSET_ADDED_TO_NOTE_PROC_NAME,
    pausable_library
);

/// Account component that stores a pause flag and registers asset callbacks that reject transfers
/// while paused.
///
/// `pause` and `unpause` do not authenticate the caller — this is an intentional choice:
/// the core mechanism is kept without access control so that owner and role-based access control   
/// can be implemented on top without duplicating the pause/unpause.
///
/// ## Storage
///
/// - [`Self::is_paused_slot()`]: single word; all zeros means unpaused, `[1,0,0,0]` means paused
///   (see MASM `miden::standards::utils::pausable`).
/// - Protocol callback slots from [`AssetCallbacks`] registered by every constructor.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pausable {
    initial_state: bool,
}

impl Pausable {
    /// Component library path (merged account module name).
    pub const NAME: &'static str = "miden::standards::components::utils::pausable";

    const IS_PAUSED_PROC_NAME: &'static str = "is_paused";
    const PAUSE_PROC_NAME: &'static str = "pause";
    const UNPAUSE_PROC_NAME: &'static str = "unpause";
    const ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_PROC_NAME: &'static str =
        "on_before_asset_added_to_account";
    const ON_BEFORE_ASSET_ADDED_TO_NOTE_PROC_NAME: &'static str = "on_before_asset_added_to_note";

    /// Creates a new [`Pausable`] with the given initial paused state.
    ///
    /// Use this constructor when the flag comes from configuration, CLI input, a registry, etc.
    /// For literal values prefer [`Self::paused`] / [`Self::unpaused`] (or [`Self::default`] for
    /// the unpaused default).
    pub const fn new(initial_state: bool) -> Self {
        Self { initial_state }
    }

    /// Creates a new [`Pausable`] that starts in the paused state.
    pub const fn paused() -> Self {
        Self::new(true)
    }

    /// Creates a new [`Pausable`] that starts in the unpaused state.
    ///
    /// Equivalent to [`Self::default`]; provided as an explicit literal form for call sites that
    /// prefer spelling out the initial state.
    pub const fn unpaused() -> Self {
        Self::new(false)
    }

    /// Storage slot name for the pause flag word.
    pub fn is_paused_slot() -> &'static StorageSlotName {
        &IS_PAUSED_SLOT_NAME
    }

    /// Schema entry for the pause flag slot (documentation / tooling).
    pub fn is_paused_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::is_paused_slot().clone(),
            StorageSlotSchema::value(
                "Pause flag word; zero is unpaused, canonical paused encoding is [1,0,0,0]",
                [
                    FeltSchema::felt("w0").with_default(Felt::ZERO),
                    FeltSchema::felt("w1").with_default(Felt::ZERO),
                    FeltSchema::felt("w2").with_default(Felt::ZERO),
                    FeltSchema::felt("w3").with_default(Felt::ZERO),
                ],
            ),
        )
    }

    /// Metadata for accounts that include this component (faucet types that may issue
    /// callback-enabled assets).
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([Self::is_paused_slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(
            Self::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "Pausable component: pause/unpause and on_before_asset_added callbacks without auth",
        )
        .with_storage_schema(storage_schema)
    }

    pub fn is_paused_digest() -> Word {
        *PAUSABLE_IS_PAUSED
    }

    pub fn pause_digest() -> Word {
        *PAUSABLE_PAUSE
    }

    pub fn unpause_digest() -> Word {
        *PAUSABLE_UNPAUSE
    }

    pub fn on_before_asset_added_to_account_digest() -> Word {
        *PAUSABLE_ON_BEFORE_ASSET_ADDED_TO_ACCOUNT
    }

    pub fn on_before_asset_added_to_note_digest() -> Word {
        *PAUSABLE_ON_BEFORE_ASSET_ADDED_TO_NOTE
    }
}

impl From<Pausable> for AccountComponent {
    fn from(pausable: Pausable) -> Self {
        let initial_word = if pausable.initial_state {
            Word::from([1u32, 0, 0, 0])
        } else {
            Word::default()
        };

        let is_paused_slot =
            StorageSlot::with_value(Pausable::is_paused_slot().clone(), initial_word);
        let callback_slots = AssetCallbacks::new()
            .on_before_asset_added_to_account(Pausable::on_before_asset_added_to_account_digest())
            .on_before_asset_added_to_note(Pausable::on_before_asset_added_to_note_digest())
            .into_storage_slots();

        let mut storage_slots = Vec::with_capacity(1 + callback_slots.len());
        storage_slots.push(is_paused_slot);
        storage_slots.extend(callback_slots);

        let metadata = Pausable::component_metadata();

        AccountComponent::new(pausable_library(), storage_slots, metadata).expect(
            "pausable component should satisfy the requirements of a valid account component",
        )
    }
}
