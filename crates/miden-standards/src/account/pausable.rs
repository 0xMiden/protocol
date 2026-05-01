use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{AccountComponent, AccountType, StorageSlot, StorageSlotName};
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

/// Account component that stores a pause flag exposing `pause` / `unpause` / `is_paused`.
///
/// `pause` and `unpause` do not authenticate the caller — this is an intentional choice:
/// the core mechanism is kept without access control so that owner and role-based access control
/// can be implemented on top without duplicating the pause/unpause.
///
/// Downstream components compose `assert_not_paused` / `assert_paused` (exec) to gate their own
/// logic — for example asset-callback procedures that must reject transfers while paused. This
/// component itself does not register any callbacks.
///
/// ## Storage
///
/// - [`Self::is_paused_slot()`]: single word; all zeros means unpaused, `[1,0,0,0]` means paused
///   (see MASM `miden::standards::utils::pausable`).
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
    /// callback-enabled assets and need a pause primitive).
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([Self::is_paused_slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(
            Self::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "Pausable component: pause / unpause / is_paused without auth. Downstream \
             components compose `assert_not_paused` / `assert_paused` to gate their own logic.",
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

        let metadata = Pausable::component_metadata();

        AccountComponent::new(pausable_library(), vec![is_paused_slot], metadata).expect(
            "pausable component should satisfy the requirements of a valid account component",
        )
    }
}
