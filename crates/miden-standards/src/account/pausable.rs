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

// PAUSABLE ACCOUNT COMPONENT
// ================================================================================================

static IS_PAUSED_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::utils::pausable::is_paused")
        .expect("storage slot name should be valid")
});

/// Storage-only account component that installs the `is_paused` flag slot.
///
/// `Pausable` exports no procedures of its own. The pause primitive lives at
/// `miden::standards::utils::pausable` (exec-only `pause`, `unpause`, `is_paused`,
/// `assert_not_paused`, `assert_paused`) and is exposed through wrapper components that
/// add an authorization layer:
/// - [`crate::account::pausable_owner::PausableOwner`] gates pause/unpause behind the
///   [`crate::account::access::Ownable2Step`] owner.
/// - `PausableRbac` gates pause/unpause behind separate `PAUSER` / `UNPAUSER` roles in
///   [`crate::account::access::RoleBasedAccessControl`].
///
/// Downstream components that need to gate their own logic on pause state (e.g. asset
/// callbacks) can compose `exec.::miden::standards::utils::pausable::assert_not_paused`
/// (or `assert_paused`) directly without going through a wrapper.
///
/// ## Storage
///
/// - [`Self::is_paused_slot()`]: single word; all zeros means unpaused, `[1, 0, 0, 0]` means paused
///   (see MASM `miden::standards::utils::pausable`).
#[derive(Debug, Clone, Copy, Default)]
pub struct Pausable {
    initial_state: bool,
}

impl Pausable {
    /// Component library path (merged account module name).
    pub const NAME: &'static str = "miden::standards::components::utils::pausable";

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

    /// Metadata for accounts that include this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([Self::is_paused_slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(
            Self::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "Storage-only Pausable component: installs the `is_paused` flag slot. Pair with \
             a wrapper component (PausableOwner / PausableRbac) to expose authorized \
             pause/unpause procedures.",
        )
        .with_storage_schema(storage_schema)
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
