use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    FeltSchema,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountProcedureRoot,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::account_component_code;
use crate::procedure_root;

mod manager;
pub use manager::PausableManager;

// IS_PAUSED STORAGE
// ================================================================================================

account_component_code!(PAUSABLE_CODE, "access/pausable/mod.masl");

static IS_PAUSED_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::pausable::is_paused")
        .expect("storage slot name should be valid")
});

procedure_root!(
    PAUSABLE_IS_PAUSED_ROOT,
    Pausable::NAME,
    Pausable::IS_PAUSED_PROC_NAME,
    Pausable::code()
);

/// Storage helper backing the pause flag for a single account.
///
/// `PausableStorage` exposes the slot name and schema for the `is_paused` flag word plus the
/// captured pause state. It is **not** an installable account component on its own — the
/// [`Pausable`] component installs the storage slot, and any consumer (TokenPolicyManager
/// dispatch, asset callbacks, metadata setters) reads via `exec.pausable::assert_not_paused` /
/// `assert_paused` exec helpers from the standards library at
/// `miden::standards::access::pausable`.
///
/// ## Storage
///
/// - [`Self::is_paused_slot()`]: single word; the zero word means unpaused, `[1, 0, 0, 0]` means
///   paused. Any non-zero word is interpreted as paused by the MASM helpers.
#[derive(Debug, Clone, Copy, Default)]
pub struct PausableStorage {
    state: bool,
}

impl PausableStorage {
    /// Creates a [`PausableStorage`] with the given pause state.
    pub const fn new(state: bool) -> Self {
        Self { state }
    }

    /// Creates a [`PausableStorage`] in the paused state.
    pub const fn paused() -> Self {
        Self::new(true)
    }

    /// Creates a [`PausableStorage`] in the unpaused state.
    pub const fn unpaused() -> Self {
        Self::new(false)
    }

    /// Returns the pause state captured in this storage.
    pub fn state(&self) -> bool {
        self.state
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

    /// Returns the pause-flag [`Word`] for the captured state.
    pub fn to_word(&self) -> Word {
        if self.state {
            Word::from([1u32, 0, 0, 0])
        } else {
            Word::default()
        }
    }

    /// Consumes the storage and returns the [`StorageSlot`] it contributes to an account
    /// component. The slot is initialized with the captured pause state.
    pub fn into_slot(self) -> StorageSlot {
        StorageSlot::with_value(Self::is_paused_slot().clone(), self.to_word())
    }
}

// PAUSABLE COMPONENT
// ================================================================================================

/// Account component that installs the [`PausableStorage`] slot and exposes `is_paused`
/// view procedure.
///
/// Pair with [`PausableManager`] to expose `pause` / `unpause` admin procedures gated by the
/// account-wide [`crate::account::access::Authority`] component.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pausable(PausableStorage);

impl Pausable {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::access::pausable";

    pub const IS_PAUSED_PROC_NAME: &'static str = "is_paused";

    /// Creates a [`Pausable`] component with the given pause state.
    pub const fn new(state: bool) -> Self {
        Self(PausableStorage::new(state))
    }

    /// Creates a [`Pausable`] component that starts in the paused state.
    pub const fn paused() -> Self {
        Self::new(true)
    }

    /// Creates a [`Pausable`] component that starts in the unpaused state.
    pub const fn unpaused() -> Self {
        Self::new(false)
    }

    /// Returns the pause state captured in this component.
    pub fn state(&self) -> bool {
        self.0.state()
    }

    /// Returns the underlying [`PausableStorage`] helper.
    pub fn storage(&self) -> &PausableStorage {
        &self.0
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &PAUSABLE_CODE
    }

    /// Returns the procedure root of the `is_paused` call procedure exposed by this component.
    pub fn is_paused_root() -> AccountProcedureRoot {
        *PAUSABLE_IS_PAUSED_ROOT
    }
}

impl From<Pausable> for AccountComponent {
    fn from(pausable: Pausable) -> Self {
        let storage_schema = StorageSchema::new([PausableStorage::is_paused_slot_schema()])
            .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(Pausable::NAME)
            .with_description(
                "Pausable: installs the `is_paused` storage slot and exposes \
                 `is_paused` view.",
            )
            .with_storage_schema(storage_schema);

        AccountComponent::new(Pausable::code().clone(), vec![pausable.0.into_slot()], metadata)
            .expect(
                "pausable component should satisfy the requirements of a valid account component",
            )
    }
}
