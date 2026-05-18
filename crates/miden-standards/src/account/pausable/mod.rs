use miden_protocol::account::component::{FeltSchema, StorageSlotSchema};
use miden_protocol::account::{StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

pub mod auth_controlled;
pub mod owner_controlled;
pub mod role_controlled;

pub use auth_controlled::PausableAuthControlled;
pub use owner_controlled::PausableOwnerControlled;
pub use role_controlled::PausableRoleControlled;

// IS_PAUSED STORAGE
// ================================================================================================

static IS_PAUSED_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::utils::pausable::is_paused")
        .expect("storage slot name should be valid")
});

/// Storage backing the pause flag for a single account.
///
/// `PausableStorage` exposes the slot name and schema for the `is_paused` flag word plus an
/// optional initial pause state. It is **not** an installable account component on its own —
/// the policy component that installs the storage slot (typically [`BasicPausable`]) reads
/// the slot name and the initial state from here.
///
/// The low-level `pause` / `unpause` / `is_paused` / `assert_not_paused` / `assert_paused`
/// procedures live in the standards library at `miden::standards::utils::pausable` as
/// `Invocation: exec` helpers — they perform no authorization and must be wrapped by an
/// auth-checking admin component (see [`PausableOwnerControlled`] / [`PausableRoleControlled`])
/// before being exposed on a production account.
///
/// ## Storage
///
/// - [`Self::is_paused_slot()`]: single word; the zero word means unpaused, `[1, 0, 0, 0]` means
///   paused. Any non-zero word is interpreted as paused by the MASM helpers.
#[derive(Debug, Clone, Copy, Default)]
pub struct PausableStorage {
    initial_state: bool,
}

impl PausableStorage {
    /// Creates a [`PausableStorage`] starting unpaused.
    pub const fn new() -> Self {
        Self { initial_state: false }
    }

    /// Creates a [`PausableStorage`] with the given initial pause state.
    pub const fn with_initial_state(initial_state: bool) -> Self {
        Self { initial_state }
    }

    /// Creates a [`PausableStorage`] that starts in the paused state.
    pub const fn paused() -> Self {
        Self::with_initial_state(true)
    }

    /// Creates a [`PausableStorage`] that starts in the unpaused state.
    pub const fn unpaused() -> Self {
        Self::with_initial_state(false)
    }

    /// Returns the initial pause state captured in this storage.
    pub fn initial_state(&self) -> bool {
        self.initial_state
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

    /// Builds the initial pause-flag [`Word`] from the captured initial state.
    pub fn build_word(&self) -> Word {
        if self.initial_state {
            Word::from([1u32, 0, 0, 0])
        } else {
            Word::default()
        }
    }

    /// Consumes the storage and returns the [`StorageSlot`] it contributes to an account
    /// component. The slot is initialized with the captured pause state.
    pub fn into_slot(self) -> StorageSlot {
        StorageSlot::with_value(Self::is_paused_slot().clone(), self.build_word())
    }
}
