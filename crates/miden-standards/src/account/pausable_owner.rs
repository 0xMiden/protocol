use alloc::vec;

use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::pausable_owner_library;
use crate::procedure_digest;

// PAUSABLE OWNER ACCOUNT COMPONENT
// ================================================================================================

procedure_digest!(
    PAUSABLE_OWNER_PAUSE,
    PausableOwner::NAME,
    PausableOwner::PAUSE_PROC_NAME,
    pausable_owner_library
);

procedure_digest!(
    PAUSABLE_OWNER_UNPAUSE,
    PausableOwner::NAME,
    PausableOwner::UNPAUSE_PROC_NAME,
    pausable_owner_library
);

procedure_digest!(
    PAUSABLE_OWNER_IS_PAUSED,
    PausableOwner::NAME,
    PausableOwner::IS_PAUSED_PROC_NAME,
    pausable_owner_library
);

/// Account component that exposes `pause` / `unpause` / `is_paused` admin procedures gated
/// by the [`crate::account::access::Ownable2Step`] owner.
///
/// Each public procedure in this component is `Invocation: call`. `pause` and `unpause`
/// assert that the note sender is the current owner before delegating to the underlying
/// `exec.pausable::pause` / `exec.pausable::unpause` primitives. `is_paused` is a read-only
/// passthrough with no authorization gate.
///
/// ## Companion components required
///
/// - [`crate::account::access::Ownable2Step`] — provides the owner storage slot the auth
///   check reads.
/// - [`crate::account::pausable::Pausable`] — provides the `is_paused` storage slot that
///   pause / unpause write to.
///
/// This component itself contributes no storage slots; both companion components must be
/// installed alongside it.
#[derive(Debug, Clone, Copy, Default)]
pub struct PausableOwner;

impl PausableOwner {
    /// Component library path (merged account module name).
    pub const NAME: &'static str = "miden::standards::components::utils::pausable_owner";

    pub const PAUSE_PROC_NAME: &'static str = "pause";
    pub const UNPAUSE_PROC_NAME: &'static str = "unpause";
    pub const IS_PAUSED_PROC_NAME: &'static str = "is_paused";

    /// Returns the digest of the `pause` procedure exposed by this component.
    pub fn pause_digest() -> Word {
        *PAUSABLE_OWNER_PAUSE
    }

    /// Returns the digest of the `unpause` procedure exposed by this component.
    pub fn unpause_digest() -> Word {
        *PAUSABLE_OWNER_UNPAUSE
    }

    /// Returns the digest of the `is_paused` procedure exposed by this component.
    pub fn is_paused_digest() -> Word {
        *PAUSABLE_OWNER_IS_PAUSED
    }

    /// Returns the [`AccountComponentMetadata`] describing this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME, AccountType::all()).with_description(
            "Owner-gated pause admin: wraps pausable::pause / unpause / is_paused with an \
             Ownable2Step::assert_sender_is_owner check. Requires the Ownable2Step and \
             Pausable companion components.",
        )
    }
}

impl From<PausableOwner> for AccountComponent {
    fn from(_: PausableOwner) -> Self {
        AccountComponent::new(
            pausable_owner_library(),
            vec![],
            PausableOwner::component_metadata(),
        )
        .expect(
            "PausableOwner component should satisfy the requirements of a valid account component",
        )
    }
}
