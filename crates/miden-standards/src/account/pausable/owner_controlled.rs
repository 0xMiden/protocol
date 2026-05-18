use alloc::vec;

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot, AccountType};

use crate::account::account_component_code;
use crate::procedure_root;

account_component_code!(PAUSABLE_OWNER_CONTROLLED_CODE, "utils/pausable/owner_controlled.masl");

// PAUSABLE OWNER-CONTROLLED ADMIN COMPONENT
// ================================================================================================

procedure_root!(
    PAUSABLE_OWNER_CONTROLLED_PAUSE,
    PausableOwnerControlled::NAME,
    PausableOwnerControlled::PAUSE_PROC_NAME,
    PausableOwnerControlled::code()
);

procedure_root!(
    PAUSABLE_OWNER_CONTROLLED_UNPAUSE,
    PausableOwnerControlled::NAME,
    PausableOwnerControlled::UNPAUSE_PROC_NAME,
    PausableOwnerControlled::code()
);

procedure_root!(
    PAUSABLE_OWNER_CONTROLLED_IS_PAUSED,
    PausableOwnerControlled::NAME,
    PausableOwnerControlled::IS_PAUSED_PROC_NAME,
    PausableOwnerControlled::code()
);

/// Account component that exposes `pause` / `unpause` / `is_paused` admin procedures gated by
/// the [`crate::account::access::Ownable2Step`] owner.
///
/// The wrapper procedures live in `miden::standards::utils::pausable::owner_controlled` and
/// call `ownable2step::assert_sender_is_owner` before delegating to the standards-library
/// helpers in `miden::standards::utils::pausable`. The `is_paused` procedure is a read-only
/// passthrough with no authorization gate.
///
/// Companion components required:
/// - [`crate::account::access::Ownable2Step`] — provides the owner storage slot the auth check
///   reads.
/// - [`super::BasicPausable`] — provides the `is_paused` storage slot that pause / unpause write
///   to.
#[derive(Debug, Clone, Copy, Default)]
pub struct PausableOwnerControlled;

impl PausableOwnerControlled {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::utils::pausable::owner_controlled";

    pub const PAUSE_PROC_NAME: &'static str = "pause";
    pub const UNPAUSE_PROC_NAME: &'static str = "unpause";
    pub const IS_PAUSED_PROC_NAME: &'static str = "is_paused";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &PAUSABLE_OWNER_CONTROLLED_CODE
    }

    /// Returns the procedure root of the `pause` procedure exposed by this component.
    pub fn pause_root() -> AccountProcedureRoot {
        *PAUSABLE_OWNER_CONTROLLED_PAUSE
    }

    /// Returns the procedure root of the `unpause` procedure exposed by this component.
    pub fn unpause_root() -> AccountProcedureRoot {
        *PAUSABLE_OWNER_CONTROLLED_UNPAUSE
    }

    /// Returns the procedure root of the `is_paused` procedure exposed by this component.
    pub fn is_paused_root() -> AccountProcedureRoot {
        *PAUSABLE_OWNER_CONTROLLED_IS_PAUSED
    }

    /// Returns the [`AccountComponentMetadata`] describing this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME, AccountType::all()).with_description(
            "Owner-controlled pause admin: wraps `pausable::pause` / `unpause` / `is_paused` \
             with Ownable2Step authorization.",
        )
    }
}

impl From<PausableOwnerControlled> for AccountComponent {
    fn from(_: PausableOwnerControlled) -> Self {
        let metadata = PausableOwnerControlled::component_metadata();
        AccountComponent::new(PausableOwnerControlled::code().clone(), vec![], metadata).expect(
            "owner-controlled pausable admin component should satisfy the requirements of a valid account component",
        )
    }
}
