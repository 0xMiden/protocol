use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::procedure_root;

// BASIC CONSTANT FEE MANAGER
// ================================================================================================

account_component_code!(
    BASIC_CONSTANT_FEE_MANAGER_CODE,
    "miden-standards-fees-policies-basic-constant-fee-manager.masp"
);

procedure_root!(
    BASIC_CONSTANT_FEE_MANAGER_SET_NOTE_FEE,
    BasicConstantFeeManager::NAME,
    BasicConstantFeeManager::SET_NOTE_FEE_PROC_NAME,
    BasicConstantFeeManager::code()
);

/// Account component that exposes the `set_note_fee` admin procedure gated by the account-wide
/// [`crate::account::access::Authority`] component via `exec.authority::assert_authorized`.
///
/// `set_note_fee` updates the fee schedule map of a companion
/// [`crate::account::fees::BasicConstantFeePolicy`] after deployment, replacing the scheduled fee
/// for a note lookup key (the note's script root) with the amount of the supplied fee asset. The
/// supplied asset's ID must match the account's configured fee asset ID. This makes an otherwise
/// static fee schedule updatable by an authorized party.
///
/// Because the fee schedule policy and the fee asset ID both live on an `AuthNetworkAccount`, this
/// manager is only usable on a network account.
///
/// `BasicConstantFeeManager` works uniformly with every standard access scheme:
/// - [`crate::account::access::Authority::AuthControlled`] — gates the admin procedure via the
///   account's own auth component.
/// - [`crate::account::access::Authority::OwnerControlled`] — requires the Ownable2Step owner.
/// - [`crate::account::access::Authority::RbacControlled`] — resolves a role for the procedure. Map
///   [`Self::set_note_fee_root`] to a role symbol (e.g. a `FEE_ADMIN` role) to gate the operation.
///
/// Companion components required:
/// - [`crate::account::auth::AuthNetworkAccount`] — provides the fee asset ID slot and the fee
///   manager the schedule is priced against.
/// - [`crate::account::access::Authority`] — provides the mode-aware auth dispatch.
/// - [`crate::account::fees::BasicConstantFeePolicy`] (installed as the network account's active or
///   allowed fee policy) — owns the `fee_schedule` storage slot this component writes.
#[derive(Debug, Clone, Copy, Default)]
pub struct BasicConstantFeeManager;

impl BasicConstantFeeManager {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::fees::policies::basic_constant_fee_manager";

    const SET_NOTE_FEE_PROC_NAME: &'static str = "set_note_fee";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &BASIC_CONSTANT_FEE_MANAGER_CODE
    }

    /// Returns the procedure root of the `set_note_fee` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn set_note_fee_root() -> AccountProcedureRoot {
        *BASIC_CONSTANT_FEE_MANAGER_SET_NOTE_FEE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME).with_description(
            "Authority-gated basic-constant-fee schedule admin: exposes `set_note_fee` to update a \
             BasicConstantFeePolicy fee schedule, gated by the account-wide Authority component.",
        )
    }
}

impl From<BasicConstantFeeManager> for AccountComponent {
    fn from(_: BasicConstantFeeManager) -> Self {
        let metadata = BasicConstantFeeManager::component_metadata();
        AccountComponent::new(BasicConstantFeeManager::code().clone(), vec![], metadata).expect(
            "authority-gated basic-constant-fee schedule admin component should satisfy the \
             requirements of a valid account component",
        )
    }
}
