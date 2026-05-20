use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    StorageSchema,
};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::account::pausable::PausableStorage;
use crate::procedure_root;

// BASIC PAUSABLE TRANSFER POLICY
// ================================================================================================

account_component_code!(
    BASIC_PAUSABLE_TRANSFER_POLICY_CODE,
    "faucets/policies/transfer/basic_pausable.masl"
);

procedure_root!(
    BASIC_PAUSABLE_TRANSFER_POLICY_ROOT,
    BasicPausable::NAME,
    BasicPausable::PROC_NAME,
    BasicPausable::code()
);

/// The basic pausable transfer policy account component.
///
/// Installs the per-account `is_paused` storage slot (defined by [`PausableStorage`]) plus
/// the `check_policy` predicate procedure. Pair with a
/// [`crate::account::policies::TokenPolicyManager`] whose send / receive policy maps include
/// [`BasicPausable::root`]. When active, transfers fail while the issuing faucet is paused.
///
/// The wrapped `initial_state` captures whether the account starts paused (default: unpaused).
/// Use [`Default`] for an unpaused start or [`Self::paused`] / [`Self::unpaused`] for explicit
/// literals.
///
/// Pause / unpause administration is intentionally not part of this component. The
/// `pause` / `unpause` procedures live in the standards library and require an auth-wrapped
/// admin component (see [`crate::account::pausable::PausableOwnerControlled`],
/// [`crate::account::pausable::PausableRoleControlled`], or
/// [`crate::account::pausable::PausableAuthControlled`]) to be safely exposed on a
/// production faucet.
#[derive(Debug, Clone, Copy, Default)]
pub struct BasicPausable {
    initial_state: bool,
}

impl BasicPausable {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::basic_pausable";

    pub(crate) const PROC_NAME: &'static str = "check_policy";

    /// Creates a basic pausable transfer policy with the given initial pause state.
    pub const fn new(initial_state: bool) -> Self {
        Self { initial_state }
    }

    /// Creates a basic pausable transfer policy that starts in the paused state.
    pub const fn paused() -> Self {
        Self::new(true)
    }

    /// Creates a basic pausable transfer policy that starts in the unpaused state.
    pub const fn unpaused() -> Self {
        Self::new(false)
    }

    /// Returns the initial pause state captured in this component.
    pub fn initial_state(&self) -> bool {
        self.initial_state
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &BASIC_PAUSABLE_TRANSFER_POLICY_CODE
    }

    /// Returns the MAST root of the basic pausable transfer policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *BASIC_PAUSABLE_TRANSFER_POLICY_ROOT
    }
}

impl From<BasicPausable> for AccountComponent {
    fn from(pausable: BasicPausable) -> Self {
        let storage = PausableStorage::with_initial_state(pausable.initial_state);
        let storage_schema = StorageSchema::new([PausableStorage::is_paused_slot_schema()])
            .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(BasicPausable::NAME)
            .with_description(
                "Basic pausable transfer policy: `check_policy` predicate plus the `is_paused` \
                 storage slot it reads",
            )
            .with_storage_schema(storage_schema);

        AccountComponent::new(BasicPausable::code().clone(), vec![storage.into_slot()], metadata)
            .expect(
                "basic pausable transfer policy component should satisfy the requirements of a valid account component",
            )
    }
}
