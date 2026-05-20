use alloc::collections::BTreeSet;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    StorageSchema,
};
use miden_protocol::account::{AccountComponent, AccountId, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::account::pausable::PausableStorage;
use crate::account::policies::transfer::blocklist::BlocklistStorage;
use crate::procedure_root;

// PAUSABLE-BLOCKLIST COMPOSITE TRANSFER POLICY
// ================================================================================================

account_component_code!(
    PAUSABLE_BLOCKLIST_TRANSFER_POLICY_CODE,
    "faucets/policies/transfer/pausable_blocklist.masl"
);

procedure_root!(
    PAUSABLE_BLOCKLIST_TRANSFER_POLICY_ROOT,
    PausableBlocklist::NAME,
    PausableBlocklist::PROC_NAME,
    PausableBlocklist::code()
);

/// Composite transfer policy combining the pause and blocklist guards.
///
/// Installs BOTH the `is_paused` storage slot (via [`PausableStorage`]) and the
/// `blocked_accounts` storage map (via [`BlocklistStorage`]), plus a single `check_policy`
/// predicate that runs `assert_not_paused` followed by `assert_not_blocked`. A transfer is
/// rejected if EITHER the issuing faucet is paused OR the native account is currently
/// blocked.
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose send / receive policy
/// maps include [`Self::root`]. Pause / unpause administration is delegated to the
/// auth-wrapped admin components in [`crate::account::pausable`]; block / unblock
/// administration is delegated to [`super::BlocklistOwnerControlled`].
///
/// Use the builder methods [`Self::with_initial_pause_state`] and
/// [`Self::with_initial_blocked_accounts`] to seed the storage at install time.
#[derive(Debug, Clone, Default)]
pub struct PausableBlocklist {
    initial_pause_state: bool,
    initial_blocked_accounts: BTreeSet<AccountId>,
}

impl PausableBlocklist {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::pausable_blocklist";

    pub(crate) const PROC_NAME: &'static str = "check_policy";

    /// Creates a composite pause-and-blocklist transfer policy that starts unpaused and with
    /// no initially blocked accounts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the initial pause state captured by this component.
    pub fn with_initial_pause_state(mut self, paused: bool) -> Self {
        self.initial_pause_state = paused;
        self
    }

    /// Sets the initial blocked accounts captured by this component.
    pub fn with_initial_blocked_accounts(
        mut self,
        accounts: impl IntoIterator<Item = AccountId>,
    ) -> Self {
        self.initial_blocked_accounts = accounts.into_iter().collect();
        self
    }

    /// Returns the initial pause state captured in this component.
    pub fn initial_pause_state(&self) -> bool {
        self.initial_pause_state
    }

    /// Returns the initial blocked accounts captured in this component.
    pub fn initial_blocked_accounts(&self) -> &BTreeSet<AccountId> {
        &self.initial_blocked_accounts
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &PAUSABLE_BLOCKLIST_TRANSFER_POLICY_CODE
    }

    /// Returns the MAST root of the composite pause-and-blocklist transfer policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *PAUSABLE_BLOCKLIST_TRANSFER_POLICY_ROOT
    }
}

impl From<PausableBlocklist> for AccountComponent {
    fn from(combo: PausableBlocklist) -> Self {
        let pause_slot = PausableStorage::with_initial_state(combo.initial_pause_state).into_slot();
        let blocked_slot =
            BlocklistStorage::with_blocked_accounts(combo.initial_blocked_accounts).into_slot();

        let storage_schema = StorageSchema::new([
            PausableStorage::is_paused_slot_schema(),
            BlocklistStorage::blocked_accounts_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(PausableBlocklist::NAME)
            .with_description(
                "Composite pause-and-blocklist transfer policy: `check_policy` predicate plus \
                 the `is_paused` flag and `blocked_accounts` map it reads",
            )
            .with_storage_schema(storage_schema);

        AccountComponent::new(
            PausableBlocklist::code().clone(),
            alloc::vec![pause_slot, blocked_slot],
            metadata,
        )
        .expect(
            "pausable-blocklist transfer policy component should satisfy the requirements of a valid account component",
        )
    }
}
