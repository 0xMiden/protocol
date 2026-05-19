use alloc::collections::BTreeSet;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    StorageSchema,
};
use miden_protocol::account::{AccountComponent, AccountId, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::account::policies::transfer::blocklist::BlocklistStorage;
use crate::procedure_root;

// BASIC BLOCKLIST TRANSFER POLICY
// ================================================================================================

account_component_code!(
    BASIC_BLOCKLIST_TRANSFER_POLICY_CODE,
    "faucets/policies/transfer/basic_blocklist.masl"
);

procedure_root!(
    BASIC_BLOCKLIST_TRANSFER_POLICY_ROOT,
    BasicBlocklist::NAME,
    BasicBlocklist::PROC_NAME,
    BasicBlocklist::code()
);

/// The basic blocklist transfer policy account component.
///
/// Installs the per-faucet `blocked_accounts` storage map (defined by [`BlocklistStorage`])
/// plus the `check_policy` predicate procedure. Pair with a
/// [`crate::account::policies::TokenPolicyManager`] whose send / receive policy maps include
/// [`BasicBlocklist::root`]. When active, transfers fail if the native account (asset
/// recipient or note creator) is currently blocked on the issuing faucet.
///
/// The wrapped [`BTreeSet<AccountId>`] captures the initial blocklist contents (it can be
/// empty for a faucet that starts unblocked). Use [`Default`] for an empty blocklist or
/// [`Self::with_blocked_accounts`] to seed the storage map at component construction time.
///
/// Block / unblock administration is intentionally not part of this component. The
/// `block_account` / `unblock_account` procedures live in the standards library and require an
/// auth-wrapped admin component (see [`super::OwnerControlledBlocklist`]) to be safely exposed
/// on a production faucet.
#[derive(Debug, Clone, Default)]
pub struct BasicBlocklist(BTreeSet<AccountId>);

impl BasicBlocklist {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::basic_blocklist";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Creates a basic blocklist with the given initial blocked accounts.
    pub fn with_blocked_accounts<I>(blocked_accounts: I) -> Self
    where
        I: IntoIterator<Item = AccountId>,
    {
        Self(blocked_accounts.into_iter().collect())
    }

    /// Returns the initial blocked accounts captured in this component.
    pub fn blocked_accounts(&self) -> &BTreeSet<AccountId> {
        &self.0
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &BASIC_BLOCKLIST_TRANSFER_POLICY_CODE
    }

    /// Returns the MAST root of the basic blocklist transfer policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *BASIC_BLOCKLIST_TRANSFER_POLICY_ROOT
    }
}

impl From<BasicBlocklist> for AccountComponent {
    fn from(blocklist: BasicBlocklist) -> Self {
        let storage = BlocklistStorage::with_blocked_accounts(blocklist.0);
        let storage_schema = StorageSchema::new([BlocklistStorage::blocked_accounts_slot_schema()])
            .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(BasicBlocklist::NAME)
            .with_description(
                "Basic blocklist transfer policy: predicate procedure plus the `blocked_accounts` \
                 storage map it reads",
            )
            .with_storage_schema(storage_schema);

        AccountComponent::new(BasicBlocklist::code().clone(), vec![storage.into_slot()], metadata)
            .expect(
                "basic blocklist transfer policy component should satisfy the requirements of a valid account component",
            )
    }
}
