use alloc::collections::BTreeSet;

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountId, AccountProcedureRoot};

use crate::account::policies::transfer::blocklist::BlocklistStorage;
use crate::account::{account_component_code, package_metadata};
use crate::procedure_root;

// BASIC BLOCKLIST TRANSFER POLICY
// ================================================================================================

account_component_code!(
    BASIC_BLOCKLIST_TRANSFER_POLICY_CODE,
    "miden-standards-faucets-policies-transfer-basic-blocklist.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from [`BasicBlocklist::NAME`],
/// which mirrors the standards-side MASM module path.
const BASIC_BLOCKLIST_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::transfer::basic_blocklist";

procedure_root!(
    BASIC_BLOCKLIST_TRANSFER_POLICY_ROOT,
    BASIC_BLOCKLIST_LIBRARY_PATH,
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
/// The issuing faucet is exempt from its own blocklist.
///
/// The wrapped [`BlocklistStorage`] captures the initial blocklist contents (it can be empty
/// for a faucet that starts unblocked). Use [`Default`] for an empty blocklist or
/// [`Self::with_blocked_accounts`] to seed the storage map at component construction time.
///
/// Block / unblock administration is intentionally not part of this component. The
/// `block_account` / `unblock_account` procedures live in the standards library and require an
/// auth-wrapped admin component (see [`super::BlocklistManager`]) to be safely exposed
/// on a production faucet.
#[derive(Debug, Clone, Default)]
pub struct BasicBlocklist(BlocklistStorage);

impl BasicBlocklist {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::faucets::policies::transfer::basic_blocklist";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Creates a basic blocklist with the given initial blocked accounts.
    pub fn with_blocked_accounts<I>(blocked_accounts: I) -> Self
    where
        I: IntoIterator<Item = AccountId>,
    {
        Self(BlocklistStorage::with_blocked_accounts(blocked_accounts))
    }

    /// Returns the initial blocked accounts captured in this component.
    pub fn blocked_accounts(&self) -> &BTreeSet<AccountId> {
        self.0.blocked_accounts()
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &BASIC_BLOCKLIST_TRANSFER_POLICY_CODE
    }

    /// Returns the MAST root of the basic blocklist transfer policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *BASIC_BLOCKLIST_TRANSFER_POLICY_ROOT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        package_metadata(Self::code())
    }
}

impl From<BlocklistStorage> for BasicBlocklist {
    fn from(storage: BlocklistStorage) -> Self {
        Self(storage)
    }
}

impl From<BasicBlocklist> for AccountComponent {
    fn from(blocklist: BasicBlocklist) -> Self {
        let metadata = BasicBlocklist::component_metadata();

        AccountComponent::new(BasicBlocklist::code().clone(), vec![blocklist.0.into_slot()], metadata)
            .expect(
                "basic blocklist transfer policy component should satisfy the requirements of a valid account component",
            )
    }
}
