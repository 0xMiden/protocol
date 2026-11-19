use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::account_component_package;
use crate::procedure_root;

// BASIC BLOCKLIST TRANSFER POLICY
// ================================================================================================

account_component_package!(
    BASIC_BLOCKLIST_TRANSFER_POLICY_PACKAGE,
    "miden-standards-faucets-policies-transfer-basic-blocklist.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from [`BasicBlocklist::NAME`],
/// which mirrors the standards-side MASM module path.
const BASIC_BLOCKLIST_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::transfer::basic_blocklist";

procedure_root!(
    BASIC_BLOCKLIST_SEND_POLICY_ROOT,
    BASIC_BLOCKLIST_LIBRARY_PATH,
    BasicBlocklist::SEND_PROC_NAME,
    BasicBlocklist::code()
);

procedure_root!(
    BASIC_BLOCKLIST_RECEIVE_POLICY_ROOT,
    BASIC_BLOCKLIST_LIBRARY_PATH,
    BasicBlocklist::RECEIVE_PROC_NAME,
    BasicBlocklist::code()
);

/// The storage-free basic blocklist transfer policy account component.
///
/// Installs the `check_send_policy` and `check_receive_policy` predicate procedures. Pair with a
/// [`crate::account::policies::TokenPolicyManager`] whose send and receive policy maps include
/// [`BasicBlocklist::send_root`] and [`BasicBlocklist::receive_root`]. When active, transfers
/// fail if the native account (asset recipient or note creator) is currently blocked on the
/// issuing faucet.
///
/// The issuing faucet is exempt from its own blocklist.
///
/// The procedures read the `blocked_accounts` storage map installed by the
/// [`super::BlocklistStorage`] component, which must be installed on the account as well.
///
/// Block / unblock administration is intentionally not part of this component. The
/// `block_account` / `unblock_account` procedures live in the standards library and require an
/// auth-wrapped admin component (see [`super::BlocklistManager`]) to be safely exposed
/// on a production faucet.
#[derive(Debug, Clone, Copy, Default)]
pub struct BasicBlocklist;

impl BasicBlocklist {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::faucets::policies::transfer::basic_blocklist";

    pub(crate) const SEND_PROC_NAME: &str = "check_send_policy";
    pub(crate) const RECEIVE_PROC_NAME: &str = "check_receive_policy";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &BASIC_BLOCKLIST_TRANSFER_POLICY_PACKAGE.code
    }

    /// Returns the procedure root of the send policy procedure.
    pub fn send_root() -> AccountProcedureRoot {
        *BASIC_BLOCKLIST_SEND_POLICY_ROOT
    }

    /// Returns the procedure root of the receive policy procedure.
    pub fn receive_root() -> AccountProcedureRoot {
        *BASIC_BLOCKLIST_RECEIVE_POLICY_ROOT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        BASIC_BLOCKLIST_TRANSFER_POLICY_PACKAGE.metadata.clone()
    }
}

impl From<BasicBlocklist> for AccountComponent {
    fn from(_: BasicBlocklist) -> Self {
        let metadata = BasicBlocklist::component_metadata();

        AccountComponent::new(BasicBlocklist::code().clone(), vec![], metadata).expect(
            "basic blocklist transfer policy component should satisfy the requirements of a valid account component",
        )
    }
}
