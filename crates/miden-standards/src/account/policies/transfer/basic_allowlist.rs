use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::account_component_package;
use crate::procedure_root;

// BASIC ALLOWLIST TRANSFER POLICY
// ================================================================================================

account_component_package!(
    BASIC_ALLOWLIST_TRANSFER_POLICY_PACKAGE,
    "miden-standards-faucets-policies-transfer-basic-allowlist.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from [`BasicAllowlist::NAME`],
/// which mirrors the standards-side MASM module path.
const BASIC_ALLOWLIST_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::transfer::basic_allowlist";

procedure_root!(
    BASIC_ALLOWLIST_SEND_POLICY_ROOT,
    BASIC_ALLOWLIST_LIBRARY_PATH,
    BasicAllowlist::SEND_PROC_NAME,
    BasicAllowlist::code()
);

procedure_root!(
    BASIC_ALLOWLIST_RECEIVE_POLICY_ROOT,
    BASIC_ALLOWLIST_LIBRARY_PATH,
    BasicAllowlist::RECEIVE_PROC_NAME,
    BasicAllowlist::code()
);

/// The storage-free basic allowlist transfer policy account component.
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose send and receive policy
/// maps include [`BasicAllowlist::send_root`] and [`BasicAllowlist::receive_root`]. When active,
/// transfers fail if the native account (asset recipient or note creator) is not currently
/// allowed on the issuing faucet.
///
/// The issuing faucet is exempt from its own allowlist.
///
/// The procedures read the `allowed_accounts` storage map installed by the
/// [`super::AllowlistStorage`] component, which must be installed on the account as well.
///
/// Allow / disallow administration is intentionally not part of this component. The
/// `allow_account` / `disallow_account` procedures live in the standards library and require
/// an auth-wrapped admin component (see [`super::AllowlistManager`]) to be safely
/// exposed on a production faucet.
#[derive(Debug, Clone, Copy, Default)]
pub struct BasicAllowlist;

impl BasicAllowlist {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::faucets::policies::transfer::basic_allowlist";

    pub(crate) const SEND_PROC_NAME: &str = "check_send_policy";
    pub(crate) const RECEIVE_PROC_NAME: &str = "check_receive_policy";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &BASIC_ALLOWLIST_TRANSFER_POLICY_PACKAGE.code
    }

    /// Returns the procedure root of the send policy procedure.
    pub fn send_root() -> AccountProcedureRoot {
        *BASIC_ALLOWLIST_SEND_POLICY_ROOT
    }

    /// Returns the procedure root of the receive policy procedure.
    pub fn receive_root() -> AccountProcedureRoot {
        *BASIC_ALLOWLIST_RECEIVE_POLICY_ROOT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        BASIC_ALLOWLIST_TRANSFER_POLICY_PACKAGE.metadata.clone()
    }
}

impl From<BasicAllowlist> for AccountComponent {
    fn from(_: BasicAllowlist) -> Self {
        let metadata = BasicAllowlist::component_metadata();

        AccountComponent::new(BasicAllowlist::code().clone(), vec![], metadata).expect(
            "basic allowlist transfer policy component should satisfy the requirements of a valid account component",
        )
    }
}
