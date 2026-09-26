use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::{account_component_code, package_metadata};
use crate::procedure_root;

// ALLOW-ALL TRANSFER POLICY
// ================================================================================================

account_component_code!(
    ALLOW_ALL_TRANSFER_POLICY_CODE,
    "miden-standards-faucets-policies-transfer-allow-all.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`TransferAllowAll::NAME`], which mirrors the standards-side MASM module path.
const TRANSFER_ALLOW_ALL_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::transfer::allow_all";

procedure_root!(
    ALLOW_ALL_TRANSFER_POLICY_ROOT,
    TRANSFER_ALLOW_ALL_LIBRARY_PATH,
    TransferAllowAll::PROC_NAME,
    TransferAllowAll::code()
);

/// The storage-free `allow_all` transfer policy account component.
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose allowed transfer-policies
/// map includes [`TransferAllowAll::root`]. When active, every transfer succeeds.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferAllowAll;

impl TransferAllowAll {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::faucets::policies::transfer::allow_all";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &ALLOW_ALL_TRANSFER_POLICY_CODE
    }

    /// Returns the procedure root of the `allow_all` transfer policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *ALLOW_ALL_TRANSFER_POLICY_ROOT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        package_metadata(Self::code())
    }
}

impl From<TransferAllowAll> for AccountComponent {
    fn from(_: TransferAllowAll) -> Self {
        let metadata = TransferAllowAll::component_metadata();

        AccountComponent::new(TransferAllowAll::code().clone(), vec![], metadata).expect(
            "`allow_all` transfer policy component should satisfy the requirements of a valid account component",
        )
    }
}
