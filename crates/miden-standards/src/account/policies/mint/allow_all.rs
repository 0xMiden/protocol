use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName, AccountProcedureRoot};

use crate::account::{account_component_code, package_metadata};
use crate::procedure_root;

// ALLOW-ALL MINT POLICY
// ================================================================================================

account_component_code!(
    ALLOW_ALL_MINT_POLICY_CODE,
    "miden-standards-faucets-policies-mint-allow-all.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from [`MintAllowAll::NAME`],
/// which mirrors the standards-side MASM module path.
const MINT_ALLOW_ALL_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::mint::allow_all";

procedure_root!(
    ALLOW_ALL_POLICY_ROOT,
    MINT_ALLOW_ALL_LIBRARY_PATH,
    MintAllowAll::PROC_NAME,
    MintAllowAll::code()
);

/// The storage-free `allow_all` mint policy account component.
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose allowed mint-policies
/// map includes [`MintAllowAll::root`]. `allow_all` makes minting permissionless (no additional
/// authorization beyond the manager's authority gate).
#[derive(Debug, Clone, Copy, Default)]
pub struct MintAllowAll;

impl MintAllowAll {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::faucets::policies::mint::allow_all";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &ALLOW_ALL_MINT_POLICY_CODE
    }

    /// Returns the procedure root of the `allow_all` mint policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *ALLOW_ALL_POLICY_ROOT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        package_metadata(Self::code())
    }
}

impl From<MintAllowAll> for AccountComponent {
    fn from(_: MintAllowAll) -> Self {
        let metadata = MintAllowAll::component_metadata();

        AccountComponent::new(MintAllowAll::code().clone(), vec![], metadata).expect(
            "`allow_all` mint policy component should satisfy the requirements of a valid account component",
        )
    }
}
