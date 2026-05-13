use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot, AccountType};
use miden_protocol::assembly::Library;
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::utils::sync::LazyLock;

use crate::procedure_digest;

// ALLOW-ALL MINT POLICY
// ================================================================================================

// Initialize the `allow_all` Mint Policy component code only once.
static ALLOW_ALL_MINT_POLICY_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/faucets/policies/mint/allow_all.masl"
    ));
    let library = Library::read_from_bytes(bytes)
        .expect("Shipped `allow_all` Mint Policy library is well-formed");
    AccountComponentCode::from(library)
});

procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    MintAllowAll::NAME,
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
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::mint::allow_all";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &ALLOW_ALL_MINT_POLICY_CODE
    }

    /// Returns the procedure root of the `allow_all` mint policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *ALLOW_ALL_POLICY_ROOT
    }
}

impl From<MintAllowAll> for AccountComponent {
    fn from(_: MintAllowAll) -> Self {
        let metadata =
            AccountComponentMetadata::new(MintAllowAll::NAME, [AccountType::FungibleFaucet])
                .with_description("`allow_all` mint policy for fungible faucets");

        AccountComponent::new(MintAllowAll::code().clone(), vec![], metadata).expect(
            "`allow_all` mint policy component should satisfy the requirements of a valid account component",
        )
    }
}
