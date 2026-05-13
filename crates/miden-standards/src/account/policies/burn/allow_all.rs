use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot, AccountType};
use miden_protocol::assembly::Library;
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::utils::sync::LazyLock;

use crate::procedure_digest;

// ALLOW-ALL BURN POLICY
// ================================================================================================

// Initialize the `allow_all` Burn Policy component code only once.
static ALLOW_ALL_BURN_POLICY_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/faucets/policies/burn/allow_all.masl"
    ));
    let library = Library::read_from_bytes(bytes)
        .expect("Shipped `allow_all` Burn Policy library is well-formed");
    AccountComponentCode::from(library)
});

procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    BurnAllowAll::NAME,
    BurnAllowAll::PROC_NAME,
    BurnAllowAll::code()
);

/// The storage-free `allow_all` burn policy account component.
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose allowed burn-policies
/// map includes [`BurnAllowAll::root`]. `allow_all` makes burning permissionless (no additional
/// authorization beyond the manager's authority gate).
#[derive(Debug, Clone, Copy, Default)]
pub struct BurnAllowAll;

impl BurnAllowAll {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::burn::allow_all";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &ALLOW_ALL_BURN_POLICY_CODE
    }

    /// Returns the procedure root of the `allow_all` burn policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *ALLOW_ALL_POLICY_ROOT
    }
}

impl From<BurnAllowAll> for AccountComponent {
    fn from(_: BurnAllowAll) -> Self {
        let metadata =
            AccountComponentMetadata::new(BurnAllowAll::NAME, [AccountType::FungibleFaucet])
                .with_description("`allow_all` burn policy for fungible faucets");

        AccountComponent::new(BurnAllowAll::code().clone(), vec![], metadata).expect(
            "`allow_all` burn policy component should satisfy the requirements of a valid account component",
        )
    }
}
