use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::allow_all_burn_policy_library;
use crate::procedure_digest;

// ALLOW-ALL BURN POLICY
// ================================================================================================

procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    BurnAllowAll::NAME,
    BurnAllowAll::PROC_NAME,
    allow_all_burn_policy_library
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

    /// Returns the MAST root of the `allow_all` burn policy procedure.
    pub fn root() -> Word {
        *ALLOW_ALL_POLICY_ROOT
    }
}

impl From<BurnAllowAll> for AccountComponent {
    fn from(_: BurnAllowAll) -> Self {
        let metadata =
            AccountComponentMetadata::new(BurnAllowAll::NAME, [AccountType::FungibleFaucet])
                .with_description("`allow_all` burn policy for fungible faucets");

        AccountComponent::new(allow_all_burn_policy_library(), vec![], metadata).expect(
            "`allow_all` burn policy component should satisfy the requirements of a valid account component",
        )
    }
}
