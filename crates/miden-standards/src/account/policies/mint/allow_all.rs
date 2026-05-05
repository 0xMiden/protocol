use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::allow_all_mint_policy_library;
use crate::procedure_digest;

// ALLOW-ALL MINT POLICY
// ================================================================================================

procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    MintAllowAll::NAME,
    MintAllowAll::PROC_NAME,
    allow_all_mint_policy_library
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

    /// Returns the MAST root of the `allow_all` mint policy procedure.
    pub fn root() -> Word {
        *ALLOW_ALL_POLICY_ROOT
    }
}

impl From<MintAllowAll> for AccountComponent {
    fn from(_: MintAllowAll) -> Self {
        let metadata =
            AccountComponentMetadata::new(MintAllowAll::NAME, [AccountType::FungibleFaucet])
                .with_description("`allow_all` mint policy for fungible faucets");

        AccountComponent::new(allow_all_mint_policy_library(), vec![], metadata).expect(
            "`allow_all` mint policy component should satisfy the requirements of a valid account component",
        )
    }
}
