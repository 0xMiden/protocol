use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::allow_all_burn_policy_library;
use crate::procedure_digest;

// ALLOW-ALL BURN POLICY
// ================================================================================================

procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    AllowAll::NAME,
    AllowAll::PROC_NAME,
    allow_all_burn_policy_library
);

/// The storage-free `allow_all` burn policy account component.
///
/// Pair with a [`crate::account::policies::burn::PolicyManager`] whose allowed-policies
/// map includes [`AllowAll::root`]. `allow_all` makes burning permissionless (no additional
/// authorization beyond the manager's authority gate).
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl AllowAll {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::policies::burn::mod";

    const PROC_NAME: &str = "allow_all";

    /// Returns the MAST root of the `allow_all` burn policy procedure.
    pub fn root() -> Word {
        *ALLOW_ALL_POLICY_ROOT
    }
}

impl From<AllowAll> for AccountComponent {
    fn from(_: AllowAll) -> Self {
        let metadata = AccountComponentMetadata::new(AllowAll::NAME, [AccountType::FungibleFaucet])
            .with_description("`allow_all` burn policy for fungible faucets");

        AccountComponent::new(allow_all_burn_policy_library(), vec![], metadata).expect(
            "`allow_all` burn policy component should satisfy the requirements of a valid account component",
        )
    }
}
