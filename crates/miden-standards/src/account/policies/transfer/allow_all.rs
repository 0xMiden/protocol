use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::allow_all_transfer_policy_library;
use crate::procedure_digest;

// ALLOW-ALL TRANSFER POLICY
// ================================================================================================

procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    TransferAllowAll::NAME,
    TransferAllowAll::PROC_NAME,
    allow_all_transfer_policy_library
);

/// The storage-free `allow_all` transfer policy account component.
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose allowed transfer-policies
/// map includes [`TransferAllowAll::root`]. When active, every transfer succeeds.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferAllowAll;

impl TransferAllowAll {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::allow_all";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the MAST root of the `allow_all` transfer policy procedure.
    pub fn root() -> Word {
        *ALLOW_ALL_POLICY_ROOT
    }
}

impl From<TransferAllowAll> for AccountComponent {
    fn from(_: TransferAllowAll) -> Self {
        let metadata = AccountComponentMetadata::new(
            TransferAllowAll::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description("`allow_all` transfer policy for callback-enabled faucets");

        AccountComponent::new(allow_all_transfer_policy_library(), vec![], metadata).expect(
            "`allow_all` transfer policy component should satisfy the requirements of a valid account component",
        )
    }
}
