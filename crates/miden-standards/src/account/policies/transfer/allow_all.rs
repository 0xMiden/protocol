use miden_protocol::Word;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::account_component_code;
use crate::procedure_root;

// ALLOW-ALL TRANSFER POLICY
// ================================================================================================

account_component_code!(ALLOW_ALL_TRANSFER_POLICY_CODE, "faucets/policies/transfer/allow_all.masl");

procedure_root!(
    ALLOW_ALL_TRANSFER_POLICY_ROOT,
    TransferAllowAll::NAME,
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
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::allow_all";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &ALLOW_ALL_TRANSFER_POLICY_CODE
    }

    /// Returns the procedure root word of the `allow_all` transfer policy procedure.
    pub fn root() -> Word {
        (*ALLOW_ALL_TRANSFER_POLICY_ROOT).as_word()
    }
}

impl From<TransferAllowAll> for AccountComponent {
    fn from(_: TransferAllowAll) -> Self {
        let metadata = AccountComponentMetadata::new(
            TransferAllowAll::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description("`allow_all` transfer policy for callback-enabled faucets");

        AccountComponent::new(TransferAllowAll::code().clone(), vec![], metadata).expect(
            "`allow_all` transfer policy component should satisfy the requirements of a valid account component",
        )
    }
}
