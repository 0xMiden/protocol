use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::if_not_blocklisted_transfer_policy_library;
use crate::procedure_digest;

// IF-NOT-BLOCKLISTED TRANSFER POLICY
// ================================================================================================

procedure_digest!(
    IF_NOT_BLOCKLISTED_POLICY_ROOT,
    TransferIfNotBlocklisted::NAME,
    TransferIfNotBlocklisted::PROC_NAME,
    if_not_blocklisted_transfer_policy_library
);

/// The storage-free `if_not_blocklisted` transfer policy account component.
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose allowed transfer-policies
/// map includes [`TransferIfNotBlocklisted::root`], plus a
/// [`crate::account::blocklistable::Blocklistable`] component that owns the per-account blocklist
/// storage map. When active, transfers fail if the native account (asset recipient or note
/// creator) is currently blocklisted on the issuing faucet.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferIfNotBlocklisted;

impl TransferIfNotBlocklisted {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::if_not_blocklisted";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the MAST root of the `if_not_blocklisted` transfer policy procedure.
    pub fn root() -> Word {
        *IF_NOT_BLOCKLISTED_POLICY_ROOT
    }
}

impl From<TransferIfNotBlocklisted> for AccountComponent {
    fn from(_: TransferIfNotBlocklisted) -> Self {
        let metadata = AccountComponentMetadata::new(
            TransferIfNotBlocklisted::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "`if_not_blocklisted` transfer policy for callback-enabled faucets; pairs with \
             Blocklistable",
        );

        AccountComponent::new(if_not_blocklisted_transfer_policy_library(), vec![], metadata)
            .expect(
                "`if_not_blocklisted` transfer policy component should satisfy the requirements of a valid account component",
            )
    }
}
