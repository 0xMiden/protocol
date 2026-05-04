use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::owner_only_mint_policy_library;
use crate::procedure_digest;

// OWNER-ONLY MINT POLICY
// ================================================================================================

procedure_digest!(
    OWNER_ONLY_POLICY_ROOT,
    MintOwnerOnly::NAME,
    MintOwnerOnly::PROC_NAME,
    owner_only_mint_policy_library
);

/// The storage-free `owner_only` mint policy account component (owner-controlled family).
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose allowed mint-policies
/// map includes [`MintOwnerOnly::root`]. When active, only the account owner (as recorded by
/// the `Ownable2Step` component) may trigger mint operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct MintOwnerOnly;

impl MintOwnerOnly {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::mint::owner_controlled::owner_only";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the MAST root of the `owner_only` mint policy procedure.
    pub fn root() -> Word {
        *OWNER_ONLY_POLICY_ROOT
    }
}

impl From<MintOwnerOnly> for AccountComponent {
    fn from(_: MintOwnerOnly) -> Self {
        let metadata =
            AccountComponentMetadata::new(MintOwnerOnly::NAME, [AccountType::FungibleFaucet])
                .with_description(
                    "`owner_only` mint policy (owner-controlled family) for fungible faucets",
                );

        AccountComponent::new(owner_only_mint_policy_library(), vec![], metadata).expect(
            "`owner_only` mint policy component should satisfy the requirements of a valid account component",
        )
    }
}
