use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::owner_only_burn_policy_library;
use crate::procedure_digest;

// OWNER-ONLY BURN POLICY
// ================================================================================================

procedure_digest!(
    OWNER_ONLY_POLICY_ROOT,
    BurnOwnerOnly::NAME,
    BurnOwnerOnly::PROC_NAME,
    owner_only_burn_policy_library
);

/// The storage-free `owner_only` burn policy account component (owner-controlled family).
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose allowed burn-policies
/// map includes [`BurnOwnerOnly::root`]. When active, only the account owner (as recorded by
/// the `Ownable2Step` component) may trigger burn operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct BurnOwnerOnly;

impl BurnOwnerOnly {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::burn::owner_controlled::owner_only";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the MAST root of the `owner_only` burn policy procedure.
    pub fn root() -> Word {
        *OWNER_ONLY_POLICY_ROOT
    }
}

impl From<BurnOwnerOnly> for AccountComponent {
    fn from(_: BurnOwnerOnly) -> Self {
        let metadata =
            AccountComponentMetadata::new(BurnOwnerOnly::NAME, [AccountType::FungibleFaucet])
                .with_description(
                    "`owner_only` burn policy (owner-controlled family) for fungible faucets",
                );

        AccountComponent::new(owner_only_burn_policy_library(), vec![], metadata).expect(
            "`owner_only` burn policy component should satisfy the requirements of a valid account component",
        )
    }
}
