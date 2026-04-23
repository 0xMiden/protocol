use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::owner_only_mint_policy_library;
use crate::procedure_digest;

// OWNER-CONTROLLED MINT POLICIES
// ================================================================================================

procedure_digest!(
    OWNER_ONLY_POLICY_ROOT,
    MintOwnerControlled::OWNER_ONLY_NAME,
    MintOwnerControlled::OWNER_ONLY_PROC_NAME,
    owner_only_mint_policy_library
);

/// Namespace for owner-controlled mint policies (those defined under the
/// `miden::standards::mint_policies::owner_controlled` module on the standards side).
///
/// Currently exposes the storage-free `owner_only` policy. Pair the resulting [`AccountComponent`]
/// with a [`crate::account::policy_manager::MintPolicyManager`] whose allowed-policies map
/// includes [`MintOwnerControlled::owner_only_root`].
#[derive(Debug, Clone, Copy)]
pub struct MintOwnerControlled;

impl MintOwnerControlled {
    /// The name of the `owner_only` mint policy component.
    pub const OWNER_ONLY_NAME: &'static str =
        "miden::standards::components::mint_policies::owner_controlled::owner_only";

    const OWNER_ONLY_PROC_NAME: &str = "owner_only";

    /// Constructs the `owner_only` mint policy component.
    pub fn owner_only() -> Self {
        Self
    }

    /// Returns the MAST root of the `owner_only` mint policy procedure.
    pub fn owner_only_root() -> Word {
        *OWNER_ONLY_POLICY_ROOT
    }
}

impl From<MintOwnerControlled> for AccountComponent {
    fn from(_: MintOwnerControlled) -> Self {
        let metadata = AccountComponentMetadata::new(
            MintOwnerControlled::OWNER_ONLY_NAME,
            [AccountType::FungibleFaucet],
        )
        .with_description(
            "`owner_only` mint policy (owner-controlled family) for fungible faucets",
        );

        AccountComponent::new(owner_only_mint_policy_library(), vec![], metadata).expect(
            "`owner_only` mint policy component should satisfy the requirements of a valid account component",
        )
    }
}
