use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::owner_only_burn_policy_library;
use crate::procedure_digest;

// OWNER-CONTROLLED BURN POLICIES
// ================================================================================================

procedure_digest!(
    OWNER_ONLY_POLICY_ROOT,
    BurnOwnerControlled::OWNER_ONLY_NAME,
    BurnOwnerControlled::OWNER_ONLY_PROC_NAME,
    owner_only_burn_policy_library
);

/// Namespace for owner-controlled burn policies (those defined under the
/// `miden::standards::burn_policies::owner_controlled` module on the standards side).
///
/// Currently exposes the storage-free `owner_only` policy. Pair the resulting [`AccountComponent`]
/// with a [`crate::account::policy_manager::BurnPolicyManager`] whose allowed-policies map
/// includes [`BurnOwnerControlled::owner_only_root`].
#[derive(Debug, Clone, Copy)]
pub struct BurnOwnerControlled;

impl BurnOwnerControlled {
    /// The name of the `owner_only` burn policy component.
    pub const OWNER_ONLY_NAME: &'static str =
        "miden::standards::components::burn_policies::owner_controlled::owner_only";

    const OWNER_ONLY_PROC_NAME: &str = "owner_only";

    /// Constructs the `owner_only` burn policy component.
    pub fn owner_only() -> Self {
        Self
    }

    /// Returns the MAST root of the `owner_only` burn policy procedure.
    pub fn owner_only_root() -> Word {
        *OWNER_ONLY_POLICY_ROOT
    }
}

impl From<BurnOwnerControlled> for AccountComponent {
    fn from(_: BurnOwnerControlled) -> Self {
        let metadata = AccountComponentMetadata::new(
            BurnOwnerControlled::OWNER_ONLY_NAME,
            [AccountType::FungibleFaucet],
        )
        .with_description(
            "`owner_only` burn policy (owner-controlled family) for fungible faucets",
        );

        AccountComponent::new(owner_only_burn_policy_library(), vec![], metadata).expect(
            "`owner_only` burn policy component should satisfy the requirements of a valid account component",
        )
    }
}
