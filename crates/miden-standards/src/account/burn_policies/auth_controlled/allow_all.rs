use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::allow_all_burn_policy_library;
use crate::procedure_digest;

// AUTH-CONTROLLED BURN POLICIES
// ================================================================================================

procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    BurnAuthControlled::ALLOW_ALL_NAME,
    BurnAuthControlled::ALLOW_ALL_PROC_NAME,
    allow_all_burn_policy_library
);

/// Namespace for auth-controlled burn policies (those intended for use with an auth-controlled
/// [`crate::account::policy_manager::BurnPolicyManager`]).
///
/// Currently exposes the storage-free `allow_all` policy. Pair the resulting [`AccountComponent`]
/// with a [`crate::account::policy_manager::BurnPolicyManager`] whose allowed-policies map
/// includes [`BurnAuthControlled::allow_all_root`].
#[derive(Debug, Clone, Copy)]
pub struct BurnAuthControlled;

impl BurnAuthControlled {
    /// The name of the `allow_all` burn policy component.
    pub const ALLOW_ALL_NAME: &'static str =
        "miden::standards::components::burn_policies::auth_controlled::allow_all";

    const ALLOW_ALL_PROC_NAME: &str = "allow_all";

    /// Constructs the `allow_all` burn policy component.
    pub fn allow_all() -> Self {
        Self
    }

    /// Returns the MAST root of the `allow_all` burn policy procedure.
    pub fn allow_all_root() -> Word {
        *ALLOW_ALL_POLICY_ROOT
    }
}

impl From<BurnAuthControlled> for AccountComponent {
    fn from(_: BurnAuthControlled) -> Self {
        let metadata = AccountComponentMetadata::new(
            BurnAuthControlled::ALLOW_ALL_NAME,
            [AccountType::FungibleFaucet],
        )
        .with_description("`allow_all` burn policy (auth-controlled family) for fungible faucets");

        AccountComponent::new(allow_all_burn_policy_library(), vec![], metadata).expect(
            "`allow_all` burn policy component should satisfy the requirements of a valid account component",
        )
    }
}

// BURN AUTH-CONTROLLED CONFIG
// ================================================================================================

/// Initial configuration for an auth-controlled [`crate::account::policy_manager::BurnPolicyManager`].
///
/// Passed to [`crate::account::policy_manager::BurnPolicyManager::auth_controlled`] to select which
/// policy is active when the faucet is first created.
#[derive(Debug, Clone, Copy, Default)]
pub enum BurnAuthControlledConfig {
    /// Active policy = [`BurnAuthControlled::allow_all_root`] (open burning).
    #[default]
    AllowAll,
    /// Active policy = the provided root. Must be one of the allowed policy roots registered on
    /// the manager.
    CustomInitialRoot(Word),
}

impl BurnAuthControlledConfig {
    /// Resolves the config into the concrete policy root to install as the active burn policy.
    pub fn initial_policy_root(self) -> Word {
        match self {
            Self::AllowAll => BurnAuthControlled::allow_all_root(),
            Self::CustomInitialRoot(root) => root,
        }
    }
}
