use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::allow_all_mint_policy_library;
use crate::procedure_digest;

// AUTH-CONTROLLED MINT POLICIES
// ================================================================================================

procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    MintAuthControlled::ALLOW_ALL_NAME,
    MintAuthControlled::ALLOW_ALL_PROC_NAME,
    allow_all_mint_policy_library
);

/// Namespace for auth-controlled mint policies (those intended for use with an auth-controlled
/// [`crate::account::policy_manager::MintPolicyManager`]).
///
/// Currently exposes the storage-free `allow_all` policy. Pair the resulting [`AccountComponent`]
/// with a [`crate::account::policy_manager::MintPolicyManager`] whose allowed-policies map
/// includes [`MintAuthControlled::allow_all_root`].
#[derive(Debug, Clone, Copy)]
pub struct MintAuthControlled;

impl MintAuthControlled {
    /// The name of the `allow_all` mint policy component.
    pub const ALLOW_ALL_NAME: &'static str =
        "miden::standards::components::mint_policies::auth_controlled::allow_all";

    const ALLOW_ALL_PROC_NAME: &str = "allow_all";

    /// Constructs the `allow_all` mint policy component.
    pub fn allow_all() -> Self {
        Self
    }

    /// Returns the MAST root of the `allow_all` mint policy procedure.
    pub fn allow_all_root() -> Word {
        *ALLOW_ALL_POLICY_ROOT
    }
}

impl From<MintAuthControlled> for AccountComponent {
    fn from(_: MintAuthControlled) -> Self {
        let metadata = AccountComponentMetadata::new(
            MintAuthControlled::ALLOW_ALL_NAME,
            [AccountType::FungibleFaucet],
        )
        .with_description("`allow_all` mint policy (auth-controlled family) for fungible faucets");

        AccountComponent::new(allow_all_mint_policy_library(), vec![], metadata).expect(
            "`allow_all` mint policy component should satisfy the requirements of a valid account component",
        )
    }
}

// MINT AUTH-CONTROLLED CONFIG
// ================================================================================================

/// Initial configuration for an auth-controlled [`crate::account::policy_manager::MintPolicyManager`].
///
/// Passed to [`crate::account::policy_manager::MintPolicyManager::auth_controlled`] to select which
/// policy is active when the faucet is first created.
#[derive(Debug, Clone, Copy, Default)]
pub enum MintAuthControlledConfig {
    /// Active policy = [`MintAuthControlled::allow_all_root`] (open minting).
    #[default]
    AllowAll,
    /// Active policy = the provided root. Must be one of the allowed policy roots registered on
    /// the manager.
    CustomInitialRoot(Word),
}

impl MintAuthControlledConfig {
    /// Resolves the config into the concrete policy root to install as the active mint policy.
    pub fn initial_policy_root(self) -> Word {
        match self {
            Self::AllowAll => MintAuthControlled::allow_all_root(),
            Self::CustomInitialRoot(root) => root,
        }
    }
}
