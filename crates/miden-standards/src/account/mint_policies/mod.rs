//! Mint policy account components.
//!
//! Mint policies are the procedures that gate the minting of tokens. This module exposes the
//! policy procedures as standalone, storage-free [`AccountComponent`]s. They are installed on a
//! faucet alongside a [`crate::account::policy_manager::MintPolicyManager`] which owns the manager
//! procedures and the 3 policy-manager storage slots.
//!
//! Top-level policies (at the standards path `miden::standards::mint_policies::*`) live on the
//! [`MintPolicy`] namespace. Policies under a family (e.g.
//! `miden::standards::mint_policies::owner_controlled::*`) live on a family-specific namespace like
//! [`MintOwnerControlled`].
//!
//! [`AccountComponent`]: miden_protocol::account::AccountComponent

mod owner_controlled;

use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

pub use self::owner_controlled::MintOwnerControlled;
use crate::account::components::allow_all_mint_policy_library;
use crate::procedure_digest;

// ALLOW-ALL MINT POLICY
// ================================================================================================

procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    MintPolicy::NAME,
    MintPolicy::ALLOW_ALL_PROC_NAME,
    allow_all_mint_policy_library
);

/// Namespace for top-level mint policies (those defined directly under the
/// `miden::standards::mint_policies` module on the standards side).
///
/// Currently exposes the storage-free `allow_all` policy. Pair the resulting [`AccountComponent`]
/// with a [`crate::account::policy_manager::MintPolicyManager`] whose allowed-policies map
/// includes [`MintPolicy::allow_all_root`].
#[derive(Debug, Clone, Copy)]
pub struct MintPolicy;

impl MintPolicy {
    /// The name of the `allow_all` mint policy component.
    pub const NAME: &'static str = "miden::standards::components::mint_policies::mod";

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

impl From<MintPolicy> for AccountComponent {
    fn from(_: MintPolicy) -> Self {
        let metadata =
            AccountComponentMetadata::new(MintPolicy::NAME, [AccountType::FungibleFaucet])
                .with_description("`allow_all` mint policy for fungible faucets");

        AccountComponent::new(allow_all_mint_policy_library(), vec![], metadata).expect(
            "`allow_all` mint policy component should satisfy the requirements of a valid account component",
        )
    }
}
