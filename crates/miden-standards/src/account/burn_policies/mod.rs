//! Burn policy account components.
//!
//! Burn policies are the procedures that gate the burning of tokens. This module exposes the
//! policy procedures as standalone, storage-free [`AccountComponent`]s. They are installed on a
//! faucet alongside a [`crate::account::policy_manager::BurnPolicyManager`] which owns the manager
//! procedures and the 3 policy-manager storage slots.
//!
//! Top-level policies (at the standards path `miden::standards::burn_policies::*`) live on the
//! [`BurnPolicy`] namespace. Policies under a family (e.g.
//! `miden::standards::burn_policies::owner_controlled::*`) live on a family-specific namespace
//! like [`BurnOwnerControlled`].
//!
//! [`AccountComponent`]: miden_protocol::account::AccountComponent

mod owner_controlled;

use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

pub use self::owner_controlled::BurnOwnerControlled;
use crate::account::components::allow_all_burn_policy_library;
use crate::procedure_digest;

// ALLOW-ALL BURN POLICY
// ================================================================================================

procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    BurnPolicy::NAME,
    BurnPolicy::ALLOW_ALL_PROC_NAME,
    allow_all_burn_policy_library
);

/// Namespace for top-level burn policies (those defined directly under the
/// `miden::standards::burn_policies` module on the standards side).
///
/// Currently exposes the storage-free `allow_all` policy. Pair the resulting [`AccountComponent`]
/// with a [`crate::account::policy_manager::BurnPolicyManager`] whose allowed-policies map
/// includes [`BurnPolicy::allow_all_root`].
#[derive(Debug, Clone, Copy)]
pub struct BurnPolicy;

impl BurnPolicy {
    /// The name of the `allow_all` burn policy component.
    pub const NAME: &'static str = "miden::standards::components::burn_policies::mod";

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

impl From<BurnPolicy> for AccountComponent {
    fn from(_: BurnPolicy) -> Self {
        let metadata =
            AccountComponentMetadata::new(BurnPolicy::NAME, [AccountType::FungibleFaucet])
                .with_description("`allow_all` burn policy for fungible faucets");

        AccountComponent::new(allow_all_burn_policy_library(), vec![], metadata).expect(
            "`allow_all` burn policy component should satisfy the requirements of a valid account component",
        )
    }
}
