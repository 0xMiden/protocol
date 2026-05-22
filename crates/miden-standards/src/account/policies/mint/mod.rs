//! Mint policy components and the mint policy descriptor used by
//! [`super::TokenPolicyManager`].

use alloc::vec::Vec;

use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

mod allow_all;
mod owner_only;

pub use allow_all::MintAllowAll;
pub use owner_only::MintOwnerOnly;

// MINT POLICY
// ================================================================================================

/// Descriptor for the mint policy registered with a [`super::TokenPolicyManager`].
///
/// Binds the procedure root the manager dispatches to (via `dynexec`) with any companion
/// [`AccountComponent`]s that must be installed for the procedure to work.
///
/// Construct via [`Self::allow_all`], [`Self::owner_only`], [`Self::custom`], or
/// [`Self::from_components`]. Pass to [`super::TokenPolicyManager::with_mint_policy`].
#[derive(Debug, Clone)]
pub struct MintPolicy {
    root: AccountProcedureRoot,
    components: Vec<AccountComponent>,
}

impl MintPolicy {
    /// Returns a mint policy that accepts every mint unconditionally.
    pub fn allow_all() -> Self {
        Self {
            root: MintAllowAll::root(),
            components: vec![MintAllowAll.into()],
        }
    }

    /// Returns a mint policy gated by the account owner.
    pub fn owner_only() -> Self {
        Self {
            root: MintOwnerOnly::root(),
            components: vec![MintOwnerOnly.into()],
        }
    }

    /// Returns a mint policy resolving to the provided procedure root. The corresponding
    /// component(s) must be installed by the caller separately — this descriptor carries no
    /// companion components.
    pub fn custom(root: AccountProcedureRoot) -> Self {
        Self { root, components: Vec::new() }
    }

    /// Returns a mint policy resolving to the provided procedure root and shipping the provided
    /// companion components.
    pub fn from_components(root: AccountProcedureRoot, components: Vec<AccountComponent>) -> Self {
        Self { root, components }
    }

    /// Returns the procedure root of the policy this descriptor resolves to.
    pub fn root(&self) -> AccountProcedureRoot {
        self.root
    }

    /// Returns the [`AccountComponent`]s that must accompany this mint policy.
    pub(crate) fn into_components(self) -> Vec<AccountComponent> {
        self.components
    }
}

impl Default for MintPolicy {
    fn default() -> Self {
        Self::owner_only()
    }
}
