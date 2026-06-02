//! Mint policy components and the mint policy descriptor used by
//! [`super::TokenPolicyManager`].

use alloc::vec::Vec;

use miden_protocol::account::{AccountComponent, AccountProcedureRoot};
use thiserror::Error;

mod allow_all;
mod owner_only;

pub use allow_all::MintAllowAll;
pub use owner_only::MintOwnerOnly;

// MINT POLICY ERROR
// ================================================================================================

/// Errors returned by [`MintPolicy::custom`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MintPolicyError {
    /// The procedure root supplied to [`MintPolicy::custom`] is not exported by any of the
    /// provided components.
    #[error(
        "custom mint policy root must match a procedure root in one of the provided components"
    )]
    RootNotInComponents,
}

// MINT POLICY
// ================================================================================================

/// Descriptor for the mint policy registered with a [`super::TokenPolicyManager`].
///
/// Binds the procedure root the manager dispatches to (via `dynexec`) with any companion
/// [`AccountComponent`]s that must be installed for the procedure to work.
///
/// Construct via [`Self::allow_all`], [`Self::owner_only`], or [`Self::custom`]. Pass to the
/// [`super::TokenPolicyManager`] builder via `active_mint_policy` or `allowed_mint_policy`.
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

    /// Returns a mint policy resolving to `root` and shipping the provided companion
    /// `components` (anything that can be converted into an [`AccountComponent`]).
    ///
    /// # Errors
    ///
    /// Returns [`MintPolicyError::RootNotInComponents`] if `root` is not the procedure root of
    /// any procedure exported by the provided components.
    pub fn custom<I>(root: AccountProcedureRoot, components: I) -> Result<Self, MintPolicyError>
    where
        I: IntoIterator,
        I::Item: Into<AccountComponent>,
    {
        let components: Vec<AccountComponent> = components.into_iter().map(Into::into).collect();
        let root_present = components
            .iter()
            .any(|component| component.procedures().any(|(proc_root, _)| proc_root == root));
        if !root_present {
            return Err(MintPolicyError::RootNotInComponents);
        }
        Ok(Self { root, components })
    }

    /// Returns the procedure root of the policy this descriptor resolves to.
    pub fn root(&self) -> AccountProcedureRoot {
        self.root
    }
}

impl Default for MintPolicy {
    fn default() -> Self {
        Self::owner_only()
    }
}

impl IntoIterator for MintPolicy {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s carried by this mint policy descriptor in installation
    /// order.
    fn into_iter(self) -> Self::IntoIter {
        self.components.into_iter()
    }
}
