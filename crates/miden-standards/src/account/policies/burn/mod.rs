//! Burn policy components and the burn policy descriptor used by
//! [`super::TokenPolicyManager`].

use alloc::vec::Vec;

use miden_protocol::account::{AccountComponent, AccountProcedureRoot};
use thiserror::Error;

mod allow_all;
mod owner_only;

pub use allow_all::BurnAllowAll;
pub use owner_only::BurnOwnerOnly;

// BURN POLICY ERROR
// ================================================================================================

/// Errors returned by [`BurnPolicy::custom`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BurnPolicyError {
    /// The procedure root supplied to [`BurnPolicy::custom`] is not exported by any of the
    /// provided components.
    #[error(
        "custom burn policy root must match a procedure root in one of the provided components"
    )]
    RootNotInComponents,
}

// BURN POLICY
// ================================================================================================

/// Descriptor for the burn policy registered with a [`super::TokenPolicyManager`].
///
/// Binds the procedure root the manager dispatches to (via `dynexec`) with any companion
/// [`AccountComponent`]s that must be installed for the procedure to work.
///
/// Construct via [`Self::allow_all`], [`Self::owner_only`], or [`Self::custom`]. Pass to the
/// [`super::TokenPolicyManager`] builder via `active_burn_policy` or `allowed_burn_policy`.
#[derive(Debug, Clone)]
pub struct BurnPolicy {
    root: AccountProcedureRoot,
    components: Vec<AccountComponent>,
}

impl BurnPolicy {
    /// Returns a burn policy that accepts every burn unconditionally.
    pub fn allow_all() -> Self {
        Self {
            root: BurnAllowAll::root(),
            components: vec![BurnAllowAll.into()],
        }
    }

    /// Returns a burn policy gated by the account owner.
    pub fn owner_only() -> Self {
        Self {
            root: BurnOwnerOnly::root(),
            components: vec![BurnOwnerOnly.into()],
        }
    }

    /// Returns a burn policy resolving to `root` and shipping the provided companion
    /// `components` (anything that can be converted into an [`AccountComponent`]).
    ///
    /// # Errors
    ///
    /// Returns [`BurnPolicyError::RootNotInComponents`] if `root` is not the procedure root of
    /// any procedure exported by the provided components.
    pub fn custom<I>(root: AccountProcedureRoot, components: I) -> Result<Self, BurnPolicyError>
    where
        I: IntoIterator,
        I::Item: Into<AccountComponent>,
    {
        let components: Vec<AccountComponent> = components.into_iter().map(Into::into).collect();
        if !components.iter().any(|component| component.has_procedure(root)) {
            return Err(BurnPolicyError::RootNotInComponents);
        }
        Ok(Self { root, components })
    }

    /// Returns the procedure root of the policy this descriptor resolves to.
    pub fn root(&self) -> AccountProcedureRoot {
        self.root
    }
}

impl Default for BurnPolicy {
    fn default() -> Self {
        Self::allow_all()
    }
}

impl IntoIterator for BurnPolicy {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s carried by this burn policy descriptor in installation
    /// order.
    fn into_iter(self) -> Self::IntoIter {
        self.components.into_iter()
    }
}
