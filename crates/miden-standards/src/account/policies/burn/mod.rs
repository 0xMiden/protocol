//! Burn policy components and the burn policy descriptor used by
//! [`super::TokenPolicyManager`].

use alloc::vec::Vec;

use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

mod allow_all;
mod owner_only;

pub use allow_all::BurnAllowAll;
pub use owner_only::BurnOwnerOnly;

// BURN POLICY
// ================================================================================================

/// Descriptor for the burn policy registered with a [`super::TokenPolicyManager`].
///
/// Binds the procedure root the manager dispatches to (via `dynexec`) with any companion
/// [`AccountComponent`]s that must be installed for the procedure to work.
///
/// Construct via [`Self::allow_all`], [`Self::owner_only`], or [`Self::custom`]. Pass to
/// [`super::TokenPolicyManager::with_burn_policy`].
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
    /// # Panics
    ///
    /// Panics if `root` is not the procedure root of any procedure exported by the provided
    /// components.
    pub fn custom<I>(root: AccountProcedureRoot, components: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<AccountComponent>,
    {
        let components: Vec<AccountComponent> = components.into_iter().map(Into::into).collect();
        assert!(
            components
                .iter()
                .any(|component| component.procedures().any(|(proc_root, _)| proc_root == root)),
            "custom burn policy root must match a procedure root in one of the provided components",
        );
        Self { root, components }
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
