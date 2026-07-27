//! Fee policy components and the fee policy descriptor used by [`super::FeePolicyManager`].

use alloc::vec::Vec;

use miden_protocol::account::{AccountComponent, AccountProcedureRoot};
use thiserror::Error;

mod basic_constant_fee;

pub use basic_constant_fee::BasicConstantFeePolicy;

// FEE POLICY ERROR
// ================================================================================================

/// Errors returned by [`FeePolicy::custom`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FeePolicyError {
    /// The procedure root supplied to [`FeePolicy::custom`] is not exported by any of the
    /// provided components.
    #[error("custom fee policy root must match a procedure root in one of the provided components")]
    RootNotInComponents,
}

// FEE POLICY
// ================================================================================================

/// Descriptor for a fee policy registered with a [`super::FeePolicyManager`].
///
/// Binds the procedure root the manager dispatches to (via `dyncall`) with any companion
/// [`AccountComponent`]s that must be installed for the procedure to work.
///
/// Construct from a concrete policy (e.g. via `From<BasicConstantFeePolicy>`) or via
/// [`Self::custom`]. Pass to the [`super::FeePolicyManager`] builder via `active_fee_policy` or
/// `allowed_fee_policy`.
#[derive(Debug, Clone)]
pub struct FeePolicy {
    root: AccountProcedureRoot,
    components: Vec<AccountComponent>,
}

impl FeePolicy {
    /// Returns a fee policy resolving to `root` and shipping the provided companion
    /// `components` (anything that can be converted into an [`AccountComponent`]).
    ///
    /// # Errors
    ///
    /// Returns [`FeePolicyError::RootNotInComponents`] if `root` is not the procedure root of
    /// any procedure exported by the provided components.
    pub fn custom<I>(root: AccountProcedureRoot, components: I) -> Result<Self, FeePolicyError>
    where
        I: IntoIterator,
        I::Item: Into<AccountComponent>,
    {
        let components: Vec<AccountComponent> = components.into_iter().map(Into::into).collect();
        if !components.iter().any(|component| component.has_procedure(root)) {
            return Err(FeePolicyError::RootNotInComponents);
        }
        Ok(Self { root, components })
    }

    /// Returns the procedure root of the policy this descriptor resolves to.
    pub fn root(&self) -> AccountProcedureRoot {
        self.root
    }
}

impl From<BasicConstantFeePolicy> for FeePolicy {
    /// Returns a fee policy charging the constant fee scheduled for the note's script root.
    fn from(policy: BasicConstantFeePolicy) -> Self {
        Self {
            root: BasicConstantFeePolicy::root(),
            components: vec![policy.into()],
        }
    }
}

impl IntoIterator for FeePolicy {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s carried by this fee policy descriptor in installation
    /// order.
    fn into_iter(self) -> Self::IntoIter {
        self.components.into_iter()
    }
}
