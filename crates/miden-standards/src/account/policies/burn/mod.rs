//! Burn policy components and the burn policy descriptor used by
//! [`super::TokenPolicyManager`].

use alloc::vec::Vec;

use miden_protocol::account::{AccountComponent, AccountProcedureRoot, StorageSlotName};
use miden_protocol::asset::AssetAmount;
use thiserror::Error;

use crate::account::access::Ownable2Step;

mod allow_all;
mod min_burn_amount;
mod owner_only;

pub use allow_all::BurnAllowAll;
pub use min_burn_amount::MinBurnAmount;
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
/// Binds the procedure root the manager dispatches to (via `dyncall`) with any companion
/// [`AccountComponent`]s that must be installed for the procedure to work, plus any storage
/// slots the procedure reads but does not own (see [`Self::required_slots`]).
///
/// Construct via [`Self::allow_all`], [`Self::owner_only`], [`Self::min_burn_amount`], or
/// [`Self::custom`]. Pass to the [`super::TokenPolicyManager`] builder via `active_burn_policy`
/// or `allowed_burn_policy`.
#[derive(Debug, Clone)]
pub struct BurnPolicy {
    root: AccountProcedureRoot,
    components: Vec<AccountComponent>,
    required_slots: Vec<StorageSlotName>,
}

impl BurnPolicy {
    /// Returns a burn policy that accepts every burn unconditionally.
    pub fn allow_all() -> Self {
        Self {
            root: BurnAllowAll::root(),
            components: vec![BurnAllowAll.into()],
            required_slots: Vec::new(),
        }
    }

    /// Returns a burn policy gated by the account owner.
    ///
    /// The policy reads the owner from the [`Ownable2Step`] storage slot, which the policy does
    /// not own: the account must install [`Ownable2Step`] separately (directly or through
    /// [`AccessControl::Ownable2Step`][crate::account::access::AccessControl::Ownable2Step]).
    /// The dependency is declared through [`Self::required_slots`] so account factories can
    /// reject the incomplete configuration at build time.
    pub fn owner_only() -> Self {
        Self {
            root: BurnOwnerOnly::root(),
            components: vec![BurnOwnerOnly.into()],
            required_slots: vec![Ownable2Step::slot_name().clone()],
        }
    }

    /// Returns a burn policy that rejects burns below `min_burn_amount`.
    ///
    /// The threshold is written to the [`MinBurnAmount`] component's storage slot and can be
    /// updated at runtime through the owner-gated `set_min_burn_amount` procedure.
    pub fn min_burn_amount(min_burn_amount: AssetAmount) -> Self {
        Self {
            root: MinBurnAmount::root(),
            components: vec![MinBurnAmount::new(min_burn_amount).into()],
            required_slots: Vec::new(),
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
        Ok(Self {
            root,
            components,
            required_slots: Vec::new(),
        })
    }

    /// Declares a storage slot the policy procedure reads but does not own, so it must be
    /// provided by another component installed on the same account.
    pub fn with_required_slot(mut self, slot_name: StorageSlotName) -> Self {
        self.required_slots.push(slot_name);
        self
    }

    /// Returns the procedure root of the policy this descriptor resolves to.
    pub fn root(&self) -> AccountProcedureRoot {
        self.root
    }

    /// Returns the storage slots the policy procedure reads but does not own. They must be
    /// provided by another component installed on the same account, otherwise every dispatch to
    /// this policy aborts on the missing slot.
    pub fn required_slots(&self) -> &[StorageSlotName] {
        &self.required_slots
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
