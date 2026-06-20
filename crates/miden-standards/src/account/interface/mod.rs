use alloc::vec::Vec;

use miden_protocol::account::AccountId;

#[cfg(test)]
mod test;

mod component;
pub use component::AccountComponentInterface;

mod extension;
pub use extension::{AccountComponentInterfaceExt, AccountInterfaceExt};

// ACCOUNT INTERFACE
// ================================================================================================

/// An [`AccountInterface`] describes the exported, callable procedures of an account.
pub struct AccountInterface {
    account_id: AccountId,
    components: Vec<AccountComponentInterface>,
}

// ------------------------------------------------------------------------------------------------
/// Constructors and public accessors
impl AccountInterface {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AccountInterface`] instance from the provided account ID and account
    /// component interfaces.
    ///
    /// # Panics
    ///
    /// Panics if `components` does not contain exactly one auth component. Every account installs
    /// a single auth component. Zero or multiple auth components is a malformed account.
    pub fn new(account_id: AccountId, components: Vec<AccountComponentInterface>) -> Self {
        let auth_count = components.iter().filter(|c| c.is_auth_component()).count();
        assert_eq!(
            auth_count, 1,
            "account interface must contain exactly one auth component, found {auth_count}"
        );
        Self { account_id, components }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the account ID.
    pub fn id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns `true` if the reference account is a private account, `false` otherwise.
    pub fn is_private(&self) -> bool {
        self.account_id.is_private()
    }

    /// Returns true if the reference account is a public account, `false` otherwise.
    pub fn is_public(&self) -> bool {
        self.account_id.is_public()
    }

    /// Returns a reference to the set of used component interfaces.
    pub fn components(&self) -> &Vec<AccountComponentInterface> {
        &self.components
    }

    /// Returns a reference to the single auth component installed on this account.
    ///
    /// Every account installs exactly one auth component (validated in [`Self::new`]).
    pub fn auth_component(&self) -> &AccountComponentInterface {
        self.components
            .iter()
            .find(|c| c.is_auth_component())
            .expect("AccountInterface invariant: exactly one auth component present")
    }
}
