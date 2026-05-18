use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_protocol::account::{Account, AccountCode, AccountId, AccountProcedureRoot};

use crate::AuthMethod;
use crate::account::components::StandardAccountComponent;
use crate::account::interface::{AccountComponentInterface, AccountInterface};

// ACCOUNT INTERFACE EXTENSION TRAIT
// ================================================================================================

/// An extension for [`AccountInterface`] that allows instantiation from higher-level types.
pub trait AccountInterfaceExt {
    /// Creates a new [`AccountInterface`] instance from the provided account ID, authentication
    /// methods and account code.
    fn from_code(account_id: AccountId, auth: Vec<AuthMethod>, code: &AccountCode) -> Self;

    /// Creates a new [`AccountInterface`] instance from the provided [`Account`].
    fn from_account(account: &Account) -> Self;
}

impl AccountInterfaceExt for AccountInterface {
    fn from_code(account_id: AccountId, auth: Vec<AuthMethod>, code: &AccountCode) -> Self {
        let components = AccountComponentInterface::from_procedures(code.procedures());

        Self::new(account_id, auth, components)
    }

    fn from_account(account: &Account) -> Self {
        let components = AccountComponentInterface::from_procedures(account.code().procedures());
        let mut auth = Vec::new();

        // Find the auth component and extract all auth methods from it
        // An account should have only one auth component
        for component in components.iter() {
            if component.is_auth_component() {
                auth = component.get_auth_methods(account.storage());
                break;
            }
        }

        Self::new(account.id(), auth, components)
    }
}

/// An extension for [`AccountComponentInterface`] that allows instantiation from a set of procedure
/// roots.
pub trait AccountComponentInterfaceExt {
    /// Creates a vector of [`AccountComponentInterface`] instances from the provided set of
    /// procedures.
    fn from_procedures(procedures: &[AccountProcedureRoot]) -> Vec<AccountComponentInterface>;
}

impl AccountComponentInterfaceExt for AccountComponentInterface {
    fn from_procedures(procedures: &[AccountProcedureRoot]) -> Vec<Self> {
        let mut component_interface_vec = Vec::new();

        let mut procedures = BTreeSet::from_iter(procedures.iter().copied());

        // Standard component interfaces
        // ----------------------------------------------------------------------------------------

        // Get all available standard components which could be constructed from the
        // `procedures` map and push them to the `component_interface_vec`
        StandardAccountComponent::extract_standard_components(
            &mut procedures,
            &mut component_interface_vec,
        );

        // Custom component interfaces
        // ----------------------------------------------------------------------------------------

        // All remaining procedures are put into the custom bucket.
        component_interface_vec
            .push(AccountComponentInterface::Custom(procedures.into_iter().collect()));

        component_interface_vec
    }
}
