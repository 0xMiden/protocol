use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_protocol::account::AccountProcedureRoot;

use crate::account::access::{Authority, Ownable2Step, RoleBasedAccessControl};
use crate::account::auth::{
    AuthGuardedMultisig,
    AuthMultisig,
    AuthMultisigSmart,
    AuthNetworkAccount,
    AuthPassThrough,
    AuthSingleSig,
    NoAuth,
};
use crate::account::faucets::FungibleFaucet;
use crate::account::inspection::CodeInspection;
use crate::account::interface::AccountComponentInterface;
use crate::account::note_creator::NoteCreator;
use crate::account::pass_through::PassThroughSweep;
use crate::account::wallets::BasicWallet;

// STANDARD ACCOUNT COMPONENTS
// ================================================================================================

/// The enum holding the types of standard account components defined in the `miden-standards`
/// crate.
pub enum StandardAccountComponent {
    BasicWallet,
    NoteCreator,
    FungibleFaucet,
    CodeInspection,
    Authority,
    Ownable2Step,
    RoleBasedAccessControl,
    AuthSingleSig,
    AuthMultisig,
    AuthMultisigSmart,
    AuthGuardedMultisig,
    AuthNoAuth,
    AuthNetworkAccount,
    AuthPassThrough,
    PassThroughSweep,
}

impl StandardAccountComponent {
    /// Returns the iterator over the [`AccountProcedureRoot`]s of all procedures exported from
    /// the component.
    pub fn procedure_roots(&self) -> impl Iterator<Item = AccountProcedureRoot> {
        let code = match self {
            Self::BasicWallet => BasicWallet::code(),
            Self::NoteCreator => NoteCreator::code(),
            Self::FungibleFaucet => FungibleFaucet::code(),
            Self::CodeInspection => CodeInspection::code(),
            Self::Authority => Authority::code(),
            Self::Ownable2Step => Ownable2Step::code(),
            Self::RoleBasedAccessControl => RoleBasedAccessControl::code(),
            Self::AuthSingleSig => AuthSingleSig::code(),
            Self::AuthMultisig => AuthMultisig::code(),
            Self::AuthMultisigSmart => AuthMultisigSmart::code(),
            Self::AuthGuardedMultisig => AuthGuardedMultisig::code(),
            Self::AuthNoAuth => NoAuth::code(),
            Self::AuthNetworkAccount => AuthNetworkAccount::code(),
            Self::AuthPassThrough => AuthPassThrough::code(),
            Self::PassThroughSweep => PassThroughSweep::code(),
        };

        code.procedure_roots()
    }

    /// Checks whether procedures from the current component are present in the procedures map
    /// and if so it removes these procedures from this map and pushes the corresponding component
    /// interface to the component interface vector.
    fn extract_component(
        &self,
        procedures_set: &mut BTreeSet<AccountProcedureRoot>,
        component_interface_vec: &mut Vec<AccountComponentInterface>,
    ) {
        // Determine if this component should be extracted based on procedure matching
        if self.procedure_roots().all(|proc_root| procedures_set.contains(&proc_root)) {
            // Remove the procedure root of any matching procedure.
            self.procedure_roots().for_each(|component_procedure| {
                procedures_set.remove(&component_procedure);
            });

            // Create the appropriate component interface
            match self {
                Self::BasicWallet => {
                    component_interface_vec.push(AccountComponentInterface::BasicWallet)
                },
                Self::NoteCreator => {
                    component_interface_vec.push(AccountComponentInterface::NoteCreator)
                },
                Self::FungibleFaucet => {
                    component_interface_vec.push(AccountComponentInterface::FungibleFaucet)
                },
                Self::CodeInspection => {
                    component_interface_vec.push(AccountComponentInterface::CodeInspection)
                },
                Self::Authority => {
                    component_interface_vec.push(AccountComponentInterface::Authority)
                },
                Self::Ownable2Step => {
                    component_interface_vec.push(AccountComponentInterface::Ownable2Step)
                },
                Self::RoleBasedAccessControl => {
                    component_interface_vec.push(AccountComponentInterface::RoleBasedAccessControl)
                },
                Self::AuthSingleSig => {
                    component_interface_vec.push(AccountComponentInterface::AuthSingleSig)
                },
                Self::AuthMultisig => {
                    component_interface_vec.push(AccountComponentInterface::AuthMultisig)
                },
                Self::AuthMultisigSmart => {
                    component_interface_vec.push(AccountComponentInterface::AuthMultisigSmart)
                },
                Self::AuthGuardedMultisig => {
                    component_interface_vec.push(AccountComponentInterface::AuthGuardedMultisig)
                },
                Self::AuthNoAuth => {
                    component_interface_vec.push(AccountComponentInterface::AuthNoAuth)
                },
                Self::AuthNetworkAccount => {
                    component_interface_vec.push(AccountComponentInterface::AuthNetworkAccount)
                },
                Self::AuthPassThrough => {
                    component_interface_vec.push(AccountComponentInterface::AuthPassThrough)
                },
                Self::PassThroughSweep => {
                    component_interface_vec.push(AccountComponentInterface::PassThroughSweep)
                },
            }
        }
    }

    /// Gets all standard components which could be constructed from the provided procedures map
    /// and pushes them to the `component_interface_vec`.
    pub fn extract_standard_components(
        procedures_set: &mut BTreeSet<AccountProcedureRoot>,
        component_interface_vec: &mut Vec<AccountComponentInterface>,
    ) {
        Self::BasicWallet.extract_component(procedures_set, component_interface_vec);
        // Must run after `BasicWallet`: `NoteCreator`'s only procedure (`create_note`) is a subset
        // of the basic wallet's, so a full wallet must claim it first to avoid misdetection.
        Self::NoteCreator.extract_component(procedures_set, component_interface_vec);
        Self::FungibleFaucet.extract_component(procedures_set, component_interface_vec);
        Self::CodeInspection.extract_component(procedures_set, component_interface_vec);
        Self::Authority.extract_component(procedures_set, component_interface_vec);
        Self::RoleBasedAccessControl.extract_component(procedures_set, component_interface_vec);
        Self::Ownable2Step.extract_component(procedures_set, component_interface_vec);
        Self::AuthSingleSig.extract_component(procedures_set, component_interface_vec);
        Self::AuthGuardedMultisig.extract_component(procedures_set, component_interface_vec);
        Self::AuthMultisig.extract_component(procedures_set, component_interface_vec);
        Self::AuthMultisigSmart.extract_component(procedures_set, component_interface_vec);
        Self::AuthNoAuth.extract_component(procedures_set, component_interface_vec);
        Self::AuthNetworkAccount.extract_component(procedures_set, component_interface_vec);
        Self::AuthPassThrough.extract_component(procedures_set, component_interface_vec);
        Self::PassThroughSweep.extract_component(procedures_set, component_interface_vec);
    }
}
