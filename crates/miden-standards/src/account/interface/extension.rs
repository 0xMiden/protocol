use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::MastNodeExt;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountCode, AccountId, AccountProcedureRoot};
use miden_protocol::assembly::mast::{MastForest, MastNode, MastNodeId};
use miden_protocol::note::{Note, NoteScript};

use crate::AuthScheme;
use crate::account::components::{
    StandardAccountComponent,
    basic_fungible_faucet_library,
    basic_wallet_library,
    ecdsa_k256_keccak_acl_library,
    ecdsa_k256_keccak_library,
    ecdsa_k256_keccak_multisig_library,
    falcon_512_rpo_acl_library,
    falcon_512_rpo_library,
    falcon_512_rpo_multisig_library,
    network_fungible_faucet_library,
    no_auth_library,
};
use crate::account::interface::{
    AccountComponentInterface,
    AccountInterface,
    NoteAccountCompatibility,
};
use crate::note::StandardNote;

// ACCOUNT INTERFACE EXTENSION TRAIT
// ================================================================================================

/// An extension for [`AccountInterface`] that allows instantiation from higher-level types.
pub trait AccountInterfaceExt {
    /// Creates a new [`AccountInterface`] instance from the provided account ID, authentication
    /// schemes and account code.
    fn from_code(account_id: AccountId, auth: Vec<AuthScheme>, code: &AccountCode) -> Self;

    /// Creates a new [`AccountInterface`] instance from the provided [`Account`].
    fn from_account(account: &Account) -> Self;

    /// Returns [NoteAccountCompatibility::Maybe] if the provided note is compatible with the
    /// current [AccountInterface], and [NoteAccountCompatibility::No] otherwise.
    fn is_compatible_with(&self, note: &Note) -> NoteAccountCompatibility;

    /// Returns the set of digests of all procedures from all account component interfaces.
    fn get_procedure_digests(&self) -> BTreeSet<Word>;
}

impl AccountInterfaceExt for AccountInterface {
    fn from_code(account_id: AccountId, auth: Vec<AuthScheme>, code: &AccountCode) -> Self {
        let components = AccountComponentInterface::from_procedures(code.procedures());

        Self::new(account_id, auth, components)
    }

    fn from_account(account: &Account) -> Self {
        let components = AccountComponentInterface::from_procedures(account.code().procedures());
        let mut auth = Vec::new();

        // Find the auth component and extract all auth schemes from it
        // An account should have only one auth component
        for component in components.iter() {
            if component.is_auth_component() {
                auth = component.get_auth_schemes(account.storage());
                break;
            }
        }

        Self::new(account.id(), auth, components)
    }

    /// Returns [NoteAccountCompatibility::Maybe] if the provided note is compatible with the
    /// current [AccountInterface], and [NoteAccountCompatibility::No] otherwise.
    fn is_compatible_with(&self, note: &Note) -> NoteAccountCompatibility {
        if let Some(standard_note) = StandardNote::from_note(note) {
            if standard_note.is_compatible_with(self) {
                NoteAccountCompatibility::Maybe
            } else {
                NoteAccountCompatibility::No
            }
        } else {
            verify_note_script_compatibility(note.script(), self.get_procedure_digests())
        }
    }

    fn get_procedure_digests(&self) -> BTreeSet<Word> {
        let mut component_proc_digests = BTreeSet::new();
        for component in self.components.iter() {
            match component {
                AccountComponentInterface::BasicWallet => {
                    component_proc_digests
                        .extend(basic_wallet_library().mast_forest().procedure_digests());
                },
                AccountComponentInterface::BasicFungibleFaucet => {
                    component_proc_digests
                        .extend(basic_fungible_faucet_library().mast_forest().procedure_digests());
                },
                AccountComponentInterface::NetworkFungibleFaucet => {
                    component_proc_digests.extend(
                        network_fungible_faucet_library().mast_forest().procedure_digests(),
                    );
                },
                AccountComponentInterface::AuthEcdsaK256Keccak => {
                    component_proc_digests
                        .extend(ecdsa_k256_keccak_library().mast_forest().procedure_digests());
                },
                AccountComponentInterface::AuthEcdsaK256KeccakAcl => {
                    component_proc_digests
                        .extend(ecdsa_k256_keccak_acl_library().mast_forest().procedure_digests());
                },
                AccountComponentInterface::AuthEcdsaK256KeccakMultisig => {
                    component_proc_digests.extend(
                        ecdsa_k256_keccak_multisig_library().mast_forest().procedure_digests(),
                    );
                },
                AccountComponentInterface::AuthFalcon512Rpo => {
                    component_proc_digests
                        .extend(falcon_512_rpo_library().mast_forest().procedure_digests());
                },
                AccountComponentInterface::AuthFalcon512RpoAcl => {
                    component_proc_digests
                        .extend(falcon_512_rpo_acl_library().mast_forest().procedure_digests());
                },
                AccountComponentInterface::AuthFalcon512RpoMultisig => {
                    component_proc_digests.extend(
                        falcon_512_rpo_multisig_library().mast_forest().procedure_digests(),
                    );
                },
                AccountComponentInterface::AuthNoAuth => {
                    component_proc_digests
                        .extend(no_auth_library().mast_forest().procedure_digests());
                },
                AccountComponentInterface::Custom(custom_procs) => {
                    component_proc_digests
                        .extend(custom_procs.iter().map(|info| *info.mast_root()));
                },
            }
        }

        component_proc_digests
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

// HELPER FUNCTIONS
// ------------------------------------------------------------------------------------------------

/// Verifies that the provided note script is compatible with the target account interfaces.
///
/// This is achieved by checking that at least one execution branch in the note script is compatible
/// with the account procedures vector.
///
/// This check relies on the fact that account procedures are the only procedures that are `call`ed
/// from note scripts, while kernel procedures are `sycall`ed.
fn verify_note_script_compatibility(
    note_script: &NoteScript,
    account_procedures: BTreeSet<Word>,
) -> NoteAccountCompatibility {
    // collect call branches of the note script
    let branches = collect_call_branches(note_script);

    // if none of the branches are compatible with the target account, return a `CheckResult::No`
    if !branches.iter().any(|call_targets| call_targets.is_subset(&account_procedures)) {
        return NoteAccountCompatibility::No;
    }

    NoteAccountCompatibility::Maybe
}

/// Collect call branches by recursively traversing through program execution branches and
/// accumulating call targets.
fn collect_call_branches(note_script: &NoteScript) -> Vec<BTreeSet<Word>> {
    let mut branches = vec![BTreeSet::new()];

    let entry_node = note_script.entrypoint();
    recursively_collect_call_branches(entry_node, &mut branches, &note_script.mast());
    branches
}

/// Generates a list of calls invoked in each execution branch of the provided code block.
fn recursively_collect_call_branches(
    mast_node_id: MastNodeId,
    branches: &mut Vec<BTreeSet<Word>>,
    note_script_forest: &Arc<MastForest>,
) {
    let mast_node = &note_script_forest[mast_node_id];

    match mast_node {
        MastNode::Block(_) => {},
        MastNode::Join(join_node) => {
            recursively_collect_call_branches(join_node.first(), branches, note_script_forest);
            recursively_collect_call_branches(join_node.second(), branches, note_script_forest);
        },
        MastNode::Split(split_node) => {
            let current_branch = branches.last().expect("at least one execution branch").clone();
            recursively_collect_call_branches(split_node.on_false(), branches, note_script_forest);

            // If the previous branch had additional calls we need to create a new branch
            if branches.last().expect("at least one execution branch").len() > current_branch.len()
            {
                branches.push(current_branch);
            }

            recursively_collect_call_branches(split_node.on_true(), branches, note_script_forest);
        },
        MastNode::Loop(loop_node) => {
            recursively_collect_call_branches(loop_node.body(), branches, note_script_forest);
        },
        MastNode::Call(call_node) => {
            if call_node.is_syscall() {
                return;
            }

            let callee_digest = note_script_forest[call_node.callee()].digest();

            branches
                .last_mut()
                .expect("at least one execution branch")
                .insert(callee_digest);
        },
        MastNode::Dyn(_) => {},
        MastNode::External(_) => {},
    }
}
