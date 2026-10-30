use alloc::vec::Vec;

use miden_core::deferred::{
    DEFERRED_AND_FRAME,
    PrecompileWitness,
    PrecompileWitnessEntry,
    TRUE_DIGEST,
    fold_deferred_root,
};
use miden_verifier::{ExecutionProof, PrecompileProof, PrecompileStatus, StarkProof, VmProof};

use crate::PROTOCOL_PROOF_HASH;

pub mod account;
pub mod account_code;
pub mod account_id;
pub mod add_component;
pub mod assembler;
pub mod asset;
pub mod block;
pub mod block_note_tree;
pub mod code;
pub mod component_metadata;
pub mod constants;
pub mod kernel_config;
pub mod noop_auth_component;
pub mod note;
pub mod note_script_root;
pub mod partial_blockchain;
pub mod protocol_config;
pub mod random_secret_key;
pub mod slot_name;
pub mod storage;
pub mod storage_map_key;
pub mod transaction_header;
pub mod transaction_logs;
pub mod tx;
pub mod update_details;
pub mod validator_config;
pub mod vault_delta;
pub mod vault_patch;

/// Creates an empty, completed execution proof for tests that do not verify its STARK payload.
///
/// The proof cannot pass verification. It has no outstanding deferred work, which is the lifecycle
/// state required by protocol objects that use it as inert test data.
pub fn dummy_execution_proof() -> ExecutionProof {
    ExecutionProof::new(
        VmProof {
            proof: StarkProof::new(Vec::new(), PROTOCOL_PROOF_HASH),
            precompile_root: TRUE_DIGEST,
        },
        PrecompileStatus::Empty,
    )
}

/// Creates a structurally incomplete placeholder execution proof for verifier tests.
pub fn dummy_deferred_execution_proof() -> ExecutionProof {
    let witness = PrecompileWitness::from_entries(vec![PrecompileWitnessEntry::Join {
        frame: DEFERRED_AND_FRAME,
        lhs: 0,
        rhs: 0,
    }])
    .expect("a join of two implicit TRUE nodes is structurally valid");

    ExecutionProof::new(
        VmProof {
            proof: StarkProof::new(Vec::new(), PROTOCOL_PROOF_HASH),
            precompile_root: fold_deferred_root(TRUE_DIGEST, TRUE_DIGEST),
        },
        PrecompileStatus::Deferred(witness),
    )
}

/// Creates a completed execution proof with an empty precompile proof for tests.
///
/// The proof cannot pass verification. It exists for testing proof lifecycle and policy checks.
pub fn dummy_precompile_execution_proof() -> ExecutionProof {
    let (_, vm, _) = dummy_execution_proof().into_parts();
    ExecutionProof::new(
        vm,
        PrecompileStatus::Proven(PrecompileProof {
            proof: StarkProof::new(Vec::new(), PROTOCOL_PROOF_HASH),
            roots: Vec::new(),
        }),
    )
}
