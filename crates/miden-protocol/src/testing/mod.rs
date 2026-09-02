pub mod account;
pub mod account_code;
pub mod account_id;
pub mod add_component;
pub mod assembler;
pub mod asset;
pub mod block;
pub mod block_note_tree;
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
pub mod tx;
pub mod update_details;
pub mod validator_config;
pub mod vault_delta;
pub mod vault_patch;

/// Returns a structurally complete placeholder execution proof for tests that do not verify it.
pub fn dummy_execution_proof() -> crate::vm::ExecutionProof {
    use alloc::vec::Vec;

    use miden_core::deferred::TRUE_DIGEST;
    use miden_verifier::{HashFunction, StarkProof, VmProof};

    crate::vm::ExecutionProof::Complete {
        vm: VmProof {
            proof: StarkProof::new(Vec::new(), HashFunction::Blake3_256),
            precompile_root: TRUE_DIGEST,
        },
        precompile: None,
    }
}

/// Returns a structurally incomplete placeholder execution proof for verifier tests.
pub fn dummy_deferred_execution_proof() -> crate::vm::ExecutionProof {
    use alloc::vec::Vec;

    use miden_core::deferred::{DeferredStateWire, TRUE_DIGEST};
    use miden_verifier::{HashFunction, StarkProof, VmProof};

    crate::vm::ExecutionProof::Deferred {
        vm: VmProof {
            proof: StarkProof::new(Vec::new(), HashFunction::Blake3_256),
            precompile_root: TRUE_DIGEST,
        },
        precompile: DeferredStateWire::default(),
    }
}

/// Returns a structurally complete placeholder proof containing precompile work.
pub fn dummy_precompile_execution_proof() -> crate::vm::ExecutionProof {
    use alloc::vec::Vec;

    use miden_verifier::{HashFunction, PrecompileProof, StarkProof};

    let crate::vm::ExecutionProof::Complete { vm, .. } = dummy_execution_proof() else {
        unreachable!("dummy execution proof must be complete");
    };

    crate::vm::ExecutionProof::Complete {
        vm,
        precompile: Some(PrecompileProof {
            proof: StarkProof::new(Vec::new(), HashFunction::Blake3_256),
            roots: Vec::new(),
        }),
    }
}
