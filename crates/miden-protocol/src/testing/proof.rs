use alloc::vec::Vec;

use miden_core::deferred::TRUE_DIGEST;
use miden_core::proof::{HashFunction, StarkProof, VmProof};

use crate::vm::ExecutionProof;

/// Returns a structurally well-formed [`ExecutionProof`] that carries no STARK bytes.
///
/// The proof is in the `Complete` state with no outstanding precompile work, so it round-trips
/// through serialization and can stand in wherever a `ProvenTransaction` or `ProvenBatch` needs a
/// proof that is never verified. Verifying it will fail.
pub fn dummy_execution_proof() -> ExecutionProof {
    ExecutionProof::Complete {
        vm: VmProof {
            proof: StarkProof::new(Vec::new(), HashFunction::Blake3_256),
            precompile_root: TRUE_DIGEST,
        },
        precompile: None,
    }
}
