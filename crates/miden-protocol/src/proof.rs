use miden_verifier::{
    ExecutionClaim,
    ExecutionProof,
    VerificationError,
    VerificationOutcome,
    Verifier,
};

use crate::PROTOCOL_PROOF_HASH;
use crate::errors::ProofVerificationError;

/// Verifies an execution proof against a claim built by the caller.
///
/// The VM proof must use [`PROTOCOL_PROOF_HASH`] for its transcript, and each verified STARK must
/// have at least `min_security_level` bits of conjectured security. The returned outcome can still
/// carry an outstanding precompile obligation; each caller applies its own precompile rules.
pub fn verify_execution_proof(
    claim: &ExecutionClaim,
    proof: &ExecutionProof,
    min_security_level: u32,
) -> Result<VerificationOutcome, ProofVerificationError> {
    let vm_hash = proof.vm().proof.hash_fn();
    if vm_hash != PROTOCOL_PROOF_HASH {
        return Err(ProofVerificationError::UnsupportedVmProofHash {
            actual: vm_hash,
            expected: PROTOCOL_PROOF_HASH,
        });
    }

    Verifier::new()
        .with_min_conjectured_security_level_per_stark(min_security_level)
        .verify(claim, proof)
        .map_err(|error| match error {
            VerificationError::InsufficientSecurityLevel { actual, required } => {
                ProofVerificationError::InsufficientSecurityLevel { actual, required }
            },
            error => ProofVerificationError::VerificationFailed(error),
        })
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use miden_verifier::{HashFunction, KernelDescriptor, StarkProof};

    use super::*;
    use crate::Word;
    use crate::testing::dummy_execution_proof;
    use crate::vm::{StackInputs, StackOutputs};

    #[test]
    fn requires_the_protocol_transcript_hash() {
        let (compatibility, mut vm, precompile) = dummy_execution_proof().into_parts();
        vm.proof = StarkProof::new(Vec::new(), HashFunction::Blake3_256);
        let proof = ExecutionProof::from_parts(compatibility, vm, precompile);
        let claim = ExecutionClaim::new(
            Word::empty(),
            KernelDescriptor::default(),
            StackInputs::default(),
            StackOutputs::default(),
        );
        assert_matches!(
            verify_execution_proof(&claim, &proof, 0),
            Err(ProofVerificationError::UnsupportedVmProofHash {
                actual: HashFunction::Blake3_256,
                expected: PROTOCOL_PROOF_HASH,
            })
        );
    }
}
