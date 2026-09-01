use miden_processor::ExecutionError;
use miden_protocol::vm::ExecutionProof;
use miden_prover::HashFunction::Poseidon2;
use miden_prover::Prover;

use crate::{BlockProverError, ExecutedBlock};

// LOCAL BLOCK PROVER
// ================================================================================================

/// A local prover for blocks in the chain.
///
/// Proves an [`ExecutedBlock`] produced by [`BlockExecutor`](crate::BlockExecutor) into an
/// [`ExecutionProof`] over the block's public commitments.
///
/// # Warning
///
/// The current block kernel is a skeleton that drops its inputs and emits an all-zero output
/// region, so the produced proof attests only that the kernel program ran over the block's
/// `[PREV_BLOCK_COMMITMENT, BATCHES_COMMITMENT]` public inputs. It does **not** yet bind the
/// block's account updates, notes or nullifiers, so a block whose contents were mutated would
/// still carry a valid proof. This must therefore not be relied on at a trust boundary until the
/// kernel verification logic that emits and binds the real commitments lands.
#[derive(Clone)]
pub struct LocalBlockProver {
    prover: Prover,
}

impl Default for LocalBlockProver {
    fn default() -> Self {
        Self {
            prover: Prover::new().with_hash_fn(Poseidon2),
        }
    }
}

impl LocalBlockProver {
    /// Creates a new [`LocalBlockProver`] instance.
    pub fn new(prover: Prover) -> Self {
        Self { prover }
    }

    /// Proves the [`ExecutedBlock`] into an [`ExecutionProof`].
    ///
    /// Builds the execution trace from the executed block and generates the proof.
    ///
    /// # Errors
    ///
    /// Returns an error if proof generation fails or the block execution used a precompile.
    pub fn prove(&self, executed_block: ExecutedBlock) -> Result<ExecutionProof, BlockProverError> {
        let proof = self
            .prover
            .prove(executed_block.into_witness())
            .map_err(|error| ExecutionError::ProvingError(error.to_string()))
            .map_err(BlockProverError::BlockKernelProvingFailed)?;

        if proof_has_precompiles(&proof) {
            return Err(BlockProverError::BlockKernelUsedPrecompiles);
        }

        Ok(proof)
    }

    /// Returns a dummy [`ExecutionProof`], without running the block kernel.
    #[cfg(feature = "testing")]
    pub fn prove_dummy(&self) -> ExecutionProof {
        miden_protocol::testing::dummy_execution_proof()
    }
}

fn proof_has_precompiles(proof: &ExecutionProof) -> bool {
    matches!(
        proof,
        ExecutionProof::Deferred { .. } | ExecutionProof::Complete { precompile: Some(_), .. }
    )
}

#[cfg(test)]
mod tests {
    use super::proof_has_precompiles;

    #[test]
    fn detects_precompile_work_in_any_proof_state() {
        assert!(!proof_has_precompiles(&miden_protocol::testing::dummy_execution_proof()));
        assert!(proof_has_precompiles(&miden_protocol::testing::dummy_deferred_execution_proof()));
        assert!(proof_has_precompiles(
            &miden_protocol::testing::dummy_precompile_execution_proof()
        ));
    }
}
