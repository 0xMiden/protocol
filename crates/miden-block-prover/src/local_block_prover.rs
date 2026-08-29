use miden_processor::ExecutionError;
use miden_protocol::vm::ExecutionProof;
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
#[derive(Clone, Default)]
pub struct LocalBlockProver {
    prover: Prover,
}

impl LocalBlockProver {
    /// Creates a new [`LocalBlockProver`] instance.
    pub fn new(_proof_security_level: u32) -> Self {
        // TODO: This will eventually take the security level as a parameter, but until we verify
        // blocks it is ignored.
        Self::default()
    }

    /// Proves the [`ExecutedBlock`] into an [`ExecutionProof`].
    ///
    /// Builds the execution trace from the executed block and generates the proof.
    ///
    /// # Errors
    ///
    /// Returns an error if proof generation fails.
    pub fn prove(&self, executed_block: ExecutedBlock) -> Result<ExecutionProof, BlockProverError> {
        self.prover
            .prove_full(executed_block.into_witness())
            .map_err(|error| ExecutionError::ProvingError(error.to_string()))
            .map_err(BlockProverError::BlockKernelExecutionFailed)
    }

    /// Returns a dummy [`ExecutionProof`], without running the block kernel.
    #[cfg(feature = "testing")]
    pub fn prove_dummy(&self) -> ExecutionProof {
        miden_protocol::testing::dummy_execution_proof()
    }
}
