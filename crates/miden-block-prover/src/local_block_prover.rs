use miden_protocol::vm::ExecutionProof;
use miden_prover::{ProvingOptions, TraceProvingInputs, prove_from_trace_sync};

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
    proving_options: ProvingOptions,
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
        let trace_inputs = executed_block.into_trace_inputs();

        let (_stack_outputs, proof) = prove_from_trace_sync(TraceProvingInputs::new(
            trace_inputs,
            self.proving_options.clone(),
        ))
        .map_err(BlockProverError::BlockKernelExecutionFailed)?;

        Ok(proof)
    }

    /// Returns a dummy [`ExecutionProof`], without running the block kernel.
    ///
    /// This is exposed for testing purposes. It is gated on the `testing` feature alone rather
    /// than also on `cfg(test)`, because [`ExecutionProof::new_dummy`] requires `miden-core`'s own
    /// `testing` feature, which only this crate's `testing` feature turns on.
    #[cfg(feature = "testing")]
    pub fn prove_dummy(&self) -> ExecutionProof {
        ExecutionProof::new_dummy()
    }
}
