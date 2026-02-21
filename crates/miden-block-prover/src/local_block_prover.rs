use miden_protocol::batch::OrderedBatches;
use miden_protocol::block::{BlockHeader, BlockInputs, BlockProof};

use crate::BlockProverError;

// LOCAL BLOCK PROVER
// ================================================================================================

/// A local prover for blocks in the chain.
#[derive(Clone)]
pub struct LocalBlockProver {}

impl LocalBlockProver {
    /// Creates a new [`LocalBlockProver`] instance.
    pub fn new(_proof_security_level: u32) -> Self {
        // TODO: This will eventually take the security level as a parameter, but until we verify
        // batches it is ignored.
        Self {}
    }

    /// Generates a proof of a block in the chain based on the given header and inputs.
    ///
    /// NOTE: Block proving is not yet implemented. This is a placeholder struct.
    pub fn prove(
        &self,
        _tx_batches: OrderedBatches,
        _block_header: &BlockHeader,
        _block_inputs: BlockInputs,
    ) -> Result<BlockProof, BlockProverError> {
        Ok(BlockProof {})
    }

    /// A mock implementation of the execution of a proof of a block in the chain based on the given
    /// header and inputs.
    ///
    /// This is exposed for testing purposes.
    #[cfg(any(feature = "testing", test))]
    pub fn prove_dummy(
        &self,
        _tx_batches: OrderedBatches,
        _block_header: BlockHeader,
        _block_inputs: BlockInputs,
    ) -> Result<BlockProof, BlockProverError> {
        Ok(BlockProof {})
    }
}
