use miden_processor::ExecutionError;
use miden_protocol::errors::BlockOutputError;
use miden_prover::ProverError;

// BLOCK PROVER ERROR
// ================================================================================================

/// Represents errors that can occur during block execution and proving.
#[derive(Debug, thiserror::Error)]
pub enum BlockProverError {
    #[error("block kernel execution failed")]
    BlockKernelExecutionFailed(#[source] ExecutionError),
    #[error("block kernel produced an invalid output stack")]
    BlockKernelOutputInvalid(#[source] BlockOutputError),
    #[error("block proof generation failed")]
    BlockProvingFailed(#[source] ProverError),
}
