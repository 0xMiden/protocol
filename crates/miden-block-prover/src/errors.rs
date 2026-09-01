use miden_processor::ExecutionError;
use miden_protocol::errors::BlockOutputError;

// BLOCK PROVER ERROR
// ================================================================================================

/// Represents errors that can occur during block execution and proving.
#[derive(Debug, thiserror::Error)]
pub enum BlockProverError {
    #[error("block kernel execution failed")]
    BlockKernelExecutionFailed(#[source] ExecutionError),
    #[error("block kernel proving failed")]
    BlockKernelProvingFailed(#[source] ExecutionError),
    #[error("block kernel produced an invalid output stack")]
    BlockKernelOutputInvalid(#[source] BlockOutputError),
}
