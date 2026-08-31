use miden_protocol::Word;
use miden_protocol::errors::ProvenBatchError;
use miden_prover::ProverError;
use miden_verifier::VerificationError;
use thiserror::Error;

// BATCH PROVER ERROR
// ================================================================================================

/// Errors returned when proving an [`ExecutedBatch`](crate::ExecutedBatch).
#[derive(Debug, Error)]
pub enum BatchProverError {
    #[error("failed to generate the batch proof")]
    ProofGenerationFailed(#[source] ProverError),
    #[error("failed to build the proven batch")]
    ProvenBatchBuildFailed(#[source] ProvenBatchError),
}

// BATCH VERIFIER ERROR
// ================================================================================================

/// Errors returned when verifying a [`ProvenBatch`](miden_protocol::batch::ProvenBatch)'s proof.
#[derive(Debug, Error)]
pub enum BatchVerifierError {
    #[error("failed to verify batch")]
    BatchVerificationFailed(#[source] VerificationError),
    #[error("batch proof defers precompile work under root {0}, which is left unproven")]
    IncompleteProof(Word),
    #[error("batch proof security level is {actual} but must be at least {expected_minimum}")]
    InsufficientProofSecurityLevel { actual: u32, expected_minimum: u32 },
}
