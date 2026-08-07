use miden_verifier::VerificationError;
use thiserror::Error;

// BATCH VERIFIER ERROR
// ================================================================================================

/// Errors returned when verifying a [`ProvenBatch`](miden_protocol::batch::ProvenBatch)'s proof.
#[derive(Debug, Error)]
pub enum BatchVerifierError {
    #[error("failed to verify batch")]
    BatchVerificationFailed(#[source] VerificationError),
    #[error("batch proof security level is {actual} but must be at least {expected_minimum}")]
    InsufficientProofSecurityLevel { actual: u32, expected_minimum: u32 },
}
