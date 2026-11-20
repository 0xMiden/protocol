use miden_protocol::errors::ProofVerificationError;
use miden_verifier::{HashFunction, VerificationError};
use thiserror::Error;

// BATCH VERIFIER ERROR
// ================================================================================================

/// Errors returned when verifying a [`ProvenBatch`](miden_protocol::batch::ProvenBatch)'s proof.
#[derive(Debug, Error)]
pub enum BatchVerifierError {
    #[error("failed to verify batch")]
    BatchVerificationFailed(#[source] VerificationError),
    #[error("batch proof contains precompile work")]
    BatchProofContainsPrecompiles,
    #[error("batch proof has an outstanding precompile obligation")]
    IncompleteProof,
    #[error("batch VM proof uses {actual:?}, but the protocol requires {expected:?}")]
    UnsupportedVmProofHash {
        actual: HashFunction,
        expected: HashFunction,
    },
    #[error("batch proof security level is {actual} but must be at least {expected_minimum}")]
    InsufficientProofSecurityLevel { actual: u32, expected_minimum: u32 },
}

impl From<ProofVerificationError> for BatchVerifierError {
    fn from(error: ProofVerificationError) -> Self {
        match error {
            ProofVerificationError::UnsupportedVmProofHash { actual, expected } => {
                Self::UnsupportedVmProofHash { actual, expected }
            },
            ProofVerificationError::InsufficientSecurityLevel { actual, required } => {
                Self::InsufficientProofSecurityLevel { actual, expected_minimum: required }
            },
            ProofVerificationError::VerificationFailed(error) => {
                Self::BatchVerificationFailed(error)
            },
        }
    }
}
