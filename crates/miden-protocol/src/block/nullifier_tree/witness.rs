use crate::crypto::merkle::smt::SmtProof;

// NULLIFIER WITNESS
// ================================================================================================

/// A proof that a certain nullifier is in the nullifier tree with the contained state.
#[derive(Debug, Clone)]
pub struct NullifierWitness {
    proof: SmtProof,
}

impl NullifierWitness {
    /// Creates a new [`NullifierWitness`] from the given proof.
    pub fn new(proof: SmtProof) -> Self {
        Self { proof }
    }

    /// Returns a reference to the underlying [`SmtProof`].
    pub fn proof(&self) -> &SmtProof {
        &self.proof
    }

    /// Consumes the witness and returns the underlying [`SmtProof`].
    pub fn into_proof(self) -> SmtProof {
        self.proof
    }
}
