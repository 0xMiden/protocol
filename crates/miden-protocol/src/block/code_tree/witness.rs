use crate::crypto::merkle::smt::SmtProof;

// CODE WITNESS
// ================================================================================================

/// A proof of the presence or absence of a procedure root in the [`CodeTree`](super::CodeTree).
///
/// The proof may open a leaf with multiple entries, since procedure roots can share a leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeWitness {
    proof: SmtProof,
}

impl CodeWitness {
    /// Creates a new [`CodeWitness`] from the given proof.
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
