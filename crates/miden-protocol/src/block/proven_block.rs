use miden_core::Word;
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;

use crate::MIN_PROOF_SECURITY_LEVEL;
use crate::block::{BlockBody, BlockHeader, BlockProof};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// PROVEN BLOCK ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum ProvenBlockError {
    #[error(
        "ECDSA signature verification failed based on the proven block's header commitment, validator public key and signature"
    )]
    InvalidSignature,
    #[error(
        "header tx commitment ({header_tx_commitment}) does not match body tx commitment ({body_tx_commitment})"
    )]
    TxCommitmentMismatch {
        header_tx_commitment: Word,
        body_tx_commitment: Word,
    },
    #[error(
        "proven block header note root ({header_root}) does not match the corresponding body's note root ({body_root})"
    )]
    NoteRootMismatch { header_root: Word, body_root: Word },
}

// PROVEN BLOCK
// ================================================================================================

/// Represents a block in the Miden blockchain that has been signed and proven.
///
/// Blocks transition through proposed, signed, and proven states. This struct represents the final,
/// proven state of a block.
///
/// Proven blocks are the final, canonical blocks in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenBlock {
    /// The header of the proven block.
    header: BlockHeader,

    /// The body of the proven block.
    body: BlockBody,

    /// The Validator's signature over the block header.
    signature: Signature,

    /// The proof of the block.
    proof: BlockProof,
}

impl ProvenBlock {
    /// Returns a new [`ProvenBlock`] instantiated from the provided components.
    ///
    /// Validates that the provided components correspond to each other by verifying the signature,
    /// and checking for matching transaction commitments and note roots.
    ///
    /// Involves non-trivial computation. Use [`Self::new_unchecked`] if the validation is not
    /// necessary.
    ///
    /// Note: this does not fully validate the consistency of provided components. Specifically,
    /// we cannot validate that:
    /// - That applying the account updates in the block body to the account tree represented by the
    ///   root from the previous block header would actually result in the account root in the
    ///   provided header.
    /// - That inserting the created nullifiers in the block body to the nullifier tree represented
    ///   by the root from the previous block header would actually result in the nullifier root in
    ///   the provided header.
    ///
    /// # Errors
    /// Returns an error if:
    /// - If the validator signature does not verify against the block header commitment and the
    ///   validator key.
    /// - If the transaction commitment in the block header is inconsistent with the transactions
    ///   included in the block body.
    /// - If the note root in the block header is inconsistent with the notes included in the block
    ///   body.
    pub fn new(
        header: BlockHeader,
        body: BlockBody,
        signature: Signature,
        proof: BlockProof,
    ) -> Result<Self, ProvenBlockError> {
        let proven_block = Self { header, signature, body, proof };

        proven_block.validate()?;

        Ok(proven_block)
    }

    /// Returns a new [`ProvenBlock`] instantiated from the provided components.
    ///
    /// # Warning
    ///
    /// This constructor does not do any validation as to whether the arguments correctly correspond
    /// to each other, which could cause errors downstream.
    pub fn new_unchecked(
        header: BlockHeader,
        body: BlockBody,
        signature: Signature,
        proof: BlockProof,
    ) -> Self {
        Self { header, signature, body, proof }
    }

    /// Validates that the components of the proven block correspond to each other by verifying the
    /// signature, and checking for matching transaction commitments and note roots.
    ///
    /// Validation involves non-trivial computation, and depending on the size of the block may
    /// take non-negligible amount of time.
    ///
    /// Note: this does not fully validate the consistency of internal components. Specifically,
    /// we cannot validate that:
    /// - That applying the account updates in the block body to the account tree represented by the
    ///   root from the previous block header would actually result in the account root in the
    ///   provided header.
    /// - That inserting the created nullifiers in the block body to the nullifier tree represented
    ///   by the root from the previous block header would actually result in the nullifier root in
    ///   the provided header.
    ///
    /// # Errors
    /// Returns an error if:
    /// - If the validator signature does not verify against the block header commitment and the
    ///   validator key.
    /// - If the transaction commitment in the block header is inconsistent with the transactions
    ///   included in the block body.
    /// - If the note root in the block header is inconsistent with the notes included in the block
    ///   body.
    pub fn validate(&self) -> Result<(), ProvenBlockError> {
        // Verify signature.
        self.validate_signature()?;

        // Validate that header / body transaction commitments match.
        self.validate_tx_commitment()?;

        // Validate that header / body note roots match.
        self.validate_note_root()?;

        Ok(())
    }

    /// Returns the proof security level of the block.
    pub fn proof_security_level(&self) -> u32 {
        MIN_PROOF_SECURITY_LEVEL
    }

    /// Returns the header of the block.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Returns the body of the block.
    pub fn body(&self) -> &BlockBody {
        &self.body
    }

    /// Returns the Validator's signature over the block header.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the proof of the block.
    pub fn proof(&self) -> &BlockProof {
        &self.proof
    }

    /// Destructures this proven block into individual parts.
    pub fn into_parts(self) -> (BlockHeader, BlockBody, Signature, BlockProof) {
        (self.header, self.body, self.signature, self.proof)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Performs ECDSA signature verification against the header commitment and validator key.
    fn validate_signature(&self) -> Result<(), ProvenBlockError> {
        if !self.signature.verify(self.header.commitment(), self.header.validator_key()) {
            Err(ProvenBlockError::InvalidSignature)
        } else {
            Ok(())
        }
    }

    /// Validates that the transaction commitments between the header and body match for this proven
    /// block.
    ///
    /// Involves non-trivial computation of the body's transaction commitment.
    fn validate_tx_commitment(&self) -> Result<(), ProvenBlockError> {
        let header_tx_commitment = self.header.tx_commitment();
        let body_tx_commitment = self.body.transactions().commitment();
        if header_tx_commitment != body_tx_commitment {
            Err(ProvenBlockError::TxCommitmentMismatch { header_tx_commitment, body_tx_commitment })
        } else {
            Ok(())
        }
    }

    /// Validates that the header's note tree root matches that of the body.
    ///
    /// Involves non-trivial computation of the body's note tree.
    fn validate_note_root(&self) -> Result<(), ProvenBlockError> {
        let header_root = self.header.note_root();
        let body_root = self.body.compute_block_note_tree().root();
        if header_root != body_root {
            Err(ProvenBlockError::NoteRootMismatch { header_root, body_root })
        } else {
            Ok(())
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for ProvenBlock {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.header.write_into(target);
        self.body.write_into(target);
        self.signature.write_into(target);
        self.proof.write_into(target);
    }
}

impl Deserializable for ProvenBlock {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let block = Self {
            header: BlockHeader::read_from(source)?,
            body: BlockBody::read_from(source)?,
            signature: Signature::read_from(source)?,
            proof: BlockProof::read_from(source)?,
        };

        Ok(block)
    }
}
