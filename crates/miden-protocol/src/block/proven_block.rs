use miden_core::Word;
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;

use crate::MIN_PROOF_SECURITY_LEVEL;
use crate::block::validation::{self, ParentValidationError};
use crate::block::{BlockBody, BlockHeader, BlockNumber, BlockProof};
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
        "ECDSA signature verification failed based on the proven block's header commitment, the parent block's validator public key and signature"
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
    #[error(
        "proven block previous block commitment ({expected}) does not match expected parent's block commitment ({parent})"
    )]
    ParentCommitmentMismatch { expected: Word, parent: Word },
    #[error("parent block number ({parent}) is not proven block number - 1 ({expected})")]
    ParentNumberMismatch {
        expected: BlockNumber,
        parent: BlockNumber,
    },
    #[error("supplied parent block ({parent}) cannot be parent to genesis block")]
    GenesisBlockHasNoParent { parent: BlockNumber },
}

impl From<ParentValidationError> for ProvenBlockError {
    fn from(err: ParentValidationError) -> Self {
        match err {
            ParentValidationError::InvalidSignature => Self::InvalidSignature,
            ParentValidationError::ParentNumberMismatch { expected, parent } => {
                Self::ParentNumberMismatch { expected, parent }
            },
            ParentValidationError::ParentCommitmentMismatch { expected, parent } => {
                Self::ParentCommitmentMismatch { expected, parent }
            },
            ParentValidationError::GenesisBlockHasNoParent { parent } => {
                Self::GenesisBlockHasNoParent { parent }
            },
        }
    }
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
    /// Validates that the header and body correspond by checking the transaction commitment and
    /// note root. This does NOT verify the validator signature, which can only be checked against
    /// the parent block's validator key; callers must also call [`Self::validate_parent`] to
    /// authenticate the block.
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

    /// Validates that the components of the proven block correspond by checking the transaction
    /// commitment and note root. Like [`Self::new`], this does NOT verify the validator signature;
    /// call [`Self::validate_parent`] to authenticate the block.
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
    /// - If the transaction commitment in the block header is inconsistent with the transactions
    ///   included in the block body.
    /// - If the note root in the block header is inconsistent with the notes included in the block
    ///   body.
    pub fn validate(&self) -> Result<(), ProvenBlockError> {
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

    /// Validates that the provided parent block precedes and authorizes this block: the parent's
    /// number is this block's number minus one, the parent's commitment matches this block's
    /// `prev_block_commitment`, and this block's signature verifies against the parent's
    /// `validator_key` (the key authorized to sign this block).
    ///
    /// `parent_block` MUST come from already-trusted chain state. Because `prev_block_commitment`
    /// is attacker-controlled, passing an untrusted parent would let a forged block self-authorize.
    ///
    /// # Errors
    ///
    /// Returns an error if the block is the genesis block (no parent), the parent's number or
    /// commitment do not match, or the signature does not verify against the parent's validator
    /// key.
    pub fn validate_parent(&self, parent_block: &BlockHeader) -> Result<(), ProvenBlockError> {
        validation::validate_against_parent(&self.header, &self.signature, parent_block)?;
        Ok(())
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_crypto::dsa::ecdsa_k256_keccak::SigningKey;

    use super::*;
    use crate::Word;
    use crate::block::validation::test_block_header;
    use crate::testing::random_secret_key::random_secret_key;
    use crate::transaction::OrderedTransactionHeaders;

    /// Builds block 1 signed by `signer` and linked to `parent`. The exhaustive matrix of failure
    /// modes lives in `block::validation`; here we only confirm `ProvenBlock::validate_parent`
    /// wires the signature and parent header through to the shared check.
    fn block_one(parent: &BlockHeader, signer: &SigningKey) -> ProvenBlock {
        let header = test_block_header(1, parent.commitment(), random_secret_key().public_key());
        let signature = signer.sign(header.commitment());
        let body = BlockBody::new_unchecked(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            OrderedTransactionHeaders::new_unchecked(Vec::new()),
        );
        ProvenBlock::new_unchecked(header, body, signature, BlockProof::new_dummy())
    }

    #[test]
    fn validate_parent_accepts_committed_signer() {
        let validator = random_secret_key();
        let parent = test_block_header(0, Word::empty(), validator.public_key());
        block_one(&parent, &validator).validate_parent(&parent).unwrap();
    }

    #[test]
    fn validate_parent_rejects_uncommitted_signer() {
        let parent = test_block_header(0, Word::empty(), random_secret_key().public_key());
        let impostor = random_secret_key();
        let result = block_one(&parent, &impostor).validate_parent(&parent);
        assert!(matches!(result, Err(ProvenBlockError::InvalidSignature)));
    }
}
