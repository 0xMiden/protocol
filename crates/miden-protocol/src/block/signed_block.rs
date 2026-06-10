use miden_core::Word;
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;

use crate::block::validation::{self, ParentValidationError};
use crate::block::{BlockBody, BlockHeader, BlockNumber};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// SIGNED BLOCK ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum SignedBlockError {
    #[error(
        "ECDSA signature verification failed based on the signed block's header commitment, the parent block's validator public key and signature"
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
        "signed block previous block commitment ({expected}) does not match expected parent's block commitment ({parent})"
    )]
    ParentCommitmentMismatch { expected: Word, parent: Word },
    #[error("parent block number ({parent}) is not signed block number - 1 ({expected})")]
    ParentNumberMismatch {
        expected: BlockNumber,
        parent: BlockNumber,
    },
    #[error(
        "signed block header note root ({header_root}) does not match the corresponding body's note root ({body_root})"
    )]
    NoteRootMismatch { header_root: Word, body_root: Word },
    #[error("supplied parent block ({parent}) cannot be parent to genesis block")]
    GenesisBlockHasNoParent { parent: BlockNumber },
}

impl From<ParentValidationError> for SignedBlockError {
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

// SIGNED BLOCK
// ================================================================================================

/// Represents a block in the Miden blockchain that has been signed by the Validator.
///
/// Signed blocks are applied to the chain's state before they are proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBlock {
    /// The header of the Signed block.
    header: BlockHeader,

    /// The body of the Signed block.
    body: BlockBody,

    /// The Validator's signature over the block header.
    signature: Signature,
}

impl SignedBlock {
    /// Returns a new [`SignedBlock`] instantiated from the provided components.
    ///
    /// Validates that the header and body correspond by checking the transaction commitment and
    /// note root. This does NOT verify the validator signature, which can only be checked against
    /// the parent block's validator key; callers must also call [`Self::validate_parent`] to
    /// authenticate the block.
    ///
    /// Involves non-trivial computation. Use [`Self::new_unchecked`] if the validation is not
    /// necessary.
    pub fn new(
        header: BlockHeader,
        body: BlockBody,
        signature: Signature,
    ) -> Result<Self, SignedBlockError> {
        let signed_block = Self { header, body, signature };

        // Validate that header / body transaction commitments match.
        signed_block.validate_tx_commitment()?;

        // Validate that header / body note roots match.
        signed_block.validate_note_root()?;

        Ok(signed_block)
    }

    /// Returns a new [`SignedBlock`] instantiated from the provided components.
    ///
    /// # Warning
    ///
    /// This constructor does not do any validation as to whether the arguments correctly correspond
    /// to each other, which could cause errors downstream.
    pub fn new_unchecked(header: BlockHeader, body: BlockBody, signature: Signature) -> Self {
        Self { header, signature, body }
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

    /// Destructures this signed block into individual parts.
    pub fn into_parts(self) -> (BlockHeader, BlockBody, Signature) {
        (self.header, self.body, self.signature)
    }

    /// Validates that the transaction commitments between the header and body match for this signed
    /// block.
    ///
    /// Involves non-trivial computation of the body's transaction commitment.
    fn validate_tx_commitment(&self) -> Result<(), SignedBlockError> {
        let header_tx_commitment = self.header.tx_commitment();
        let body_tx_commitment = self.body.transactions().commitment();
        if header_tx_commitment != body_tx_commitment {
            Err(SignedBlockError::TxCommitmentMismatch { header_tx_commitment, body_tx_commitment })
        } else {
            Ok(())
        }
    }

    /// Validates that the header's note tree root matches that of the body.
    ///
    /// Involves non-trivial computation of the body's note tree.
    fn validate_note_root(&self) -> Result<(), SignedBlockError> {
        let header_root = self.header.note_root();
        let body_root = self.body.compute_block_note_tree().root();
        if header_root != body_root {
            Err(SignedBlockError::NoteRootMismatch { header_root, body_root })
        } else {
            Ok(())
        }
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
    pub fn validate_parent(&self, parent_block: &BlockHeader) -> Result<(), SignedBlockError> {
        validation::validate_against_parent(&self.header, &self.signature, parent_block)?;
        Ok(())
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for SignedBlock {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.header.write_into(target);
        self.body.write_into(target);
        self.signature.write_into(target);
    }
}

impl Deserializable for SignedBlock {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let block = Self {
            header: BlockHeader::read_from(source)?,
            body: BlockBody::read_from(source)?,
            signature: Signature::read_from(source)?,
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
    /// modes lives in `block::validation`; here we only confirm `SignedBlock::validate_parent`
    /// wires the signature and parent header through to the shared check.
    fn block_one(parent: &BlockHeader, signer: &SigningKey) -> SignedBlock {
        let header = test_block_header(1, parent.commitment(), random_secret_key().public_key());
        let signature = signer.sign(header.commitment());
        let body = BlockBody::new_unchecked(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            OrderedTransactionHeaders::new_unchecked(Vec::new()),
        );
        SignedBlock::new_unchecked(header, body, signature)
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
        assert!(matches!(result, Err(SignedBlockError::InvalidSignature)));
    }
}
