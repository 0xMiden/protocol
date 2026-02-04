use miden_core::Word;
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;

use crate::block::{BlockBody, BlockHeader, BlockNumber};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// SIGNED BLOCK ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum SignedBlockError {
    #[error(
        "ECDSA signature verification failed based on the signed block's header commitment, validator public key and signature"
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
    /// Validates that the provided components correspond to each other by verifying the signature,
    /// and checking for matching commitments and note roots.
    ///
    /// Involves non-trivial computation. Use [`Self::new_unchecked`] if the validation is not
    /// necessary.
    pub fn new(
        header: BlockHeader,
        body: BlockBody,
        signature: Signature,
    ) -> Result<Self, SignedBlockError> {
        let signed_block = Self { header, body, signature };

        // Verify signature.
        signed_block.validate_signature()?;

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

    /// Performs ECDSA signature verification against the header commitment and validator key.
    fn validate_signature(&self) -> Result<(), SignedBlockError> {
        if !self.signature.verify(self.header.commitment(), self.header.validator_key()) {
            Err(SignedBlockError::InvalidSignature)
        } else {
            Ok(())
        }
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

    /// Validates that the provided parent block's commitment and number correctly corresponds to
    /// the signed block.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signed block is the genesis block.
    /// - The parent block number is not the signed block number - 1.
    /// - The parent block's commitment is not equal to the signed block's previous block
    ///   commitment.
    pub fn validate_parent(&self, parent_block: &BlockHeader) -> Result<(), SignedBlockError> {
        // Check block numbers.
        if let Some(expected) = self.header.block_num().checked_sub(1) {
            let parent = parent_block.block_num();
            if expected != parent {
                return Err(SignedBlockError::ParentNumberMismatch { expected, parent });
            }

            // Check commitments.
            let expected = self.header.prev_block_commitment();
            let parent = parent_block.commitment();
            if expected != parent {
                return Err(SignedBlockError::ParentCommitmentMismatch { expected, parent });
            }

            Ok(())
        } else {
            // Block 0 does not have a parent.
            let parent = parent_block.block_num();
            Err(SignedBlockError::GenesisBlockHasNoParent { parent })
        }
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
