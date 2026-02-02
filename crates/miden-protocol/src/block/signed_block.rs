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
        "signed block commitment ({signed_block}) does not match expected parent's block commitment ({parent})"
    )]
    ParentCommitmentMismatch { signed_block: Word, parent: Word },
    #[error("signed block num ({signed_block}) is not parent block num + 1 ({parent})")]
    ParentNumberMismatch {
        signed_block: BlockNumber,
        parent: BlockNumber,
    },
    #[error(
        "signed block header note root ({header_root}) does not match the corresponding body's note root ({body_root})"
    )]
    NoteRootMismatch { header_root: Word, body_root: Word },
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
    /// Involves non-trivial computation. If some checks are unnecessary, [`Self::new_unchecked`]
    /// can be used instead, alongside subsequent calls of relevant `Self::validate_*` methods.
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
    pub fn validate_signature(&self) -> Result<(), SignedBlockError> {
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
    pub fn validate_tx_commitment(&self) -> Result<(), SignedBlockError> {
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
    pub fn validate_note_root(&self) -> Result<(), SignedBlockError> {
        let header_root = self.header.note_root();
        let body_root = self.body.compute_block_note_tree().root();
        if header_root != body_root {
            Err(SignedBlockError::NoteRootMismatch { header_root, body_root })
        } else {
            Ok(())
        }
    }

    /// Validates that the provided parent block's commitment and number correctly corresponds to
    /// the signed block. block commitment.
    pub fn validate_parent(&self, parent: &BlockHeader) -> Result<(), SignedBlockError> {
        // Commitments.
        if self.header.prev_block_commitment() != parent.commitment() {
            return Err(SignedBlockError::ParentCommitmentMismatch {
                signed_block: self.header.prev_block_commitment(),
                parent: parent.commitment(),
            });
        }
        // Block numbers.
        if self.header.block_num() != parent.block_num() + 1 {
            return Err(SignedBlockError::ParentNumberMismatch {
                signed_block: self.header.block_num(),
                parent: parent.block_num(),
            });
        }
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
