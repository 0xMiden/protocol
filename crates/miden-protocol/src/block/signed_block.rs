use miden_core::Word;
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;

use crate::block::{BlockBody, BlockHeader};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// SIGNED BLOCK ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum SignedBlockError {
    #[error(
        "block signature does not match the corresponding block header commitment and validator public key"
    )]
    InvalidSignature,
    #[error("invalid block transaction commitment: expected {expected}, actual {actual}")]
    InvalidTransactionCommitment { expected: Word, actual: Word },
    #[error(
        "signed block commitment does not match expected parent's : signed block commitment {signed_block}, parent {parent}"
    )]
    ParentMismatch { signed_block: Word, parent: Word },
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
    /// and checking for matching commitments.
    pub fn new(
        header: BlockHeader,
        body: BlockBody,
        signature: Signature,
    ) -> Result<Self, SignedBlockError> {
        // Verify signature.
        if !signature.verify(header.commitment(), header.validator_key()) {
            return Err(SignedBlockError::InvalidSignature);
        }

        // Validate header / body matching transaction commitments.
        let tx_commitment = body.transactions().commitment();
        if header.tx_commitment() != tx_commitment {
            return Err(SignedBlockError::InvalidTransactionCommitment {
                expected: tx_commitment,
                actual: header.tx_commitment(),
            });
        }

        Ok(Self { header, body, signature })
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

    /// Validates that the provided parent block's commitment matches the signed block's previous
    /// block commitment.
    pub fn validate_parent(&self, parent: &BlockHeader) -> Result<(), SignedBlockError> {
        if self.header.prev_block_commitment() == parent.commitment() {
            Ok(())
        } else {
            Err(SignedBlockError::ParentMismatch {
                signed_block: self.header.prev_block_commitment(),
                parent: parent.commitment(),
            })
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
