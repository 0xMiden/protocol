use miden_core::Word;

use crate::block::header::ParentValidationError;
use crate::block::{BlockBody, BlockHeader, BlockNumber, BlockSignatures};
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
        "signed block has {actual} signatures but its parent's validator set has {expected} keys"
    )]
    SignatureCountMismatch { expected: usize, actual: usize },
    #[error(
        "signed block signature at position {position} does not verify against the parent's validator key at that position"
    )]
    InvalidSignatureAtPosition { position: usize },
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
            ParentValidationError::SignatureCountMismatch { expected, actual } => {
                Self::SignatureCountMismatch { expected, actual }
            },
            ParentValidationError::InvalidSignatureAtPosition { position } => {
                Self::InvalidSignatureAtPosition { position }
            },
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

// UNVERIFIED SIGNED BLOCK
// ================================================================================================

/// The decoded components of a signed block before they have been verified against a trusted
/// parent block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedSignedBlock {
    header: BlockHeader,
    body: BlockBody,
    signatures: BlockSignatures,
}

impl UnverifiedSignedBlock {
    /// Creates an unverified signed block from its decoded components.
    pub fn new(header: BlockHeader, body: BlockBody, signatures: BlockSignatures) -> Self {
        Self { header, body, signatures }
    }

    /// Returns the header of the block.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Returns the body of the block.
    pub fn body(&self) -> &BlockBody {
        &self.body
    }

    /// Returns the validators' positional signatures over the block header.
    pub fn signatures(&self) -> &BlockSignatures {
        &self.signatures
    }

    /// Verifies the block's internal consistency and authenticates it against `parent`.
    ///
    /// `parent` must come from already-trusted chain state.
    ///
    /// # Errors
    ///
    /// Returns an error if the block header and body are inconsistent, the parent is not the
    /// header's parent, or the signatures do not verify against the parent's validator keys.
    pub fn verify(self, parent: &BlockHeader) -> Result<SignedBlock, SignedBlockError> {
        let block = SignedBlock::new_unchecked(self.header, self.body, self.signatures);
        block.validate(Some(parent))?;
        Ok(block)
    }
}

// SIGNED BLOCK
// ================================================================================================

/// Represents a block in the Miden blockchain that has been signed by the validators.
///
/// Signed blocks are applied to the chain's state before they are proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBlock {
    /// The header of the Signed block.
    header: BlockHeader,

    /// The body of the Signed block.
    body: BlockBody,

    /// The validators' positional signatures over the block header.
    signatures: BlockSignatures,
}

impl SignedBlock {
    /// Returns a new [`SignedBlock`] instantiated from the provided components.
    ///
    /// Validates that the header and body correspond by checking the transaction commitment and
    /// note root. This does NOT verify the validator signatures, which can only be checked against
    /// the parent block's validator keys; call [`Self::validate`] with the parent header to
    /// authenticate the block.
    ///
    /// Involves non-trivial computation. Use [`Self::new_unchecked`] if the validation is not
    /// necessary.
    pub fn new(
        header: BlockHeader,
        body: BlockBody,
        signatures: BlockSignatures,
    ) -> Result<Self, SignedBlockError> {
        let signed_block = Self { header, body, signatures };

        signed_block.validate(None)?;

        Ok(signed_block)
    }

    /// Returns a new [`SignedBlock`] instantiated from the provided components.
    ///
    /// # Warning
    ///
    /// This constructor does not do any validation as to whether the arguments correctly correspond
    /// to each other, which could cause errors downstream.
    pub fn new_unchecked(
        header: BlockHeader,
        body: BlockBody,
        signatures: BlockSignatures,
    ) -> Self {
        Self { header, signatures, body }
    }

    /// Returns the header of the block.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Returns the body of the block.
    pub fn body(&self) -> &BlockBody {
        &self.body
    }

    /// Returns the validators' positional signatures over the block header.
    pub fn signatures(&self) -> &BlockSignatures {
        &self.signatures
    }

    /// Destructures this signed block into individual parts.
    pub fn into_parts(self) -> (BlockHeader, BlockBody, BlockSignatures) {
        (self.header, self.body, self.signatures)
    }

    /// Validates that the header and body correspond by checking the transaction commitment and
    /// note root, and -- when `parent` is provided -- authenticates the block against its parent.
    ///
    /// Pass `Some(parent)` to additionally authenticate the block against its parent; pass `None`
    /// for the genesis block, which has no parent, or when only self-consistency is required.
    ///
    /// `parent` MUST come from already-trusted chain state. Because `prev_block_commitment` is
    /// attacker-controlled, passing an untrusted parent would let a forged block self-authorize.
    ///
    /// # Errors
    /// Returns an error if:
    /// - the transaction commitment in the block header is inconsistent with the transactions
    ///   included in the block body;
    /// - the note root in the block header is inconsistent with the notes included in the block
    ///   body; or
    /// - a `parent` is provided and the block is not authorized by it: the block is the genesis
    ///   block (which has no parent), the parent's number or commitment do not match, or the
    ///   signatures do not verify against the parent's validator keys.
    pub fn validate(&self, parent: Option<&BlockHeader>) -> Result<(), SignedBlockError> {
        // Validate that header / body transaction commitments match.
        self.validate_tx_commitment()?;

        // Validate that header / body note roots match.
        self.validate_note_root()?;

        // When a trusted parent is provided, authenticate the block against it.
        if let Some(parent) = parent {
            self.header.validate_against_parent(parent, &self.signatures)?;
        }

        Ok(())
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
}

// SERIALIZATION
// ================================================================================================

impl Serializable for SignedBlock {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.header.write_into(target);
        self.body.write_into(target);
        self.signatures.write_into(target);
    }
}

impl Deserializable for SignedBlock {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let block = Self {
            header: BlockHeader::read_from(source)?,
            body: BlockBody::read_from(source)?,
            signatures: BlockSignatures::read_from(source)?,
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
    use crate::block::ValidatorConfig;
    use crate::transaction::OrderedTransactionHeaders;

    fn empty_body() -> BlockBody {
        BlockBody::new_unchecked(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            OrderedTransactionHeaders::new_unchecked(Vec::new()),
        )
    }

    fn block_one(
        parent: &BlockHeader,
        parent_keys: &ValidatorConfig,
        signers: &[SigningKey],
    ) -> SignedBlock {
        let next_keys = ValidatorConfig::random_with_signers(3).1;
        let header = BlockHeader::new_dummy(1, parent.commitment(), next_keys);
        let signatures = parent_keys.sign_all(signers, header.commitment());
        SignedBlock::new_unchecked(header, empty_body(), signatures)
    }

    #[test]
    fn validate_accepts_committed_signers() {
        let (signers, keys) = ValidatorConfig::random_with_signers(3);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        block_one(&parent, &keys, &signers).validate(Some(&parent)).unwrap();
    }

    #[test]
    fn validate_accepts_single_validator() {
        let (signers, keys) = ValidatorConfig::random_with_signers(1);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        block_one(&parent, &keys, &signers).validate(Some(&parent)).unwrap();
    }

    #[test]
    fn unverified_signed_block_verifies_against_parent() {
        let (signers, keys) = ValidatorConfig::random_with_signers(3);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        let expected = block_one(&parent, &keys, &signers);
        let (header, body, signatures) = expected.clone().into_parts();
        let unverified = UnverifiedSignedBlock::new(header, body, signatures);

        assert_eq!(unverified.verify(&parent).unwrap(), expected);
    }

    #[test]
    fn validate_rejects_uncommitted_signers() {
        let (_, keys) = ValidatorConfig::random_with_signers(3);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        let next_keys = ValidatorConfig::random_with_signers(3).1;
        let header = BlockHeader::new_dummy(1, parent.commitment(), next_keys);

        // The block is signed by a full, valid validator set of the same size the parent never
        // committed.
        let (impostor_signers, impostor_keys) = ValidatorConfig::random_with_signers(3);
        let signatures = impostor_keys.sign_all(&impostor_signers, header.commitment());
        let block = SignedBlock::new_unchecked(header, empty_body(), signatures);

        let result = block.validate(Some(&parent));
        assert!(matches!(result, Err(SignedBlockError::InvalidSignatureAtPosition { .. })));
    }
}
