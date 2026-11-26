use miden_core::Word;

use crate::block::header::ParentValidationError;
use crate::block::{
    BlockBody,
    BlockHeader,
    BlockNumber,
    BlockSignatures,
    SignatureVerificationError,
};

// SIGNED BLOCK ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum SignedBlockError {
    #[error("signed block signatures do not verify against the parent's validator set")]
    InvalidSignatures(#[source] SignatureVerificationError),
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
            ParentValidationError::InvalidSignatures(source) => Self::InvalidSignatures(source),
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

/// Represents a block in the Miden blockchain that has been signed by the validators.
///
/// Signed blocks are applied to the chain's state before they are proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBlock {
    /// The header of the Signed block.
    header: BlockHeader,

    /// The body of the Signed block.
    body: BlockBody,

    /// The validators' signatures over the block header.
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

    /// Returns the validators' signatures over the block header.
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
        let header_tx_commitment = self.header.transactions_commitment();
        let body_tx_commitment = self.body.compute_transactions_commitment();
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use miden_crypto::dsa::ecdsa_k256_keccak::SigningKey;

    use super::*;
    use crate::Word;
    use crate::block::ValidatorConfig;

    fn block_one(parent: &BlockHeader, signers: &[SigningKey]) -> SignedBlock {
        let next_keys = ValidatorConfig::random_with_signers(3).1;
        let header = BlockHeader::new_dummy(1, parent.commitment(), next_keys);
        let signatures = BlockSignatures::sign(signers, header.commitment());
        SignedBlock::new_unchecked(header, BlockBody::default(), signatures)
    }

    #[test]
    fn validate_accepts_committed_signers() {
        let (signers, keys) = ValidatorConfig::random_with_signers(3);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys);
        block_one(&parent, &signers).validate(Some(&parent)).unwrap();
    }

    #[test]
    fn validate_accepts_single_validator() {
        let (signers, keys) = ValidatorConfig::random_with_signers(1);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys);
        block_one(&parent, &signers).validate(Some(&parent)).unwrap();
    }

    #[test]
    fn validate_rejects_uncommitted_signers() {
        let (_, keys) = ValidatorConfig::random_with_signers(3);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys);
        let next_keys = ValidatorConfig::random_with_signers(3).1;
        let header = BlockHeader::new_dummy(1, parent.commitment(), next_keys);

        // The block is signed by a full, valid validator set of the same size the parent never
        // committed.
        let (impostor_signers, _) = ValidatorConfig::random_with_signers(3);
        let signatures = BlockSignatures::sign(&impostor_signers, header.commitment());
        let block = SignedBlock::new_unchecked(header, BlockBody::default(), signatures);

        let result = block.validate(Some(&parent));
        assert!(matches!(
            result,
            Err(SignedBlockError::InvalidSignatures(
                SignatureVerificationError::SignerNotInValidatorSet { .. }
            ))
        ));
    }
}
