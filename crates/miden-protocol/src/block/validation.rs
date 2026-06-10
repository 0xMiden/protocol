use miden_core::Word;
use miden_crypto::dsa::ecdsa_k256_keccak::Signature;

use crate::block::{BlockHeader, BlockNumber};

// PARENT VALIDATION ERROR
// ================================================================================================

/// Error returned when a block fails validation against its parent block.
///
/// This is the shared, block-type-agnostic error produced by [`validate_against_parent`]. Each
/// block type maps it into its own error enum via `From`, which preserves that type's specific
/// error messages.
#[derive(Debug)]
pub(crate) enum ParentValidationError {
    InvalidSignature,
    ParentNumberMismatch {
        expected: BlockNumber,
        parent: BlockNumber,
    },
    ParentCommitmentMismatch {
        expected: Word,
        parent: Word,
    },
    GenesisBlockHasNoParent {
        parent: BlockNumber,
    },
}

// PARENT VALIDATION
// ================================================================================================

/// Validates that `parent_block` precedes and authorizes the block described by `header` and
/// `signature`: the parent's number is this block's number minus one, the parent's commitment
/// matches this block's `prev_block_commitment`, and the signature verifies against the parent's
/// `validator_key` (the key the parent authorized to sign this block).
///
/// `parent_block` MUST come from already-trusted chain state. Because `prev_block_commitment` is
/// attacker-controlled, passing an untrusted parent would let a forged block self-authorize.
///
/// # Errors
///
/// Returns an error if the block is the genesis block (no parent), the parent's number or
/// commitment do not match, or the signature does not verify against the parent's validator key.
pub(crate) fn validate_against_parent(
    header: &BlockHeader,
    signature: &Signature,
    parent_block: &BlockHeader,
) -> Result<(), ParentValidationError> {
    // Block 0 does not have a parent.
    let Some(expected_parent_num) = header.block_num().checked_sub(1) else {
        return Err(ParentValidationError::GenesisBlockHasNoParent {
            parent: parent_block.block_num(),
        });
    };

    // Check block numbers.
    let parent_num = parent_block.block_num();
    if expected_parent_num != parent_num {
        return Err(ParentValidationError::ParentNumberMismatch {
            expected: expected_parent_num,
            parent: parent_num,
        });
    }

    // Check commitments.
    let expected_prev_commitment = header.prev_block_commitment();
    let parent_commitment = parent_block.commitment();
    if expected_prev_commitment != parent_commitment {
        return Err(ParentValidationError::ParentCommitmentMismatch {
            expected: expected_prev_commitment,
            parent: parent_commitment,
        });
    }

    // Verify the signature against the validator key authorized by the parent block.
    if !signature.verify(header.commitment(), parent_block.validator_key()) {
        return Err(ParentValidationError::InvalidSignature);
    }

    Ok(())
}

// TEST HELPERS
// ================================================================================================

/// Builds a minimal block header with a controllable block number, previous-block commitment, and
/// validator key. All other fields are zeroed; they are irrelevant to parent validation.
///
/// Shared by the `validate_parent` tests of [`SignedBlock`](super::SignedBlock),
/// [`ProvenBlock`](super::ProvenBlock), and this module.
#[cfg(test)]
pub(crate) fn test_block_header(
    block_num: u32,
    prev_block_commitment: Word,
    validator_key: miden_crypto::dsa::ecdsa_k256_keccak::PublicKey,
) -> BlockHeader {
    use crate::block::FeeParameters;
    use crate::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    let fee_parameters =
        FeeParameters::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 500);
    BlockHeader::new(
        0,
        prev_block_commitment,
        BlockNumber::from(block_num),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        validator_key,
        fee_parameters,
        0,
    )
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{test_block_header as header, *};
    use crate::testing::random_secret_key::random_secret_key;

    /// Expected outcome of a [`validate_against_parent`] case.
    enum Expect {
        Ok,
        InvalidSignature,
        Genesis,
        ParentNumber,
        ParentCommitment,
    }

    /// Exercises `validate_against_parent` against a parent that commits `validator` as the signer
    /// of the child. Each case tweaks one input: the child's block number, whether it links to the
    /// parent, and whether it is signed by the committed key.
    #[rstest::rstest]
    // Signed by the committed key and correctly linked: accepted. The next key it commits is free.
    #[case::accepts(1, true, true, Expect::Ok)]
    // The rotation bug: self-signed with a key the parent never committed.
    #[case::self_signed_uncommitted_key(1, true, false, Expect::InvalidSignature)]
    // Genesis has no parent to anchor against.
    #[case::genesis(0, true, true, Expect::Genesis)]
    // Child claims to be block 2, but the parent is block 0.
    #[case::wrong_parent_number(2, true, true, Expect::ParentNumber)]
    // Child's prev_block_commitment does not match the parent's commitment.
    #[case::wrong_parent_commitment(1, false, true, Expect::ParentCommitment)]
    fn validate_against_parent_cases(
        #[case] child_num: u32,
        #[case] link_to_parent: bool,
        #[case] sign_with_committed_key: bool,
        #[case] expected: Expect,
    ) {
        let validator = random_secret_key();
        let parent = header(0, Word::empty(), validator.public_key());

        let prev_commitment = if link_to_parent {
            parent.commitment()
        } else {
            Word::empty()
        };

        // The signer and the key the child commits as the next block's signer.
        let (signer, child_validator_key) = if sign_with_committed_key {
            (validator, random_secret_key().public_key())
        } else {
            let impostor = random_secret_key();
            let key = impostor.public_key();
            (impostor, key)
        };

        let child = header(child_num, prev_commitment, child_validator_key);
        let signature = signer.sign(child.commitment());
        let result = validate_against_parent(&child, &signature, &parent);

        match expected {
            Expect::Ok => result.unwrap(),
            Expect::InvalidSignature => {
                assert!(matches!(result, Err(ParentValidationError::InvalidSignature)));
            },
            Expect::Genesis => {
                assert!(matches!(
                    result,
                    Err(ParentValidationError::GenesisBlockHasNoParent { .. })
                ));
            },
            Expect::ParentNumber => {
                assert!(matches!(result, Err(ParentValidationError::ParentNumberMismatch { .. })));
            },
            Expect::ParentCommitment => {
                assert!(matches!(
                    result,
                    Err(ParentValidationError::ParentCommitmentMismatch { .. })
                ));
            },
        }
    }
}
