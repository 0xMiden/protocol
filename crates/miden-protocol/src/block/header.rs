use alloc::vec::Vec;

use crate::account::AccountId;
use crate::block::{BlockNumber, BlockSignatures, SignatureVerificationError, ValidatorKeys};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word, ZERO};

// BLOCK HEADER
// ================================================================================================

/// The header of a block. It contains metadata about the block, commitments to the current state of
/// the chain and the hash of the proof that attests to the integrity of the chain.
///
/// A block header includes the following fields:
///
/// - `version` specifies the version of the protocol.
/// - `prev_block_commitment` is the hash of the previous block header.
/// - `block_num` is a unique sequential number of the current block.
/// - `chain_commitment` is a commitment to an MMR of the entire chain where each block is a leaf.
/// - `account_root` is a commitment to account database.
/// - `nullifier_root` is a commitment to the nullifier database.
/// - `note_root` is a commitment to all notes created in the current block.
/// - `tx_commitment` is a commitment to the set of transaction IDs which affected accounts in the
///   block.
/// - `tx_kernel_commitment` a commitment to all transaction kernels supported by this block.
/// - `validator_keys` is the set of validator public keys authorized to sign the *next* block.
/// - `fee_parameters` are the parameters defining the base fees and the fee faucet ID, see
///   [`FeeParameters`] for more details.
/// - `timestamp` is the time when the block was created, in seconds since UNIX epoch. Current
///   representation is sufficient to represent time up to year 2106.
/// - `sub_commitment` is a sequential hash of all fields except the note_root.
/// - `commitment` is a 2-to-1 hash of the sub_commitment and the note_root.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct BlockHeader {
    version: u32,
    prev_block_commitment: Word,
    block_num: BlockNumber,
    chain_commitment: Word,
    account_root: Word,
    nullifier_root: Word,
    note_root: Word,
    tx_commitment: Word,
    tx_kernel_commitment: Word,
    validator_keys: ValidatorKeys,
    fee_parameters: FeeParameters,
    timestamp: u32,
    sub_commitment: Word,
    commitment: Word,
}

impl BlockHeader {
    /// Creates a new block header.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u32,
        prev_block_commitment: Word,
        block_num: BlockNumber,
        chain_commitment: Word,
        account_root: Word,
        nullifier_root: Word,
        note_root: Word,
        tx_commitment: Word,
        tx_kernel_commitment: Word,
        validator_keys: ValidatorKeys,
        fee_parameters: FeeParameters,
        timestamp: u32,
    ) -> Self {
        // Compute block sub commitment.
        let sub_commitment = Self::compute_sub_commitment(
            version,
            prev_block_commitment,
            chain_commitment,
            account_root,
            nullifier_root,
            tx_commitment,
            tx_kernel_commitment,
            &validator_keys,
            &fee_parameters,
            timestamp,
            block_num,
        );

        // The sub commitment is merged with the note_root - hash(sub_commitment, note_root) to
        // produce the final hash. This is done to make the note_root easily accessible
        // without having to unhash the entire header. Having the note_root easily
        // accessible is useful when authenticating notes.
        let commitment = Hasher::merge(&[sub_commitment, note_root]);

        Self {
            version,
            prev_block_commitment,
            block_num,
            chain_commitment,
            account_root,
            nullifier_root,
            note_root,
            tx_commitment,
            tx_kernel_commitment,
            validator_keys,
            fee_parameters,
            timestamp,
            sub_commitment,
            commitment,
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the protocol version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Returns the commitment of the block header.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// Returns the sub commitment of the block header.
    ///
    /// The sub commitment is a sequential hash of all block header fields except the note root.
    /// This is used in the block commitment computation which is a 2-to-1 hash of the sub
    /// commitment and the note root [hash(sub_commitment, note_root)]. This procedure is used to
    /// make the note root easily accessible without having to unhash the entire header.
    pub fn sub_commitment(&self) -> Word {
        self.sub_commitment
    }

    /// Returns the commitment to the previous block header.
    pub fn prev_block_commitment(&self) -> Word {
        self.prev_block_commitment
    }

    /// Returns the block number.
    pub fn block_num(&self) -> BlockNumber {
        self.block_num
    }

    /// Returns the epoch to which this block belongs.
    ///
    /// This is the block number shifted right by [`BlockNumber::EPOCH_LENGTH_EXPONENT`].
    pub fn block_epoch(&self) -> u16 {
        self.block_num.block_epoch()
    }

    /// Returns the chain commitment.
    pub fn chain_commitment(&self) -> Word {
        self.chain_commitment
    }

    /// Returns the account database root.
    pub fn account_root(&self) -> Word {
        self.account_root
    }

    /// Returns the nullifier database root.
    pub fn nullifier_root(&self) -> Word {
        self.nullifier_root
    }

    /// Returns the note root.
    pub fn note_root(&self) -> Word {
        self.note_root
    }

    /// Returns the set of validator public keys authorized to sign the *next* block.
    ///
    /// A block's signatures are verified against the `validator_keys` committed to by its parent
    /// block, not against this field. See the [`BlockHeader`] docs for details.
    pub fn validator_keys(&self) -> &ValidatorKeys {
        &self.validator_keys
    }

    /// Returns the commitment to all transactions in this block.
    ///
    /// The commitment is computed as sequential hash of (`transaction_id`, `account_id`) tuples.
    /// This makes it possible for the verifier to link transaction IDs to the accounts which
    /// they were executed against.
    pub fn tx_commitment(&self) -> Word {
        self.tx_commitment
    }

    /// Returns the transaction kernel commitment.
    ///
    /// The transaction kernel commitment is computed as a sequential hash of all transaction kernel
    /// hashes.
    pub fn tx_kernel_commitment(&self) -> Word {
        self.tx_kernel_commitment
    }

    /// Returns a reference to the [`FeeParameters`] in this header.
    pub fn fee_parameters(&self) -> &FeeParameters {
        &self.fee_parameters
    }

    /// Returns the timestamp at which the block was created, in seconds since UNIX epoch.
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Returns the block number of the epoch block to which this block belongs.
    pub fn epoch_block_num(&self) -> BlockNumber {
        BlockNumber::from_epoch(self.block_epoch())
    }

    // VALIDATION
    // --------------------------------------------------------------------------------------------

    /// Validates that `parent` precedes and authorizes this block.
    ///
    /// The `signatures` are positional with respect to the validator set committed to by `parent`
    /// (see [`ValidatorKeys`]): the signature at index `i` must verify against the parent's
    /// validator key at index `i`. Every validator in the parent's set must have signed.
    ///
    /// # Errors
    ///
    /// Returns an error if the block is the genesis block (no parent), the parent's number or
    /// commitment do not match, the number of signatures does not match the parent's validator
    /// count, or a signature does not verify against its validator key.
    pub(crate) fn validate_against_parent(
        &self,
        parent: &BlockHeader,
        signatures: &BlockSignatures,
    ) -> Result<(), ParentValidationError> {
        // Block 0 does not have a parent.
        let Some(expected_parent_num) = self.block_num().checked_sub(1) else {
            return Err(ParentValidationError::GenesisBlockHasNoParent {
                parent: parent.block_num(),
            });
        };

        // Check block numbers.
        if expected_parent_num != parent.block_num() {
            return Err(ParentValidationError::ParentNumberMismatch {
                expected: expected_parent_num,
                parent: parent.block_num(),
            });
        }

        // Check commitments.
        let expected_prev_commitment = self.prev_block_commitment();
        if expected_prev_commitment != parent.commitment() {
            return Err(ParentValidationError::ParentCommitmentMismatch {
                expected: expected_prev_commitment,
                parent: parent.commitment(),
            });
        }

        // Verify the signatures positionally against the parent's validator set using the shared,
        // canonical verifier, which also enforces that every validator signed.
        signatures
            .verify_against(self.commitment(), parent.validator_keys())
            .map_err(|err| match err {
                SignatureVerificationError::SignatureCountMismatch { expected, actual } => {
                    ParentValidationError::SignatureCountMismatch { expected, actual }
                },
                SignatureVerificationError::InvalidSignatureAtPosition { position } => {
                    ParentValidationError::InvalidSignatureAtPosition { position }
                },
            })?;

        Ok(())
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Computes the sub commitment of the block header.
    ///
    /// The sub commitment is computed as a sequential hash of the following fields:
    /// `prev_block_commitment`, `chain_commitment`, `account_root`, `nullifier_root`, `note_root`,
    /// `tx_commitment`, `tx_kernel_commitment`, `validator_keys_commitment`, `version`,
    /// `timestamp`, `block_num`, `fee_faucet_id`, `verification_base_fee` (all fields except
    /// the `note_root`).
    #[allow(clippy::too_many_arguments)]
    fn compute_sub_commitment(
        version: u32,
        prev_block_commitment: Word,
        chain_commitment: Word,
        account_root: Word,
        nullifier_root: Word,
        tx_commitment: Word,
        tx_kernel_commitment: Word,
        validator_keys: &ValidatorKeys,
        fee_parameters: &FeeParameters,
        timestamp: u32,
        block_num: BlockNumber,
    ) -> Word {
        let mut elements: Vec<Felt> = Vec::with_capacity(40);
        elements.extend_from_slice(prev_block_commitment.as_elements());
        elements.extend_from_slice(chain_commitment.as_elements());
        elements.extend_from_slice(account_root.as_elements());
        elements.extend_from_slice(nullifier_root.as_elements());
        elements.extend_from_slice(tx_commitment.as_elements());
        elements.extend_from_slice(tx_kernel_commitment.as_elements());
        elements.extend(validator_keys.commitment());
        elements.extend([block_num.into(), Felt::from(version), Felt::from(timestamp), ZERO]);
        elements.extend([
            ZERO,
            Felt::from(fee_parameters.verification_base_fee()),
            fee_parameters.fee_faucet_id().suffix(),
            fee_parameters.fee_faucet_id().prefix().as_felt(),
        ]);
        elements.extend([ZERO, ZERO, ZERO, ZERO]);
        Hasher::hash_elements(&elements)
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Builds a minimal block header with a controllable block number, previous-block commitment,
    /// and validator key set.
    ///
    /// The remaining roots are zeroed except the note root and transaction commitment, which match
    /// the empty [`BlockBody`](super::BlockBody) the block tests pair this header with, so the
    /// self-consistency checks in `SignedBlock::validate` and  `ProvenBlock::validate` pass.
    #[cfg(test)]
    pub(crate) fn new_dummy(
        block_num: u32,
        prev_block_commitment: Word,
        validator_keys: ValidatorKeys,
    ) -> Self {
        use crate::block::{BlockBody, FeeParameters};
        use crate::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
        use crate::transaction::OrderedTransactionHeaders;

        let body = BlockBody::new_unchecked(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            OrderedTransactionHeaders::new_unchecked(Vec::new()),
        );
        let note_root = body.compute_block_note_tree().root();
        let tx_commitment = body.transactions().commitment();

        let fee_parameters =
            FeeParameters::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 500);
        BlockHeader::new(
            0,
            prev_block_commitment,
            BlockNumber::from(block_num),
            Word::empty(),
            Word::empty(),
            Word::empty(),
            note_root,
            tx_commitment,
            Word::empty(),
            validator_keys,
            fee_parameters,
            0,
        )
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for BlockHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self {
            version,
            prev_block_commitment,
            block_num,
            chain_commitment,
            account_root,
            nullifier_root,
            note_root,
            tx_commitment,
            tx_kernel_commitment,
            validator_keys,
            fee_parameters,
            timestamp,
            // Don't serialize sub commitment and commitment as they can be derived.
            sub_commitment: _,
            commitment: _,
        } = self;

        version.write_into(target);
        prev_block_commitment.write_into(target);
        block_num.write_into(target);
        chain_commitment.write_into(target);
        account_root.write_into(target);
        nullifier_root.write_into(target);
        note_root.write_into(target);
        tx_commitment.write_into(target);
        tx_kernel_commitment.write_into(target);
        validator_keys.write_into(target);
        fee_parameters.write_into(target);
        timestamp.write_into(target);
    }
}

impl Deserializable for BlockHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read()?;
        let prev_block_commitment = source.read()?;
        let block_num = source.read()?;
        let chain_commitment = source.read()?;
        let account_root = source.read()?;
        let nullifier_root = source.read()?;
        let note_root = source.read()?;
        let tx_commitment = source.read()?;
        let tx_kernel_commitment = source.read()?;
        let validator_keys = source.read()?;
        let fee_parameters = source.read()?;
        let timestamp = source.read()?;

        Ok(Self::new(
            version,
            prev_block_commitment,
            block_num,
            chain_commitment,
            account_root,
            nullifier_root,
            note_root,
            tx_commitment,
            tx_kernel_commitment,
            validator_keys,
            fee_parameters,
            timestamp,
        ))
    }
}

// FEE PARAMETERS
// ================================================================================================

/// The fee-related parameters of a block.
///
/// This defines how to compute the fees of a transaction and which asset fees can be paid in.
///
/// The fee asset is assumed to be a fungible asset
/// ([`AssetComposition::Fungible`](crate::asset::AssetComposition::Fungible)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeParameters {
    /// The [`AccountId`] of the faucet whose assets are accepted for fee payments in the
    /// transaction kernel, or in other words, the fee faucet of the blockchain.
    fee_faucet_id: AccountId,

    /// The base fee (in base units) capturing the cost for the verification of a transaction.
    verification_base_fee: u32,
}

impl FeeParameters {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates [`FeeParameters`] from the provided inputs.
    pub fn new(fee_faucet_id: AccountId, verification_base_fee: u32) -> Self {
        Self { fee_faucet_id, verification_base_fee }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountId`] of the faucet whose assets are accepted for fee payments in the
    /// transaction kernel, or in other words, the fee faucet of the blockchain.
    pub fn fee_faucet_id(&self) -> AccountId {
        self.fee_faucet_id
    }

    /// Returns the base fee capturing the cost for the verification of a transaction.
    pub fn verification_base_fee(&self) -> u32 {
        self.verification_base_fee
    }
}

impl Serializable for FeeParameters {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.fee_faucet_id.write_into(target);
        self.verification_base_fee.write_into(target);
    }
}

impl Deserializable for FeeParameters {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let fee_faucet_id = source.read()?;
        let verification_base_fee = source.read()?;

        Ok(Self::new(fee_faucet_id, verification_base_fee))
    }
}

// PARENT VALIDATION ERROR
// ================================================================================================

/// Error returned when a block fails validation against its parent block.
///
/// This is the shared, block-type-agnostic error produced by
/// [`BlockHeader::validate_against_parent`]. Each block type maps it into its own error enum via
/// `From`, which preserves that type's specific error messages.
#[derive(Debug)]
pub(crate) enum ParentValidationError {
    SignatureCountMismatch {
        expected: usize,
        actual: usize,
    },
    InvalidSignatureAtPosition {
        position: usize,
    },
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::Word;
    use miden_crypto::rand::test_utils::rand_value;

    use super::*;
    use crate::testing::validator_keys::{random_validator_set, sign_all};

    #[test]
    fn test_serde() {
        let chain_commitment = rand_value::<Word>();
        let note_root = rand_value::<Word>();
        let tx_kernel_commitment = rand_value::<Word>();
        let header = BlockHeader::mock(
            0,
            Some(chain_commitment),
            Some(note_root),
            &[],
            tx_kernel_commitment,
        );
        let serialized = header.to_bytes();
        let deserialized = BlockHeader::read_from_bytes(&serialized).unwrap();

        assert_eq!(deserialized, header);
    }

    /// Builds a child of `parent` committing a fresh validator set of `next_count` validators as
    /// the signer of the *next* block.
    fn child_of(parent: &BlockHeader, child_num: u32, next_count: usize) -> BlockHeader {
        let (_, next_keys) = random_validator_set(next_count);
        BlockHeader::new_dummy(child_num, parent.commitment(), next_keys)
    }

    #[test]
    fn validate_against_parent_accepts_all_signatures() {
        let (signers, keys) = random_validator_set(5);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        let child = child_of(&parent, 1, 5);
        let signatures = sign_all(&keys, &signers, child.commitment());

        child.validate_against_parent(&parent, &signatures).unwrap();
    }

    #[test]
    fn validate_against_parent_accepts_single_validator() {
        let (signers, keys) = random_validator_set(1);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        let child = child_of(&parent, 1, 1);
        let signatures = sign_all(&keys, &signers, child.commitment());

        child.validate_against_parent(&parent, &signatures).unwrap();
    }

    #[test]
    fn validate_against_parent_rejects_incomplete_signatures() {
        let (signers, keys) = random_validator_set(3);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        let child = child_of(&parent, 1, 3);
        // Only one of three validators signs, so the resulting set is too short to align
        // positionally with the parent's validator keys. `BlockSignatures::new` does not check
        // this -- only `verify_against` (called by `validate_against_parent`) does.
        let signatures = BlockSignatures::new(alloc::vec![signers[0].sign(child.commitment())]);

        let result = child.validate_against_parent(&parent, &signatures);
        assert!(matches!(
            result,
            Err(ParentValidationError::SignatureCountMismatch { expected: 3, actual: 1 })
        ));
    }

    #[test]
    fn validate_against_parent_rejects_signature_count_mismatch() {
        let (_, keys) = random_validator_set(3);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        let child = child_of(&parent, 1, 3);

        // A block signed by a validator set of a different size cannot align positionally with the
        // parent's committed set. Deserialization does not check this, so build it directly.
        let (other_signers, other_keys) = random_validator_set(4);
        let signatures = sign_all(&other_keys, &other_signers, child.commitment());
        let bytes = signatures.to_bytes();
        let deserialized = BlockSignatures::read_from_bytes(&bytes).unwrap();

        let result = child.validate_against_parent(&parent, &deserialized);
        assert!(matches!(
            result,
            Err(ParentValidationError::SignatureCountMismatch { expected: 3, actual: 4 })
        ));
    }

    #[test]
    fn validate_against_parent_rejects_uncommitted_signatures() {
        let (_, keys) = random_validator_set(3);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        let child = child_of(&parent, 1, 3);

        // The child is signed by a full, valid validator set of the same size the parent never
        // committed, so the signatures do not verify against the parent's validator keys.
        let (impostor_signers, impostor_keys) = random_validator_set(3);
        let signatures = sign_all(&impostor_keys, &impostor_signers, child.commitment());

        let result = child.validate_against_parent(&parent, &signatures);
        assert!(matches!(result, Err(ParentValidationError::InvalidSignatureAtPosition { .. })));
    }

    #[test]
    fn validate_against_parent_rejects_genesis() {
        let (signers, keys) = random_validator_set(3);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        // Block 0 has no parent to anchor against.
        let child = BlockHeader::new_dummy(0, parent.commitment(), random_validator_set(3).1);
        let signatures = sign_all(&keys, &signers, child.commitment());

        let result = child.validate_against_parent(&parent, &signatures);
        assert!(matches!(result, Err(ParentValidationError::GenesisBlockHasNoParent { .. })));
    }

    #[test]
    fn validate_against_parent_rejects_wrong_parent_number() {
        let (signers, keys) = random_validator_set(3);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        // Child claims to be block 2, but the parent is block 0.
        let child = child_of(&parent, 2, 3);
        let signatures = sign_all(&keys, &signers, child.commitment());

        let result = child.validate_against_parent(&parent, &signatures);
        assert!(matches!(result, Err(ParentValidationError::ParentNumberMismatch { .. })));
    }

    #[test]
    fn validate_against_parent_rejects_wrong_parent_commitment() {
        let (signers, keys) = random_validator_set(3);
        let parent = BlockHeader::new_dummy(0, Word::empty(), keys.clone());
        // Child does not link to the parent's commitment.
        let child = BlockHeader::new_dummy(1, Word::empty(), random_validator_set(3).1);
        let signatures = sign_all(&keys, &signers, child.commitment());

        let result = child.validate_against_parent(&parent, &signatures);
        assert!(matches!(result, Err(ParentValidationError::ParentCommitmentMismatch { .. })));
    }
}
