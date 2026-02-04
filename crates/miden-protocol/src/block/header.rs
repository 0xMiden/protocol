use alloc::string::ToString;
use alloc::vec::Vec;

use crate::account::{AccountId, AccountType};
use crate::block::BlockNumber;
use crate::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use crate::errors::FeeError;
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
/// - `validator_key` is the public key of the validator that is expected to sign the block.
/// - `fee_parameters` are the parameters defining the base fees and the native asset, see
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
    validator_key: PublicKey,
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
        validator_key: PublicKey,
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
            &validator_key,
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
            validator_key,
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

    /// Returns the public key of the block's validator.
    pub fn validator_key(&self) -> &PublicKey {
        &self.validator_key
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

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Computes the sub commitment of the block header.
    ///
    /// The sub commitment is computed as a sequential hash of the following fields:
    /// `prev_block_commitment`, `chain_commitment`, `account_root`, `nullifier_root`, `note_root`,
    /// `tx_commitment`, `tx_kernel_commitment`, `validator_key_commitment`, `version`, `timestamp`,
    /// `block_num`, `native_asset_id`, `verification_base_fee` (all fields except the `note_root`).
    #[allow(clippy::too_many_arguments)]
    fn compute_sub_commitment(
        version: u32,
        prev_block_commitment: Word,
        chain_commitment: Word,
        account_root: Word,
        nullifier_root: Word,
        tx_commitment: Word,
        tx_kernel_commitment: Word,
        validator_key: &PublicKey,
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
        elements.extend(validator_key.to_commitment());
        elements.extend([block_num.into(), version.into(), timestamp.into(), ZERO]);
        elements.extend([
            fee_parameters.native_asset_id().suffix(),
            fee_parameters.native_asset_id().prefix().as_felt(),
            fee_parameters.verification_base_fee().into(),
            ZERO,
        ]);
        elements.extend([ZERO, ZERO, ZERO, ZERO]);
        Hasher::hash_elements(&elements)
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
            validator_key,
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
        validator_key.write_into(target);
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
        let validator_key = source.read()?;
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
            validator_key,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeParameters {
    /// The [`AccountId`] of the fungible faucet whose assets are accepted for fee payments in the
    /// transaction kernel, or in other words, the native asset of the blockchain.
    native_asset_id: AccountId,
    /// The base fee (in base units) capturing the cost for the verification of a transaction.
    verification_base_fee: u32,
}

impl FeeParameters {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`FeeParameters`] from the provided inputs.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided native asset ID is not a fungible faucet account ID.
    pub fn new(native_asset_id: AccountId, verification_base_fee: u32) -> Result<Self, FeeError> {
        if !matches!(native_asset_id.account_type(), AccountType::FungibleFaucet) {
            return Err(FeeError::NativeAssetIdNotFungible {
                account_type: native_asset_id.account_type(),
            });
        }

        Ok(Self { native_asset_id, verification_base_fee })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountId`] of the faucet whose assets are accepted for fee payments in the
    /// transaction kernel, or in other words, the native asset of the blockchain.
    pub fn native_asset_id(&self) -> AccountId {
        self.native_asset_id
    }

    /// Returns the base fee capturing the cost for the verification of a transaction.
    pub fn verification_base_fee(&self) -> u32 {
        self.verification_base_fee
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for FeeParameters {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.native_asset_id.write_into(target);
        self.verification_base_fee.write_into(target);
    }
}

impl Deserializable for FeeParameters {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let native_asset_id = source.read()?;
        let verification_base_fee = source.read()?;

        Self::new(native_asset_id, verification_base_fee)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_core::Word;
    use winter_rand_utils::rand_value;

    use super::*;
    use crate::testing::account_id::ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET;

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

    /// Tests that the fee parameters constructor fails when the provided account ID is not a
    /// fungible faucet.
    #[test]
    fn fee_parameters_fail_when_native_asset_is_not_fungible() {
        assert_matches!(
            FeeParameters::new(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into().unwrap(), 0)
                .unwrap_err(),
            FeeError::NativeAssetIdNotFungible { .. }
        );
    }
}
