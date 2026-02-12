use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::account::AccountId;
use crate::batch::{BatchAccountUpdate, BatchId};
use crate::block::BlockNumber;
use crate::errors::ProvenBatchError;
use crate::note::Nullifier;
use crate::transaction::{InputNoteCommitment, InputNotes, OrderedTransactionHeaders, OutputNote};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use crate::{MIN_PROOF_SECURITY_LEVEL, Word};

/// A transaction batch with an execution proof.
/// Currently, there is no proof attached. Future versions will extend this structure to include
/// a proof artifact once recursive proving is implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenBatch {
    id: BatchId,
    reference_block_commitment: Word,
    reference_block_num: BlockNumber,
    account_updates: BTreeMap<AccountId, BatchAccountUpdate>,
    input_notes: InputNotes<InputNoteCommitment>,
    output_notes: Vec<OutputNote>,
    batch_expiration_block_num: BlockNumber,
    transactions: OrderedTransactionHeaders,
}

impl ProvenBatch {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`ProvenBatch`] from the provided parts.
    ///
    /// # Errors
    ///
    /// Returns an error if the batch expiration block number is not greater than the reference
    /// block number.
    pub fn new(
        id: BatchId,
        reference_block_commitment: Word,
        reference_block_num: BlockNumber,
        account_updates: BTreeMap<AccountId, BatchAccountUpdate>,
        input_notes: InputNotes<InputNoteCommitment>,
        output_notes: Vec<OutputNote>,
        batch_expiration_block_num: BlockNumber,
        transactions: OrderedTransactionHeaders,
    ) -> Result<Self, ProvenBatchError> {
        // Check that the batch expiration block number is greater than the reference block number.
        if batch_expiration_block_num <= reference_block_num {
            return Err(ProvenBatchError::InvalidBatchExpirationBlockNum {
                batch_expiration_block_num,
                reference_block_num,
            });
        }

        Ok(Self {
            id,
            reference_block_commitment,
            reference_block_num,
            account_updates,
            input_notes,
            output_notes,
            batch_expiration_block_num,
            transactions,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// The ID of this batch. See [`BatchId`] for details on how it is computed.
    pub fn id(&self) -> BatchId {
        self.id
    }

    /// Returns the commitment to the reference block of the batch.
    pub fn reference_block_commitment(&self) -> Word {
        self.reference_block_commitment
    }

    /// Returns the number of the reference block of the batch.
    pub fn reference_block_num(&self) -> BlockNumber {
        self.reference_block_num
    }

    /// Returns the block number at which the batch will expire.
    pub fn batch_expiration_block_num(&self) -> BlockNumber {
        self.batch_expiration_block_num
    }

    /// Returns an iterator over the IDs of all accounts updated in this batch.
    pub fn updated_accounts(&self) -> impl Iterator<Item = AccountId> + use<'_> {
        self.account_updates.keys().copied()
    }

    /// Returns the proof security level of the batch.
    pub fn proof_security_level(&self) -> u32 {
        MIN_PROOF_SECURITY_LEVEL
    }

    /// Returns the map of account IDs mapped to their [`BatchAccountUpdate`]s.
    ///
    /// If an account was updated by multiple transactions, the [`BatchAccountUpdate`] is the result
    /// of merging the individual updates.
    ///
    /// For example, suppose an account's state before this batch is `A` and the batch contains two
    /// transactions that updated it. Applying the first transaction results in intermediate state
    /// `B`, and applying the second one results in state `C`. Then the returned update represents
    /// the state transition from `A` to `C`.
    pub fn account_updates(&self) -> &BTreeMap<AccountId, BatchAccountUpdate> {
        &self.account_updates
    }

    /// Returns the [`InputNotes`] of this batch.
    pub fn input_notes(&self) -> &InputNotes<InputNoteCommitment> {
        &self.input_notes
    }

    /// Returns an iterator over the nullifiers created in this batch.
    pub fn created_nullifiers(&self) -> impl Iterator<Item = Nullifier> + use<'_> {
        self.input_notes.iter().map(InputNoteCommitment::nullifier)
    }

    /// Returns the output notes of the batch.
    ///
    /// This is the aggregation of all output notes by the transactions in the batch, except the
    /// ones that were consumed within the batch itself.
    pub fn output_notes(&self) -> &[OutputNote] {
        &self.output_notes
    }

    /// Returns the [`OrderedTransactionHeaders`] included in this batch.
    pub fn transactions(&self) -> &OrderedTransactionHeaders {
        &self.transactions
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Consumes self and returns the contained [`OrderedTransactionHeaders`] of this batch.
    pub fn into_transactions(self) -> OrderedTransactionHeaders {
        self.transactions
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for ProvenBatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.id.write_into(target);
        self.reference_block_commitment.write_into(target);
        self.reference_block_num.write_into(target);
        self.account_updates.write_into(target);
        self.input_notes.write_into(target);
        self.output_notes.write_into(target);
        self.batch_expiration_block_num.write_into(target);
        self.transactions.write_into(target);
    }
}

impl Deserializable for ProvenBatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let id = BatchId::read_from(source)?;
        let reference_block_commitment = Word::read_from(source)?;
        let reference_block_num = BlockNumber::read_from(source)?;
        let account_updates = BTreeMap::read_from(source)?;
        let input_notes = InputNotes::<InputNoteCommitment>::read_from(source)?;
        let output_notes = Vec::<OutputNote>::read_from(source)?;
        let batch_expiration_block_num = BlockNumber::read_from(source)?;
        let transactions = OrderedTransactionHeaders::read_from(source)?;

        Self::new(
            id,
            reference_block_commitment,
            reference_block_num,
            account_updates,
            input_notes,
            output_notes,
            batch_expiration_block_num,
            transactions,
        )
        .map_err(|e| DeserializationError::UnknownError(e.to_string()))
    }
}
