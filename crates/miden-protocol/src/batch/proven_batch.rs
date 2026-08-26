use alloc::collections::btree_map::Entry;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::account::AccountId;
use crate::batch::{BatchAccountUpdate, BatchId};
use crate::block::BlockNumber;
use crate::errors::ProvenBatchError;
use crate::note::Nullifier;
use crate::transaction::{
    InputNoteCommitment,
    InputNotes,
    OrderedTransactionHeaders,
    OutputNote,
    TransactionHeader,
    TransactionHeaderNoteAggregationError,
};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::vm::ExecutionProof;
use crate::{
    MAX_ACCOUNTS_PER_BATCH,
    MAX_INPUT_NOTES_PER_BATCH,
    MAX_OUTPUT_NOTES_PER_BATCH,
    MIN_PROOF_SECURITY_LEVEL,
    Word,
};

/// A transaction batch with an execution proof.
/// Currently, this only carries a skeleton proof which does not attest to anything meaningful.
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
    proof: ExecutionProof,
}

impl ProvenBatch {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`ProvenBatch`] from the provided parts and validates its structural
    /// consistency.
    ///
    /// This verifies that the account updates form the state transitions described by the
    /// [`TransactionHeader`]s and that the input and output notes are their correctly aggregated
    /// note sets, including in-batch note erasure.
    ///
    /// This does not verify the execution proof, per-transaction reference blocks or expiration
    /// block numbers, or note inclusion proofs. Those checks require data which is not present in
    /// a [`TransactionHeader`] and must be performed before constructing the proven batch or by a
    /// batch verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if any structural limit or invariant is violated, or if the aggregate
    /// account updates and notes do not match the transaction headers.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reference_block_commitment: Word,
        reference_block_num: BlockNumber,
        account_updates: impl IntoIterator<Item = BatchAccountUpdate>,
        input_notes: InputNotes<InputNoteCommitment>,
        output_notes: Vec<OutputNote>,
        batch_expiration_block_num: BlockNumber,
        transactions: OrderedTransactionHeaders,
        proof: ExecutionProof,
    ) -> Result<Self, ProvenBatchError> {
        if transactions.as_slice().is_empty() {
            return Err(ProvenBatchError::EmptyTransactionBatch);
        }
        let mut transaction_ids = BTreeSet::new();
        for transaction in transactions.as_slice() {
            if !transaction_ids.insert(transaction.id()) {
                return Err(ProvenBatchError::DuplicateTransaction(transaction.id()));
            }
        }
        let mut account_updates_by_id = BTreeMap::new();
        for (index, update) in account_updates.into_iter().enumerate() {
            let account_update_count = index + 1;
            if account_update_count > MAX_ACCOUNTS_PER_BATCH {
                return Err(ProvenBatchError::TooManyAccountUpdates(account_update_count));
            }

            let account_id = update.account_id();
            if account_updates_by_id.insert(account_id, update).is_some() {
                return Err(ProvenBatchError::DuplicateAccountUpdate(account_id));
            }
        }
        let input_note_count = usize::from(input_notes.num_notes());
        if input_note_count > MAX_INPUT_NOTES_PER_BATCH {
            return Err(ProvenBatchError::TooManyInputNotes(input_note_count));
        }
        if output_notes.len() > MAX_OUTPUT_NOTES_PER_BATCH {
            return Err(ProvenBatchError::TooManyOutputNotes(output_notes.len()));
        }

        validate_account_updates(&account_updates_by_id, transactions.as_slice())?;
        validate_aggregate_notes(&input_notes, &output_notes, &transactions)?;

        let id =
            BatchId::from_ids(transactions.as_slice().iter().map(|tx| (tx.id(), tx.account_id())));
        Self::new_unchecked(
            id,
            reference_block_commitment,
            reference_block_num,
            account_updates_by_id,
            input_notes,
            output_notes,
            batch_expiration_block_num,
            transactions,
            proof,
        )
    }

    /// Creates a new [`ProvenBatch`] from the provided parts without checking any constraints
    /// except the expiration constraint listed below.
    ///
    /// Callers must ensure that the batch satisfies the structural constraints checked by
    /// [`ProvenBatch::new`].
    ///
    /// # Errors
    ///
    /// Returns an error if the batch expiration block number is not greater than the reference
    /// block number.
    #[allow(clippy::too_many_arguments)]
    pub fn new_unchecked(
        id: BatchId,
        reference_block_commitment: Word,
        reference_block_num: BlockNumber,
        account_updates: BTreeMap<AccountId, BatchAccountUpdate>,
        input_notes: InputNotes<InputNoteCommitment>,
        output_notes: Vec<OutputNote>,
        batch_expiration_block_num: BlockNumber,
        transactions: OrderedTransactionHeaders,
        proof: ExecutionProof,
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
            proof,
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

    /// Returns the execution proof attached to this batch.
    pub fn proof(&self) -> &ExecutionProof {
        &self.proof
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Consumes self and returns the contained [`OrderedTransactionHeaders`] of this batch.
    pub fn into_transactions(self) -> OrderedTransactionHeaders {
        self.transactions
    }
}

// VALIDATION HELPERS
// ================================================================================================

fn validate_account_updates(
    account_updates: &BTreeMap<AccountId, BatchAccountUpdate>,
    transactions: &[TransactionHeader],
) -> Result<(), ProvenBatchError> {
    let mut expected_updates = BTreeMap::<AccountId, (Word, Word)>::new();

    for transaction in transactions {
        match expected_updates.entry(transaction.account_id()) {
            Entry::Vacant(entry) => {
                entry.insert((
                    transaction.initial_state_commitment(),
                    transaction.final_state_commitment(),
                ));
            },
            Entry::Occupied(mut entry) => {
                let (_, previous_final_state_commitment) = entry.get_mut();
                if *previous_final_state_commitment != transaction.initial_state_commitment() {
                    return Err(ProvenBatchError::TransactionAccountStateMismatch {
                        account_id: transaction.account_id(),
                        transaction_id: transaction.id(),
                        expected_initial_state_commitment: *previous_final_state_commitment,
                        actual_initial_state_commitment: transaction.initial_state_commitment(),
                    });
                }
                *previous_final_state_commitment = transaction.final_state_commitment();
            },
        }
    }

    for (account_id, (expected_initial, expected_final)) in &expected_updates {
        let update = account_updates
            .get(account_id)
            .ok_or(ProvenBatchError::MissingAccountUpdate(*account_id))?;

        if update.initial_state_commitment() != *expected_initial {
            return Err(ProvenBatchError::AccountUpdateInitialStateMismatch {
                account_id: *account_id,
                expected: *expected_initial,
                actual: update.initial_state_commitment(),
            });
        }
        if update.final_state_commitment() != *expected_final {
            return Err(ProvenBatchError::AccountUpdateFinalStateMismatch {
                account_id: *account_id,
                expected: *expected_final,
                actual: update.final_state_commitment(),
            });
        }
    }

    if let Some(account_id) = account_updates
        .keys()
        .find(|account_id| !expected_updates.contains_key(account_id))
    {
        return Err(ProvenBatchError::UnexpectedAccountUpdate(*account_id));
    }

    Ok(())
}

fn validate_aggregate_notes(
    input_notes: &InputNotes<InputNoteCommitment>,
    output_notes: &[OutputNote],
    transactions: &OrderedTransactionHeaders,
) -> Result<(), ProvenBatchError> {
    let expected_notes = transactions.aggregate_notes().map_err(|error| match error {
        TransactionHeaderNoteAggregationError::DuplicateInputNote(nullifier) => {
            ProvenBatchError::DuplicateInputNote(nullifier)
        },
        TransactionHeaderNoteAggregationError::DuplicateOutputNote(note_id) => {
            ProvenBatchError::DuplicateOutputNote(note_id)
        },
        TransactionHeaderNoteAggregationError::NoteCreatedAndConsumed(note_id) => {
            ProvenBatchError::NoteCreatedAndConsumed(note_id)
        },
        TransactionHeaderNoteAggregationError::NoteConsumedBeforeCreated(note_id) => {
            ProvenBatchError::NoteConsumedBeforeCreated(note_id)
        },
    })?;

    let inputs_match = usize::from(input_notes.num_notes()) == expected_notes.input_notes().len()
        && input_notes.iter().zip(expected_notes.input_notes().values()).all(
            |(actual, expected)| {
                actual.nullifier() == expected.nullifier()
                    && match (actual.header(), expected.header()) {
                        (None, Some(_)) | (None, None) => true,
                        (Some(actual), Some(expected)) => actual == expected,
                        (Some(_), None) => false,
                    }
            },
        );
    if !inputs_match {
        return Err(ProvenBatchError::InputNotesMismatch);
    }

    let outputs_match = output_notes.len() == expected_notes.output_notes().len()
        && output_notes
            .iter()
            .zip(expected_notes.output_notes().values())
            .all(|(actual, expected)| <&crate::note::NoteHeader>::from(actual) == expected);
    if !outputs_match {
        return Err(ProvenBatchError::OutputNotesMismatch);
    }

    Ok(())
}

// SERIALIZATION
// ================================================================================================

impl Serializable for ProvenBatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.reference_block_commitment.write_into(target);
        self.reference_block_num.write_into(target);
        self.account_updates.write_into(target);
        self.input_notes.write_into(target);
        self.output_notes.write_into(target);
        self.batch_expiration_block_num.write_into(target);
        self.transactions.write_into(target);
        self.proof.write_into(target);
    }
}

impl Deserializable for ProvenBatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let reference_block_commitment = Word::read_from(source)?;
        let reference_block_num = BlockNumber::read_from(source)?;
        let account_updates = BTreeMap::<AccountId, BatchAccountUpdate>::read_from(source)?;
        let input_notes = InputNotes::<InputNoteCommitment>::read_from(source)?;
        let output_notes = Vec::<OutputNote>::read_from(source)?;
        let batch_expiration_block_num = BlockNumber::read_from(source)?;
        let transactions = OrderedTransactionHeaders::read_from(source)?;
        let proof = ExecutionProof::read_from(source)?;

        Self::new(
            reference_block_commitment,
            reference_block_num,
            account_updates.into_values(),
            input_notes,
            output_notes,
            batch_expiration_block_num,
            transactions,
            proof,
        )
        .map_err(|e| DeserializationError::UnknownError(e.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::ProvenBatch;
    use crate::account::{AccountId, AccountType, AccountUpdateDetails};
    use crate::batch::{BatchAccountUpdate, BatchId};
    use crate::block::BlockNumber;
    use crate::errors::ProvenBatchError;
    use crate::note::{Note, NoteHeader, NoteId};
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        AccountIdBuilder,
    };
    use crate::transaction::{
        InputNoteCommitment,
        InputNotes,
        OrderedTransactionHeaders,
        OutputNote,
        RawOutputNote,
        TransactionHeader,
    };
    use crate::utils::serde::{Deserializable, DeserializationError, Serializable};
    use crate::vm::ExecutionProof;
    use crate::{MAX_ACCOUNTS_PER_BATCH, Word};

    fn account_id() -> AccountId {
        AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap()
    }

    fn transaction_header(
        initial_state_commitment: Word,
        final_state_commitment: Word,
        input_notes: InputNotes<InputNoteCommitment>,
        output_notes: Vec<NoteHeader>,
    ) -> TransactionHeader {
        TransactionHeader::new(
            account_id(),
            initial_state_commitment,
            final_state_commitment,
            input_notes,
            output_notes,
        )
        .unwrap()
    }

    fn transaction_headers() -> OrderedTransactionHeaders {
        let transaction = transaction_header(
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            InputNotes::default(),
            vec![],
        );

        OrderedTransactionHeaders::new_unchecked(vec![transaction])
    }

    fn private_account_update() -> BatchAccountUpdate {
        BatchAccountUpdate::new(
            account_id(),
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            AccountUpdateDetails::Private,
        )
        .unwrap()
    }

    fn private_account_update_for(account_id: AccountId) -> BatchAccountUpdate {
        BatchAccountUpdate::new(
            account_id,
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            AccountUpdateDetails::Private,
        )
        .unwrap()
    }

    fn conflicting_notes() -> (NoteId, InputNotes<InputNoteCommitment>, Vec<OutputNote>) {
        let note = Note::mock_noop(Word::empty());
        let note_id = note.id();
        let input_note =
            InputNoteCommitment::from_parts_unchecked(note.nullifier(), Some(*note.header()));
        let output_note = RawOutputNote::Full(note).into_output_note().unwrap();

        (note_id, InputNotes::new(vec![input_note]).unwrap(), vec![output_note])
    }

    fn transactions_with_conflicting_notes(
        input_notes: &InputNotes<InputNoteCommitment>,
        output_notes: &[OutputNote],
    ) -> (OrderedTransactionHeaders, BatchAccountUpdate) {
        let states = [
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            Word::from([9_u32, 10, 11, 12]),
        ];
        let output_note_headers =
            output_notes.iter().map(|note| *<&NoteHeader>::from(note)).collect();
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![
            transaction_header(states[0], states[1], input_notes.clone(), vec![]),
            transaction_header(states[1], states[2], InputNotes::default(), output_note_headers),
        ]);
        let update = BatchAccountUpdate::new(
            account_id(),
            states[0],
            states[2],
            AccountUpdateDetails::Private,
        )
        .unwrap();

        (transactions, update)
    }

    #[test]
    fn rejects_note_consumed_before_created_in_same_batch() {
        let (note_id, input_notes, output_notes) = conflicting_notes();
        let (transactions, update) =
            transactions_with_conflicting_notes(&input_notes, &output_notes);

        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![update],
            input_notes,
            output_notes,
            BlockNumber::from(2),
            transactions,
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        assert_matches!(error, ProvenBatchError::NoteConsumedBeforeCreated(id) if id == note_id);
    }

    #[test]
    fn derives_account_update_keys_from_updates() {
        let update = private_account_update();
        let account_id = update.account_id();

        let batch = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![update],
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transaction_headers(),
            ExecutionProof::new_dummy(),
        )
        .unwrap();

        assert_eq!(batch.account_updates().keys().copied().collect::<Vec<_>>(), vec![account_id]);
    }

    #[test]
    fn rejects_duplicate_account_updates() {
        let update = private_account_update();
        let account_id = update.account_id();

        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![update.clone(), update],
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transaction_headers(),
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        assert_matches!(error, ProvenBatchError::DuplicateAccountUpdate(id) if id == account_id);
    }

    #[test]
    fn rejects_too_many_account_updates_without_consuming_the_tail() {
        let mut next_index = 0_u64;
        let account_updates = core::iter::from_fn(move || {
            assert!(
                next_index <= MAX_ACCOUNTS_PER_BATCH as u64,
                "account update iterator was consumed past the batch limit"
            );

            let mut seed = [0_u8; 32];
            seed[..8].copy_from_slice(&next_index.to_le_bytes());
            next_index += 1;

            let account_id =
                AccountIdBuilder::new().account_type(AccountType::Private).build_with_seed(seed);
            Some(private_account_update_for(account_id))
        });

        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            account_updates,
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transaction_headers(),
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        assert_matches!(error, ProvenBatchError::TooManyAccountUpdates(_));
    }

    #[test]
    fn rejects_missing_account_update() {
        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            Vec::new(),
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transaction_headers(),
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        assert_matches!(error, ProvenBatchError::MissingAccountUpdate(id) if id == account_id());
    }

    #[test]
    fn rejects_unexpected_account_update() {
        let unexpected_account_id =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE).unwrap();

        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![private_account_update(), private_account_update_for(unexpected_account_id)],
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transaction_headers(),
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        assert_matches!(
            error,
            ProvenBatchError::UnexpectedAccountUpdate(id) if id == unexpected_account_id
        );
    }

    #[rstest]
    #[case::initial(true)]
    #[case::final_state(false)]
    fn rejects_account_update_commitment_mismatch(#[case] mismatch_initial: bool) {
        let expected_initial = Word::from([1_u32, 2, 3, 4]);
        let expected_final = Word::from([5_u32, 6, 7, 8]);
        let actual_initial = if mismatch_initial {
            Word::from([9_u32, 2, 3, 4])
        } else {
            expected_initial
        };
        let actual_final = if mismatch_initial {
            expected_final
        } else {
            Word::from([9_u32, 6, 7, 8])
        };
        let update = BatchAccountUpdate::new(
            account_id(),
            actual_initial,
            actual_final,
            AccountUpdateDetails::Private,
        )
        .unwrap();

        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![update],
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transaction_headers(),
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        if mismatch_initial {
            assert_matches!(
                error,
                ProvenBatchError::AccountUpdateInitialStateMismatch { account_id: id, .. }
                    if id == account_id()
            );
        } else {
            assert_matches!(
                error,
                ProvenBatchError::AccountUpdateFinalStateMismatch { account_id: id, .. }
                    if id == account_id()
            );
        }
    }

    #[test]
    fn rejects_non_chained_transaction_headers() {
        let initial = Word::from([1_u32, 2, 3, 4]);
        let intermediate = Word::from([5_u32, 6, 7, 8]);
        let unexpected = Word::from([9_u32, 10, 11, 12]);
        let final_state = Word::from([13_u32, 14, 15, 16]);
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![
            transaction_header(initial, intermediate, InputNotes::default(), vec![]),
            transaction_header(unexpected, final_state, InputNotes::default(), vec![]),
        ]);
        let update = BatchAccountUpdate::new(
            account_id(),
            initial,
            final_state,
            AccountUpdateDetails::Private,
        )
        .unwrap();

        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![update],
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transactions,
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        assert_matches!(
            error,
            ProvenBatchError::TransactionAccountStateMismatch { account_id: id, .. }
                if id == account_id()
        );
    }

    #[test]
    fn rejects_input_notes_missing_from_batch() {
        let note = Note::mock_noop(Word::empty());
        let input =
            InputNoteCommitment::from_parts_unchecked(note.nullifier(), Some(*note.header()));
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![transaction_header(
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            InputNotes::new(vec![input]).unwrap(),
            vec![],
        )]);

        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![private_account_update()],
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transactions,
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        assert_matches!(error, ProvenBatchError::InputNotesMismatch);
    }

    #[test]
    fn deserialization_rejects_note_consumed_before_created_in_same_batch() {
        let (note_id, input_notes, output_notes) = conflicting_notes();
        let (transactions, update) =
            transactions_with_conflicting_notes(&input_notes, &output_notes);
        let id =
            BatchId::from_ids(transactions.as_slice().iter().map(|tx| (tx.id(), tx.account_id())));
        let invalid_batch = ProvenBatch::new_unchecked(
            id,
            Word::empty(),
            BlockNumber::from(1),
            BTreeMap::from([(account_id(), update)]),
            input_notes,
            output_notes,
            BlockNumber::from(2),
            transactions,
            ExecutionProof::new_dummy(),
        )
        .unwrap();

        let error = ProvenBatch::read_from_bytes(&invalid_batch.to_bytes()).unwrap_err();

        assert_matches!(
            error,
            DeserializationError::UnknownError(message)
                if message
                    == format!(
                        "note with id {note_id} is consumed before it is created in the proven batch"
                    )
        );
    }

    #[test]
    fn rejects_unexpected_batch_output_note() {
        let (_, _, output_notes) = conflicting_notes();

        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![private_account_update()],
            InputNotes::default(),
            output_notes,
            BlockNumber::from(2),
            transaction_headers(),
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        assert_matches!(error, ProvenBatchError::OutputNotesMismatch);
    }

    #[test]
    fn rejects_output_note_missing_from_batch() {
        let note = Note::mock_noop(Word::empty());
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![transaction_header(
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            InputNotes::default(),
            vec![*note.header()],
        )]);

        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![private_account_update()],
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transactions,
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        assert_matches!(error, ProvenBatchError::OutputNotesMismatch);
    }

    #[test]
    fn rejects_duplicate_input_note_after_erasure() {
        let note = Note::mock_noop(Word::empty());
        let states = [
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            Word::from([9_u32, 10, 11, 12]),
            Word::from([13_u32, 14, 15, 16]),
        ];
        let input =
            InputNoteCommitment::from_parts_unchecked(note.nullifier(), Some(*note.header()));
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![
            transaction_header(states[0], states[1], InputNotes::default(), vec![*note.header()]),
            transaction_header(
                states[1],
                states[2],
                InputNotes::new(vec![input.clone()]).unwrap(),
                vec![],
            ),
            transaction_header(states[2], states[3], InputNotes::new(vec![input]).unwrap(), vec![]),
        ]);
        let update = BatchAccountUpdate::new(
            account_id(),
            states[0],
            states[3],
            AccountUpdateDetails::Private,
        )
        .unwrap();

        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![update],
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transactions,
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        assert_matches!(
            error,
            ProvenBatchError::DuplicateInputNote(nullifier) if nullifier == note.nullifier()
        );
    }

    #[test]
    fn rejects_duplicate_output_note_after_erasure() {
        let note = Note::mock_noop(Word::empty());
        let states = [
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            Word::from([9_u32, 10, 11, 12]),
            Word::from([13_u32, 14, 15, 16]),
        ];
        let input =
            InputNoteCommitment::from_parts_unchecked(note.nullifier(), Some(*note.header()));
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![
            transaction_header(states[0], states[1], InputNotes::default(), vec![*note.header()]),
            transaction_header(states[1], states[2], InputNotes::new(vec![input]).unwrap(), vec![]),
            transaction_header(states[2], states[3], InputNotes::default(), vec![*note.header()]),
        ]);
        let update = BatchAccountUpdate::new(
            account_id(),
            states[0],
            states[3],
            AccountUpdateDetails::Private,
        )
        .unwrap();

        let error = ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![update],
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transactions,
            ExecutionProof::new_dummy(),
        )
        .unwrap_err();

        assert_matches!(
            error,
            ProvenBatchError::DuplicateOutputNote(note_id) if note_id == note.id()
        );
    }

    #[test]
    fn accepts_in_order_note_erasure() {
        let note = Note::mock_noop(Word::empty());
        let initial = Word::from([1_u32, 2, 3, 4]);
        let intermediate = Word::from([5_u32, 6, 7, 8]);
        let final_state = Word::from([9_u32, 10, 11, 12]);
        let input =
            InputNoteCommitment::from_parts_unchecked(note.nullifier(), Some(*note.header()));
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![
            transaction_header(initial, intermediate, InputNotes::default(), vec![*note.header()]),
            transaction_header(
                intermediate,
                final_state,
                InputNotes::new(vec![input]).unwrap(),
                vec![],
            ),
        ]);
        let update = BatchAccountUpdate::new(
            account_id(),
            initial,
            final_state,
            AccountUpdateDetails::Private,
        )
        .unwrap();

        ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![update],
            InputNotes::default(),
            Vec::new(),
            BlockNumber::from(2),
            transactions,
            ExecutionProof::new_dummy(),
        )
        .unwrap();
    }

    #[test]
    fn accepts_authenticated_aggregate_input_note() {
        let note = Note::mock_noop(Word::empty());
        let header_input =
            InputNoteCommitment::from_parts_unchecked(note.nullifier(), Some(*note.header()));
        let transactions = OrderedTransactionHeaders::new_unchecked(vec![transaction_header(
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            InputNotes::new(vec![header_input]).unwrap(),
            vec![],
        )]);
        let batch_inputs =
            InputNotes::new(vec![InputNoteCommitment::from(note.nullifier())]).unwrap();

        ProvenBatch::new(
            Word::empty(),
            BlockNumber::from(1),
            vec![private_account_update()],
            batch_inputs,
            Vec::new(),
            BlockNumber::from(2),
            transactions,
            ExecutionProof::new_dummy(),
        )
        .unwrap();
    }
}
