use alloc::vec::Vec;

use miden_processor::DeserializationError;

use crate::Word;
use crate::asset::FungibleAsset;
use crate::note::NoteHeader;
use crate::transaction::{
    AccountId,
    ExecutedTransaction,
    InputNoteCommitment,
    InputNotes,
    OutputNote,
    OutputNotes,
    ProvenTransaction,
    TransactionId,
};
use crate::utils::{ByteReader, ByteWriter, Deserializable, Serializable};

/// A transaction header derived from a
/// [`ProvenTransaction`](crate::transaction::ProvenTransaction).
///
/// The header is essentially a direct copy of the transaction's commitments, in particular the
/// initial and final account state commitment as well as all nullifiers of consumed notes and all
/// note IDs of created notes. While account updates may be aggregated and notes may be erased as
/// part of batch and block building, the header retains the original transaction's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionHeader {
    id: TransactionId,
    account_id: AccountId,
    initial_state_commitment: Word,
    final_state_commitment: Word,
    input_notes: InputNotes<InputNoteCommitment>,
    output_notes: Vec<NoteHeader>,
    fee: FungibleAsset,
}

impl TransactionHeader {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a new [`TransactionHeader`] from the provided parameters.
    ///
    /// The [`TransactionId`] is computed from the provided parameters.
    ///
    /// The input notes and output notes must be in the same order as they appeared in the
    /// transaction that this header represents, otherwise an incorrect ID will be computed.
    ///
    /// Note that this cannot validate that the [`AccountId`] or the fee asset is valid with respect
    /// to the other data. This must be validated outside of this type.
    pub fn new(
        account_id: AccountId,
        initial_state_commitment: Word,
        final_state_commitment: Word,
        input_notes: InputNotes<InputNoteCommitment>,
        output_notes: Vec<NoteHeader>,
        fee: FungibleAsset,
    ) -> Self {
        let input_notes_commitment = input_notes.commitment();
        let output_notes_commitment = OutputNotes::compute_commitment(output_notes.iter());

        let id = TransactionId::new(
            initial_state_commitment,
            final_state_commitment,
            input_notes_commitment,
            output_notes_commitment,
        );

        Self {
            id,
            account_id,
            initial_state_commitment,
            final_state_commitment,
            input_notes,
            output_notes,
            fee,
        }
    }

    /// Constructs a new [`TransactionHeader`] from the provided parameters.
    ///
    /// # Warning
    ///
    /// This does not validate the internal consistency of the data. Prefer [`Self::new`] whenever
    /// possible.
    pub fn new_unchecked(
        id: TransactionId,
        account_id: AccountId,
        initial_state_commitment: Word,
        final_state_commitment: Word,
        input_notes: InputNotes<InputNoteCommitment>,
        output_notes: Vec<NoteHeader>,
        fee: FungibleAsset,
    ) -> Self {
        Self {
            id,
            account_id,
            initial_state_commitment,
            final_state_commitment,
            input_notes,
            output_notes,
            fee,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the unique identifier of this transaction.
    pub fn id(&self) -> TransactionId {
        self.id
    }

    /// Returns the ID of the account against which this transaction was executed.
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Returns a commitment to the state of the account before this update is applied.
    ///
    /// This is equal to [`Word::empty()`] for new accounts.
    pub fn initial_state_commitment(&self) -> Word {
        self.initial_state_commitment
    }

    /// Returns a commitment to the state of the account after this update is applied.
    pub fn final_state_commitment(&self) -> Word {
        self.final_state_commitment
    }

    /// Returns a reference to the consumed notes of the transaction.
    ///
    /// The returned input note commitments have the same order as the transaction to which the
    /// header belongs.
    ///
    /// Note that the note may have been erased at the batch or block level, so it may not be
    /// present there.
    pub fn input_notes(&self) -> &InputNotes<InputNoteCommitment> {
        &self.input_notes
    }

    /// Returns a reference to the ID and metadata of the output notes created by the transaction.
    ///
    /// The returned output note data has the same order as the transaction to which the header
    /// belongs.
    ///
    /// Note that the note may have been erased at the batch or block level, so it may not be
    /// present there.
    pub fn output_notes(&self) -> &[NoteHeader] {
        &self.output_notes
    }

    /// Returns the fee paid by this transaction.
    pub fn fee(&self) -> FungibleAsset {
        self.fee
    }
}

impl From<&ProvenTransaction> for TransactionHeader {
    /// Constructs a [`TransactionHeader`] from a [`ProvenTransaction`].
    fn from(tx: &ProvenTransaction) -> Self {
        // SAFETY: The data in a proven transaction is guaranteed to be internally consistent and so
        // we can skip the consistency checks by the `new` constructor.
        TransactionHeader::new_unchecked(
            tx.id(),
            tx.account_id(),
            tx.account_update().initial_state_commitment(),
            tx.account_update().final_state_commitment(),
            tx.input_notes().clone(),
            tx.output_notes().iter().map(OutputNote::header).cloned().collect(),
            tx.fee(),
        )
    }
}

impl From<&ExecutedTransaction> for TransactionHeader {
    /// Constructs a [`TransactionHeader`] from a [`ExecutedTransaction`].
    fn from(tx: &ExecutedTransaction) -> Self {
        TransactionHeader::new_unchecked(
            tx.id(),
            tx.account_id(),
            tx.initial_account().initial_commitment(),
            tx.final_account().commitment(),
            tx.input_notes().to_commitments(),
            tx.output_notes().iter().map(OutputNote::header).cloned().collect(),
            tx.fee(),
        )
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for TransactionHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self {
            id: _,
            account_id,
            initial_state_commitment,
            final_state_commitment,
            input_notes,
            output_notes,
            fee,
        } = self;

        account_id.write_into(target);
        initial_state_commitment.write_into(target);
        final_state_commitment.write_into(target);
        input_notes.write_into(target);
        output_notes.write_into(target);
        fee.write_into(target);
    }
}

impl Deserializable for TransactionHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account_id = <AccountId>::read_from(source)?;
        let initial_state_commitment = <Word>::read_from(source)?;
        let final_state_commitment = <Word>::read_from(source)?;
        let input_notes = <InputNotes<InputNoteCommitment>>::read_from(source)?;
        let output_notes = <Vec<NoteHeader>>::read_from(source)?;
        let fee = FungibleAsset::read_from(source)?;

        let tx_header = Self::new(
            account_id,
            initial_state_commitment,
            final_state_commitment,
            input_notes,
            output_notes,
            fee,
        );

        Ok(tx_header)
    }
}
