use alloc::string::ToString;
use alloc::vec::Vec;

use super::{InputNote, ToInputNoteCommitments};
use crate::Word;
use crate::account::{AccountUpdateDetails, validate_new_public_account};
use crate::block::BlockNumber;
use crate::errors::ProvenTransactionError;
use crate::note::{NoteHeader, NoteId};
use crate::transaction::{
    AccountId,
    InputNotes,
    Nullifier,
    OutputNote,
    OutputNotes,
    TransactionId,
};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::vm::ExecutionProof;

// PROVEN TRANSACTION
// ================================================================================================

/// Result of executing and proving a transaction. Contains all the data required to verify that a
/// transaction was executed correctly.
///
/// A proven transaction must not be empty. A transaction is empty if the account state is unchanged
/// or the number of input notes is zero. This check prevents proving a transaction once and
/// submitting it to the network many times. Output notes are not considered because they can be
/// empty (i.e. contain no assets). Otherwise, a transaction with no account state change, no input
/// notes and one such empty output note could be resubmitted many times to the network and fill up
/// block space which is a form of DOS attack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenTransaction {
    /// A unique identifier for the transaction, see [TransactionId] for additional details.
    id: TransactionId,

    /// Account update data.
    account_update: TxAccountUpdate,

    /// Committed details of all notes consumed by the transaction.
    input_notes: InputNotes<InputNoteCommitment>,

    /// Notes created by the transaction. For private notes, this will contain only note headers,
    /// while for public notes this will also contain full note details.
    output_notes: OutputNotes,

    /// [`BlockNumber`] of the transaction's reference block.
    ref_block_num: BlockNumber,

    /// The block commitment of the transaction's reference block.
    ref_block_commitment: Word,

    /// The block number by which the transaction will expire, as defined by the executed scripts.
    expiration_block_num: BlockNumber,

    /// A STARK proof that attests to the correct execution of the transaction.
    proof: ExecutionProof,
}

impl ProvenTransaction {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new [ProvenTransaction] from the specified components.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The total number of input notes is greater than
    ///   [`MAX_INPUT_NOTES_PER_TX`](crate::constants::MAX_INPUT_NOTES_PER_TX).
    /// - The vector of input notes contains duplicates.
    /// - The total number of output notes is greater than
    ///   [`MAX_OUTPUT_NOTES_PER_TX`](crate::constants::MAX_OUTPUT_NOTES_PER_TX).
    /// - The vector of output notes contains duplicates.
    /// - The set of input and output notes contains the same note.
    /// - The transaction is empty, which is the case if the account state is unchanged or the
    ///   number of input notes is zero.
    /// - The commitment computed on the actual account delta contained in [`TxAccountUpdate`] does
    ///   not match its declared account delta commitment.
    pub fn new(
        account_update: TxAccountUpdate,
        input_notes: impl IntoIterator<Item = impl Into<InputNoteCommitment>>,
        output_notes: impl IntoIterator<Item = impl Into<OutputNote>>,
        ref_block_num: BlockNumber,
        ref_block_commitment: Word,
        expiration_block_num: BlockNumber,
        proof: ExecutionProof,
    ) -> Result<Self, ProvenTransactionError> {
        let input_notes: Vec<InputNoteCommitment> =
            input_notes.into_iter().map(Into::into).collect();
        let output_notes: Vec<OutputNote> = output_notes.into_iter().map(Into::into).collect();

        let input_notes =
            InputNotes::new(input_notes).map_err(ProvenTransactionError::InputNotesError)?;
        let output_notes =
            OutputNotes::new(output_notes).map_err(ProvenTransactionError::OutputNotesError)?;

        Self::from_parts(
            account_update,
            input_notes,
            output_notes,
            ref_block_num,
            ref_block_commitment,
            expiration_block_num,
            proof,
        )
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns unique identifier of this transaction.
    pub fn id(&self) -> TransactionId {
        self.id
    }

    /// Returns ID of the account against which this transaction was executed.
    pub fn account_id(&self) -> AccountId {
        self.account_update.account_id()
    }

    /// Returns the account update details.
    pub fn account_update(&self) -> &TxAccountUpdate {
        &self.account_update
    }

    /// Returns a reference to the notes consumed by the transaction.
    pub fn input_notes(&self) -> &InputNotes<InputNoteCommitment> {
        &self.input_notes
    }

    /// Returns a reference to the notes produced by the transaction.
    pub fn output_notes(&self) -> &OutputNotes {
        &self.output_notes
    }

    /// Returns the proof of the transaction.
    pub fn proof(&self) -> &ExecutionProof {
        &self.proof
    }

    /// Returns the number of the reference block the transaction was executed against.
    pub fn ref_block_num(&self) -> BlockNumber {
        self.ref_block_num
    }

    /// Returns the commitment of the block transaction was executed against.
    pub fn ref_block_commitment(&self) -> Word {
        self.ref_block_commitment
    }

    /// Returns an iterator of the headers of unauthenticated input notes in this transaction.
    pub fn unauthenticated_notes(&self) -> impl Iterator<Item = &NoteHeader> {
        self.input_notes.iter().filter_map(|note| note.header())
    }

    /// Returns the block number at which the transaction will expire.
    pub fn expiration_block_num(&self) -> BlockNumber {
        self.expiration_block_num
    }

    /// Returns an iterator over the nullifiers of all input notes in this transaction.
    ///
    /// This includes both authenticated and unauthenticated notes.
    pub fn nullifiers(&self) -> impl Iterator<Item = Nullifier> + '_ {
        self.input_notes.iter().map(InputNoteCommitment::nullifier)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Creates a [`ProvenTransaction`] from its raw parts, enforcing all invariants.
    ///
    /// Both [`ProvenTransaction::new`] and [`ProvenTransaction::read_from`] funnel through this
    /// constructor so that every invariant is checked on both the creation and deserialization
    /// paths.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The transaction is empty (account state unchanged and no input notes).
    /// - The same note ID appears as both an unauthenticated input and an output (circular
    ///   dependency, see <https://github.com/0xMiden/protocol/issues/2796>).
    /// - The commitment computed on the actual account delta does not match its declared account
    ///   delta commitment.
    fn from_parts(
        account_update: TxAccountUpdate,
        input_notes: InputNotes<InputNoteCommitment>,
        output_notes: OutputNotes,
        ref_block_num: BlockNumber,
        ref_block_commitment: Word,
        expiration_block_num: BlockNumber,
        proof: ExecutionProof,
    ) -> Result<Self, ProvenTransactionError> {
        // Check that either the account state was changed or at least one note was consumed,
        // otherwise this transaction is considered empty.
        if account_update.initial_state_commitment() == account_update.final_state_commitment()
            && input_notes.commitment().is_empty()
        {
            return Err(ProvenTransactionError::EmptyTransaction);
        }

        // Disallow creating and consuming notes with the same ID in a transaction. This is a
        // circular dependency that can be abused (see https://github.com/0xMiden/protocol/issues/2796).
        // This is only relevant for unauthenticated notes (notes with a header), since only these
        // can be erased at batch or block level. Authenticated notes don't exhibit this issue.
        for input_note in input_notes.iter().filter_map(InputNoteCommitment::header) {
            if output_notes.iter().any(|output_note| output_note.id() == input_note.id()) {
                return Err(ProvenTransactionError::NoteCreatedAndConsumed(input_note.id()));
            }
        }

        let id = TransactionId::new(
            account_update.initial_state_commitment(),
            account_update.final_state_commitment(),
            input_notes.commitment(),
            output_notes.commitment(),
        );

        Ok(Self {
            id,
            account_update,
            input_notes,
            output_notes,
            ref_block_num,
            ref_block_commitment,
            expiration_block_num,
            proof,
        })
    }
}

impl Serializable for ProvenTransaction {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account_update.write_into(target);
        self.input_notes.write_into(target);
        self.output_notes.write_into(target);
        self.ref_block_num.write_into(target);
        self.ref_block_commitment.write_into(target);
        self.expiration_block_num.write_into(target);
        self.proof.write_into(target);
    }
}

impl Deserializable for ProvenTransaction {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account_update = TxAccountUpdate::read_from(source)?;

        let input_notes = <InputNotes<InputNoteCommitment>>::read_from(source)?;
        let output_notes = OutputNotes::read_from(source)?;

        let ref_block_num = BlockNumber::read_from(source)?;
        let ref_block_commitment = Word::read_from(source)?;
        let expiration_block_num = BlockNumber::read_from(source)?;
        let proof = ExecutionProof::read_from(source)?;

        Self::from_parts(
            account_update,
            input_notes,
            output_notes,
            ref_block_num,
            ref_block_commitment,
            expiration_block_num,
            proof,
        )
        .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TRANSACTION ACCOUNT UPDATE
// ================================================================================================

/// Describes the changes made to the account state resulting from a transaction execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAccountUpdate {
    /// ID of the account updated by a transaction.
    account_id: AccountId,

    /// The commitment of the account before the transaction was executed.
    ///
    /// Set to `Word::empty()` for new accounts.
    init_state_commitment: Word,

    /// The commitment of the account state after the transaction was executed.
    final_state_commitment: Word,

    /// The commitment to the [`AccountPatch`](crate::account::AccountPatch) resulting from the
    /// execution of the transaction, as computed by the transaction kernel in the epilogue. This
    /// commitment is always set regardless of whether the account is public or private.
    /// - When `details` is [`AccountUpdateDetails::Public`], it must equal the commitment of the
    ///   patch carried in that variant.
    /// - When `details` is [`AccountUpdateDetails::Private`], the patch itself is not transmitted
    ///   and the commitment is validated implicitly as part of transaction verification.
    account_patch_commitment: Word,

    /// A description of the changes to the account that produces the post-transaction state when
    /// applied to the pre-transaction state. For private accounts this is set to
    /// [`AccountUpdateDetails::Private`].
    details: AccountUpdateDetails,
}

impl TxAccountUpdate {
    /// Returns a new [TxAccountUpdate] instantiated from the specified components.
    ///
    /// Returns an error if:
    /// - The size of the serialized account update exceeds [`crate::ACCOUNT_UPDATE_MAX_SIZE`].
    /// - The transaction was executed against an account with public state and its account ID does
    ///   not match the ID of the patch in the account update.
    /// - The transaction was executed against a _new_ account with public state and its commitment
    ///   does not match the final state commitment of the account update.
    /// - The transaction creates a _new_ account with public state and the update is of type
    ///   [`AccountUpdateDetails::Public`] but the account patch is not a full state patch.
    /// - The transaction was executed against a private account and the account update is _not_ of
    ///   type [`AccountUpdateDetails::Private`].
    /// - The transaction was executed against an account with public state and the update is of
    ///   type [`AccountUpdateDetails::Private`].
    pub fn new(
        account_id: AccountId,
        init_state_commitment: Word,
        final_state_commitment: Word,
        account_patch_commitment: Word,
        details: AccountUpdateDetails,
    ) -> Result<Self, ProvenTransactionError> {
        let account_update = Self {
            account_id,
            init_state_commitment,
            final_state_commitment,
            account_patch_commitment,
            details,
        };

        account_update.details.validate_size(account_id)?;

        let Some(patch) = account_update.details.validate_for_account(account_id)? else {
            return Ok(account_update);
        };

        let actual_patch_commitment = patch.to_commitment();
        if account_patch_commitment != actual_patch_commitment {
            return Err(ProvenTransactionError::AccountPatchCommitmentMismatch {
                expected_patch_commitment: account_patch_commitment,
                actual_patch_commitment,
            });
        }

        if account_update.initial_state_commitment().is_empty() {
            validate_new_public_account(patch, account_update.final_state_commitment)?;
        }

        Ok(account_update)
    }

    /// Returns the ID of the updated account.
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Returns the commitment of the account before the transaction was executed.
    pub fn initial_state_commitment(&self) -> Word {
        self.init_state_commitment
    }

    /// Returns the commitment of the account after the transaction was executed.
    pub fn final_state_commitment(&self) -> Word {
        self.final_state_commitment
    }

    /// Returns the commitment to the [`AccountPatch`](crate::account::AccountPatch) resulting from
    /// the execution of the transaction.
    pub fn account_patch_commitment(&self) -> Word {
        self.account_patch_commitment
    }

    /// Returns the description of the updates for public accounts.
    ///
    /// These descriptions can be used to build the new account state from the previous account
    /// state.
    pub fn details(&self) -> &AccountUpdateDetails {
        &self.details
    }

    /// Returns `true` if the account update details are for a private account.
    pub fn is_private(&self) -> bool {
        self.details.is_private()
    }
}

impl Serializable for TxAccountUpdate {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account_id.write_into(target);
        self.init_state_commitment.write_into(target);
        self.final_state_commitment.write_into(target);
        self.account_patch_commitment.write_into(target);
        self.details.write_into(target);
    }
}

impl Deserializable for TxAccountUpdate {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account_id = AccountId::read_from(source)?;
        let init_state_commitment = Word::read_from(source)?;
        let final_state_commitment = Word::read_from(source)?;
        let account_patch_commitment = Word::read_from(source)?;
        let details = AccountUpdateDetails::read_from(source)?;

        Self::new(
            account_id,
            init_state_commitment,
            final_state_commitment,
            account_patch_commitment,
            details,
        )
        .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// INPUT NOTE COMMITMENT
// ================================================================================================

/// The commitment to an input note.
///
/// For notes authenticated by the transaction kernel, the commitment consists only of the note's
/// nullifier. For notes whose authentication is delayed to batch/block kernels, the commitment
/// also includes full note header (i.e., note ID and metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputNoteCommitment {
    nullifier: Nullifier,
    header: Option<NoteHeader>,
}

impl InputNoteCommitment {
    /// Returns a new [InputNoteCommitment] instantiated from the provided nullifier and optional
    /// note header.
    ///
    /// Note: this method does not validate that the provided nullifier and header are consistent
    /// with each other (i.e., it does not check that the nullifier was derived from the note
    /// referenced by the header).
    pub fn from_parts_unchecked(nullifier: Nullifier, header: Option<NoteHeader>) -> Self {
        Self { nullifier, header }
    }

    /// Returns the nullifier of the input note committed to by this commitment.
    pub fn nullifier(&self) -> Nullifier {
        self.nullifier
    }

    /// Returns the header of the input committed to by this commitment.
    ///
    /// Note headers are present only for notes whose presence in the change has not yet been
    /// authenticated.
    pub fn header(&self) -> Option<&NoteHeader> {
        self.header.as_ref()
    }

    /// Returns true if this commitment is for a note whose presence in the chain has been
    /// authenticated.
    ///
    /// Authenticated notes are represented solely by their nullifiers and are missing the note
    /// header.
    pub fn is_authenticated(&self) -> bool {
        self.header.is_none()
    }
}

impl From<InputNote> for InputNoteCommitment {
    fn from(note: InputNote) -> Self {
        Self::from(&note)
    }
}

impl From<&InputNote> for InputNoteCommitment {
    fn from(note: &InputNote) -> Self {
        match note {
            InputNote::Authenticated { note, .. } => Self {
                nullifier: note.nullifier(),
                header: None,
            },
            InputNote::Unauthenticated { note } => Self {
                nullifier: note.nullifier(),
                header: Some(*note.header()),
            },
        }
    }
}

impl From<Nullifier> for InputNoteCommitment {
    fn from(nullifier: Nullifier) -> Self {
        Self { nullifier, header: None }
    }
}

impl ToInputNoteCommitments for InputNoteCommitment {
    fn nullifier(&self) -> Nullifier {
        self.nullifier
    }

    fn note_id(&self) -> Option<NoteId> {
        self.header.as_ref().map(NoteHeader::id)
    }
}

// SERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for InputNoteCommitment {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.nullifier.write_into(target);
        self.header.write_into(target);
    }
}

impl Deserializable for InputNoteCommitment {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let nullifier = Nullifier::read_from(source)?;
        let header = <Option<NoteHeader>>::read_from(source)?;

        Ok(Self::from_parts_unchecked(nullifier, header))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    use anyhow::Context;
    use assert_matches::assert_matches;
    use miden_crypto::rand::test_utils::rand_value;
    use miden_verifier::ExecutionProof;

    use super::ProvenTransaction;
    use crate::account::{
        Account,
        AccountId,
        AccountPatch,
        AccountStoragePatch,
        AccountType,
        AccountUpdateDetails,
        AccountVaultPatch,
        StorageMapKey,
        StorageMapPatch,
        StorageMapPatchEntries,
        StorageSlotName,
    };
    use crate::block::BlockNumber;
    use crate::errors::ProvenTransactionError;
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    };
    use crate::testing::add_component::AddComponent;
    use crate::testing::noop_auth_component::NoopAuthComponent;
    use crate::transaction::{InputNoteCommitment, OutputNote, TxAccountUpdate};
    use crate::utils::serde::{Deserializable, Serializable};
    use crate::{ACCOUNT_UPDATE_MAX_SIZE, EMPTY_WORD, Felt, Word};

    fn check_if_sync<T: Sync>() {}
    fn check_if_send<T: Send>() {}

    /// [ProvenTransaction] being Sync is part of its public API and changing it is backwards
    /// incompatible.
    #[test]
    fn test_proven_transaction_is_sync() {
        check_if_sync::<ProvenTransaction>();
    }

    /// [ProvenTransaction] being Send is part of its public API and changing it is backwards
    /// incompatible.
    #[test]
    fn test_proven_transaction_is_send() {
        check_if_send::<ProvenTransaction>();
    }

    #[test]
    fn account_update_size_limit_not_exceeded() -> anyhow::Result<()> {
        // A small account's delta does not exceed the limit.
        let account = Account::builder([9; 32])
            .account_type(AccountType::Public)
            .with_component(NoopAuthComponent)
            .with_component(AddComponent)
            .build_existing()?;
        let patch = AccountPatch::try_from(account.clone())?;
        let patch_commitment = patch.to_commitment();

        let details = AccountUpdateDetails::Public(patch);

        TxAccountUpdate::new(
            account.id(),
            account.to_commitment(),
            account.to_commitment(),
            patch_commitment,
            details,
        )?;

        Ok(())
    }

    #[test]
    fn account_update_size_limit_exceeded() {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        let mut map = BTreeMap::new();
        // The number of entries in the map required to exceed the limit.
        // We divide by each entry's size which consists of a key (digest) and a value (word), both
        // 32 bytes in size.
        let required_entries = ACCOUNT_UPDATE_MAX_SIZE / (2 * 32);
        for _ in 0..required_entries {
            map.insert(StorageMapKey::from_raw(rand_value()), rand_value::<Word>());
        }
        let storage_patch = StorageMapPatch::Update {
            entries: StorageMapPatchEntries::from_raw(map),
        };

        // A patch that exceeds the limit returns an error.
        let storage_patch =
            AccountStoragePatch::from_iters([], [], [(StorageSlotName::mock(4), storage_patch)]);
        let patch = AccountPatch::new(
            account_id,
            storage_patch,
            AccountVaultPatch::default(),
            None,
            Some(Felt::from(2u32)),
        )
        .unwrap();
        let details = AccountUpdateDetails::Public(patch);
        let details_size = details.get_size_hint();

        let err = TxAccountUpdate::new(
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap(),
            EMPTY_WORD,
            EMPTY_WORD,
            EMPTY_WORD,
            details,
        )
        .unwrap_err();

        assert!(
            matches!(err, ProvenTransactionError::AccountUpdateSizeLimitExceeded { update_size, .. } if update_size == details_size)
        );
    }

    /// Building a [`TxAccountUpdate`] for a public account fails if the account ID in the patch
    /// does not match the account ID passed to the constructor.
    #[test]
    fn account_update_id_mismatch_between_account_id_and_patch() -> anyhow::Result<()> {
        let patch_account = Account::builder([9; 32])
            .account_type(AccountType::Public)
            .with_component(NoopAuthComponent)
            .with_component(AddComponent)
            .build_existing()?;
        let patch = AccountPatch::try_from(patch_account.clone())?;

        let other_account_id =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)?;
        assert_ne!(patch_account.id(), other_account_id);

        let err = TxAccountUpdate::new(
            other_account_id,
            patch_account.to_commitment(),
            patch_account.to_commitment(),
            Word::empty(),
            AccountUpdateDetails::Public(patch),
        )
        .unwrap_err();

        assert_matches!(
            err,
            ProvenTransactionError::AccountIdMismatch {
                tx_account_id,
                details_account_id,
            } => {
                assert_eq!(tx_account_id, other_account_id);
                assert_eq!(details_account_id, patch_account.id());
            }
        );

        Ok(())
    }

    #[test]
    fn account_patch_commitment_mismatch() -> anyhow::Result<()> {
        let account = Account::builder([9; 32])
            .account_type(AccountType::Public)
            .with_component(NoopAuthComponent)
            .with_component(AddComponent)
            .build_existing()?;
        let patch = AccountPatch::try_from(account.clone())?;
        let actual_patch_commitment = patch.to_commitment();
        // EMPTY_WORD is all-zeros and differs from a real Rescue hash.
        let wrong_commitment = EMPTY_WORD;
        assert_ne!(wrong_commitment, actual_patch_commitment);
        let err = TxAccountUpdate::new(
            account.id(),
            account.to_commitment(),
            account.to_commitment(),
            wrong_commitment,
            AccountUpdateDetails::Public(patch),
        )
        .unwrap_err();
        assert_matches!(
            err,
            ProvenTransactionError::AccountPatchCommitmentMismatch {
                expected_patch_commitment,
                actual_patch_commitment: returned_actual,
            } if expected_patch_commitment == wrong_commitment
                && returned_actual == actual_patch_commitment
        );
        Ok(())
    }
    #[test]
    fn test_proven_tx_serde_roundtrip() -> anyhow::Result<()> {
        let account_id =
            AccountId::builder().account_type(AccountType::Private).build_with_seed([1; 32]);
        let initial_account_commitment =
            [2; 32].try_into().expect("failed to create initial account commitment");
        let final_account_commitment =
            [3; 32].try_into().expect("failed to create final account commitment");
        let account_patch_commitment =
            [4; 32].try_into().expect("failed to create account patch commitment");
        let ref_block_num = BlockNumber::from(1);
        let ref_block_commitment = Word::empty();
        let expiration_block_num = BlockNumber::from(2);
        let proof = ExecutionProof::new_dummy();

        let account_update = TxAccountUpdate::new(
            account_id,
            initial_account_commitment,
            final_account_commitment,
            account_patch_commitment,
            AccountUpdateDetails::Private,
        )
        .context("failed to build account update")?;

        let tx = ProvenTransaction::new(
            account_update,
            Vec::<InputNoteCommitment>::new(),
            Vec::<OutputNote>::new(),
            ref_block_num,
            ref_block_commitment,
            expiration_block_num,
            proof,
        )
        .context("failed to build proven transaction")?;

        let deserialized = ProvenTransaction::read_from_bytes(&tx.to_bytes()).unwrap();

        assert_eq!(tx, deserialized);

        Ok(())
    }
}
