use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteHeader, NoteId};
use miden_protocol::transaction::{
    InputNoteCommitment,
    InputNotes,
    OutputNote,
    PrivateOutputNote,
    ProvenTransaction,
    PublicOutputNote,
    TransactionArgs,
    TransactionHeader,
    TransactionId,
    TransactionScript,
    TxAccountUpdate,
};
use miden_protocol::vm::ExecutionProof;
use miden_protocol::{MastForest, MastNodeId, Word};

use crate::{ConversionError, ConversionResultExt, proto};

// TRANSACTION ARGUMENTS
// ================================================================================================

impl From<&TransactionScript> for proto::transaction::TransactionScript {
    fn from(value: &TransactionScript) -> Self {
        Self {
            entrypoint: value.entrypoint().into(),
            mast: Some(value.mast().as_ref().into()),
        }
    }
}

pub(crate) fn decode_transaction_script(
    mast: MastForest,
    entrypoint: u32,
) -> Result<TransactionScript, ConversionError> {
    let entrypoint = MastNodeId::from_u32_safe(entrypoint, &mast).map_err(|error| {
        ConversionError::deserialization("transaction_script.entrypoint", error)
    })?;

    TransactionScript::from_parts(Arc::new(mast), entrypoint).map_err(ConversionError::new)
}

impl From<&TransactionArgs> for proto::transaction::TransactionArgs {
    fn from(value: &TransactionArgs) -> Self {
        Self {
            tx_script: value.tx_script().map(Into::into),
            tx_script_args: Some(value.tx_script_args().into()),
            note_args: value
                .note_args()
                .iter()
                .map(|(note_id, args)| proto::transaction::NoteArgument {
                    note_id: Some(note_id.into()),
                    args: Some(args.into()),
                })
                .collect(),
            advice_inputs: Some(value.advice_inputs().into()),
            auth_args: Some(value.auth_args().into()),
        }
    }
}

impl From<TransactionArgs> for proto::transaction::TransactionArgs {
    fn from(value: TransactionArgs) -> Self {
        (&value).into()
    }
}

pub(crate) fn decode_transaction_args(
    tx_script: Option<TransactionScript>,
    tx_script_args: Word,
    decoded_note_args: Vec<(NoteId, Word)>,
    advice_inputs: miden_protocol::vm::AdviceInputs,
    auth_args: Word,
) -> Result<TransactionArgs, ConversionError> {
    let mut note_args = BTreeMap::new();
    for (index, (note_id, args)) in decoded_note_args.into_iter().enumerate() {
        if note_args.insert(note_id, args).is_some() {
            return Err(ConversionError::message("duplicate note argument")
                .context(format!("note_args[{index}].note_id")));
        }
    }

    Ok(TransactionArgs::from_parts(
        tx_script,
        tx_script_args,
        note_args,
        advice_inputs,
        auth_args,
    ))
}

// TX ACCOUNT UPDATE
// ================================================================================================

impl From<&TxAccountUpdate> for proto::transaction::TxAccountUpdate {
    fn from(value: &TxAccountUpdate) -> Self {
        Self {
            account_id: Some(value.account_id().into()),
            initial_state_commitment: Some(value.initial_state_commitment().into()),
            final_state_commitment: Some(value.final_state_commitment().into()),
            account_patch_commitment: Some(value.account_patch_commitment().into()),
            details: Some(value.details().into()),
        }
    }
}

// PROVEN TRANSACTION
// ================================================================================================

impl From<&ProvenTransaction> for proto::transaction::ProvenTransaction {
    fn from(value: &ProvenTransaction) -> Self {
        Self {
            account_update: Some(value.account_update().into()),
            input_notes: value.input_notes().iter().map(Into::into).collect(),
            output_notes: value.output_notes().iter().map(Into::into).collect(),
            reference_block_num: Some(value.ref_block_num().into()),
            reference_block_commitment: Some(value.ref_block_commitment().into()),
            expiration_block_num: Some(value.expiration_block_num().into()),
            proof: Some(value.proof().into()),
        }
    }
}

impl From<ProvenTransaction> for proto::transaction::ProvenTransaction {
    fn from(value: ProvenTransaction) -> Self {
        Self::from(&value)
    }
}

pub(crate) fn decode_proven_transaction(
    account_update: TxAccountUpdate,
    input_notes: Vec<InputNoteCommitment>,
    output_notes: Vec<OutputNote>,
    reference_block_commitment: Word,
    reference_block_num: BlockNumber,
    expiration_block_num: BlockNumber,
    proof: ExecutionProof,
) -> Result<ProvenTransaction, ConversionError> {
    ProvenTransaction::new(
        account_update,
        input_notes,
        output_notes,
        reference_block_num,
        reference_block_commitment,
        expiration_block_num,
        proof,
    )
    .map_err(ConversionError::new)
}

// FROM TRANSACTION ID
// ================================================================================================

impl From<&TransactionId> for proto::transaction::TransactionId {
    fn from(value: &TransactionId) -> Self {
        proto::transaction::TransactionId { id: Some(value.as_word().into()) }
    }
}

impl From<TransactionId> for proto::transaction::TransactionId {
    fn from(value: TransactionId) -> Self {
        (&value).into()
    }
}

// INTO TRANSACTION ID
// ================================================================================================

// INPUT NOTE COMMITMENT
// ================================================================================================

impl From<InputNoteCommitment> for proto::transaction::InputNoteCommitment {
    fn from(value: InputNoteCommitment) -> Self {
        Self::from(&value)
    }
}

impl From<&InputNoteCommitment> for proto::transaction::InputNoteCommitment {
    fn from(value: &InputNoteCommitment) -> Self {
        Self {
            nullifier: Some(value.nullifier().as_word().into()),
            header: value.header().copied().map(Into::into),
        }
    }
}

// TRANSACTION HEADER
// ================================================================================================

impl From<&TransactionHeader> for proto::transaction::TransactionHeader {
    fn from(header: &TransactionHeader) -> Self {
        Self {
            transaction_id: Some(header.id().into()),
            account_id: Some(header.account_id().into()),
            initial_state_commitment: Some(header.initial_state_commitment().into()),
            final_state_commitment: Some(header.final_state_commitment().into()),
            input_notes: header.input_notes().iter().map(Into::into).collect(),
            output_notes: header.output_notes().iter().copied().map(Into::into).collect(),
        }
    }
}

impl From<TransactionHeader> for proto::transaction::TransactionHeader {
    fn from(header: TransactionHeader) -> Self {
        Self::from(&header)
    }
}

pub(crate) fn decode_transaction_header(
    transmitted_id: TransactionId,
    account_id: miden_protocol::account::AccountId,
    initial_state_commitment: Word,
    final_state_commitment: Word,
    input_notes: Vec<InputNoteCommitment>,
    output_notes: Vec<NoteHeader>,
) -> Result<TransactionHeader, ConversionError> {
    let input_notes = InputNotes::new(input_notes)
        .map_err(ConversionError::new)
        .context("input_notes")?;
    let header = TransactionHeader::new(
        account_id,
        initial_state_commitment,
        final_state_commitment,
        input_notes,
        output_notes,
    )
    .map_err(ConversionError::new)?;
    if header.id() != transmitted_id {
        return Err(ConversionError::message(format!(
            "transaction ID mismatch: transmitted {transmitted_id}, recomputed {}",
            header.id()
        ))
        .context("transaction_id"));
    }

    Ok(header)
}

// OUTPUT NOTES
// ================================================================================================

impl From<&PublicOutputNote> for proto::transaction::PublicOutputNote {
    fn from(note: &PublicOutputNote) -> Self {
        Self {
            note: Some(note.as_note().clone().into()),
        }
    }
}

impl From<PublicOutputNote> for proto::transaction::PublicOutputNote {
    fn from(note: PublicOutputNote) -> Self {
        Self::from(&note)
    }
}

impl From<&PrivateOutputNote> for proto::transaction::PrivateOutputNote {
    fn from(note: &PrivateOutputNote) -> Self {
        Self {
            header: Some((*note.header()).into()),
            attachments: Some(note.attachments().into()),
        }
    }
}

impl From<PrivateOutputNote> for proto::transaction::PrivateOutputNote {
    fn from(note: PrivateOutputNote) -> Self {
        Self::from(&note)
    }
}

impl From<&OutputNote> for proto::transaction::OutputNote {
    fn from(note: &OutputNote) -> Self {
        use proto::transaction::output_note::Note;

        let note = match note {
            OutputNote::Public(note) => Note::Public(note.into()),
            OutputNote::Private(note) => Note::Private(note.into()),
        };
        Self { note: Some(note) }
    }
}

impl From<OutputNote> for proto::transaction::OutputNote {
    fn from(note: OutputNote) -> Self {
        Self::from(&note)
    }
}
