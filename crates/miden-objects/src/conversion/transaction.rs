use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_protocol::note::{NoteHeader, NoteId, Nullifier};
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
use miden_protocol::{MastForest, MastNodeId, Word};

use super::{MessageDecodeExt, required};
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

impl TryFrom<proto::transaction::TransactionScript> for TransactionScript {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::TransactionScript) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let mast: MastForest = required!(decoder, value.mast)?;
        let entrypoint = MastNodeId::from_u32_safe(value.entrypoint, &mast).map_err(|error| {
            ConversionError::deserialization("transaction_script.entrypoint", error)
        })?;

        Self::from_parts(Arc::new(mast), entrypoint).map_err(ConversionError::new)
    }
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

impl TryFrom<proto::transaction::TransactionArgs> for TransactionArgs {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::TransactionArgs) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let tx_script = value.tx_script.map(TryInto::try_into).transpose()?;
        let tx_script_args = required!(decoder, value.tx_script_args)?;
        let mut note_args = BTreeMap::new();
        for (index, note_arg) in value.note_args.into_iter().enumerate() {
            let decoder = note_arg.decoder();
            let note_arg_context = format!("note_args[{index}]");
            let note_id_word: Word =
                required!(decoder, note_arg.note_id).context(&note_arg_context)?;
            let note_id = NoteId::from_raw(note_id_word);
            let args = required!(decoder, note_arg.args).context(&note_arg_context)?;
            if note_args.insert(note_id, args).is_some() {
                return Err(ConversionError::message("duplicate note argument")
                    .context(format!("{note_arg_context}.note_id")));
            }
        }
        let advice_inputs = required!(decoder, value.advice_inputs)?;
        let auth_args = required!(decoder, value.auth_args)?;

        Ok(Self::from_parts(tx_script, tx_script_args, note_args, advice_inputs, auth_args))
    }
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

impl TryFrom<proto::transaction::ProvenTransaction> for ProvenTransaction {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::ProvenTransaction) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let account_update = required!(decoder, value.account_update)?;
        let input_notes = value
            .input_notes
            .into_iter()
            .enumerate()
            .map(|(index, note)| {
                InputNoteCommitment::try_from(note).context(format!("input_notes[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let output_notes = value
            .output_notes
            .into_iter()
            .enumerate()
            .map(|(index, note)| {
                OutputNote::try_from(note).context(format!("output_notes[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let reference_block_commitment = required!(decoder, value.reference_block_commitment)?;
        let reference_block_num =
            required!(decoder, value.reference_block_num).context("reference_block_num")?;
        let expiration_block_num =
            required!(decoder, value.expiration_block_num).context("expiration_block_num")?;
        let proof = required!(decoder, value.proof)?;

        Self::new(
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

impl TryFrom<proto::transaction::InputNoteCommitment> for InputNoteCommitment {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::InputNoteCommitment) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let nullifier = Nullifier::from_raw(required!(decoder, value.nullifier)?);

        let header = value.header.map(TryInto::try_into).transpose().context("header")?;

        Ok(InputNoteCommitment::from_parts_unchecked(nullifier, header))
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

impl TryFrom<proto::transaction::TransactionHeader> for TransactionHeader {
    type Error = ConversionError;

    fn try_from(header: proto::transaction::TransactionHeader) -> Result<Self, Self::Error> {
        let decoder = header.decoder();
        let transmitted_id = required!(decoder, header.transaction_id)?;
        let account_id = required!(decoder, header.account_id)?;
        let initial_state_commitment = required!(decoder, header.initial_state_commitment)?;
        let final_state_commitment = required!(decoder, header.final_state_commitment)?;
        let input_notes = header
            .input_notes
            .into_iter()
            .enumerate()
            .map(|(index, note)| {
                InputNoteCommitment::try_from(note).context(format!("input_notes[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let input_notes = InputNotes::new(input_notes)
            .map_err(ConversionError::new)
            .context("input_notes")?;
        let output_notes = header
            .output_notes
            .into_iter()
            .enumerate()
            .map(|(index, note)| {
                NoteHeader::try_from(note).context(format!("output_notes[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;

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

impl TryFrom<proto::transaction::OutputNote> for OutputNote {
    type Error = ConversionError;

    fn try_from(note: proto::transaction::OutputNote) -> Result<Self, Self::Error> {
        use proto::transaction::output_note::Note;

        match note.note {
            Some(Note::Public(note)) => note.try_into().map(OutputNote::Public).context("public"),
            Some(Note::Private(note)) => {
                note.try_into().map(OutputNote::Private).context("private")
            },
            None => Err(ConversionError::missing_field::<proto::transaction::OutputNote>("note")),
        }
    }
}
