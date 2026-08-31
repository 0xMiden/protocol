use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use miden_protocol::account::{AccountCode, StorageSlotId, StorageSlotName};
use miden_protocol::note::{Note, NoteId, NoteInclusionProof};
use miden_protocol::transaction::{InputNote, InputNotes, TransactionInputs};

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

fn decode_required<M, T, U>(name: &'static str, value: Option<T>) -> Result<U, ConversionError>
where
    M: prost::Message,
    T: TryInto<U>,
    T::Error: Into<ConversionError>,
{
    let value = value.ok_or_else(|| ConversionError::missing_field::<M>(name).context(name))?;
    value.try_into().map_err(Into::into).context(name)
}

impl From<&InputNote> for proto::transaction::InputNote {
    fn from(value: &InputNote) -> Self {
        use proto::transaction::input_note::Note as ProtoInputNote;

        let note = match value {
            InputNote::Authenticated { note, proof } => {
                ProtoInputNote::Authenticated(proto::transaction::AuthenticatedInputNote {
                    note: Some(note.clone().into()),
                    proof: Some((&note.id(), proof).into()),
                })
            },
            InputNote::Unauthenticated { note } => {
                ProtoInputNote::Unauthenticated(note.clone().into())
            },
        };

        Self { note: Some(note) }
    }
}

impl TryFrom<proto::transaction::InputNote> for InputNote {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::InputNote) -> Result<Self, Self::Error> {
        use proto::transaction::input_note::Note as ProtoInputNote;

        match value.note {
            Some(ProtoInputNote::Authenticated(authenticated)) => {
                decode_authenticated_input_note(authenticated).context("authenticated")
            },
            Some(ProtoInputNote::Unauthenticated(note)) => {
                Note::try_from(note).map(InputNote::unauthenticated).context("unauthenticated")
            },
            None => Err(ConversionError::missing_field::<proto::transaction::InputNote>("note")),
        }
    }
}

fn decode_authenticated_input_note(
    authenticated: proto::transaction::AuthenticatedInputNote,
) -> Result<InputNote, ConversionError> {
    let note: Note = decode_required::<proto::transaction::AuthenticatedInputNote, _, _>(
        "note",
        authenticated.note,
    )?;
    let proof_message: proto::note::NoteInclusionProof = decode_required::<
        proto::transaction::AuthenticatedInputNote,
        _,
        _,
    >("proof", authenticated.proof)?;
    let (proof_note_id, proof): (NoteId, NoteInclusionProof) =
        (&proof_message).try_into().context("proof")?;
    if proof_note_id != note.id() {
        return Err(ConversionError::message(format!(
            "note ID mismatch: transmitted {proof_note_id}, decoded {}",
            note.id()
        ))
        .context("proof.note_id"));
    }

    Ok(InputNote::authenticated(note, proof))
}

impl From<&InputNotes<InputNote>> for proto::transaction::InputNotes {
    fn from(value: &InputNotes<InputNote>) -> Self {
        Self {
            notes: value.iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<proto::transaction::InputNotes> for InputNotes<InputNote> {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::InputNotes) -> Result<Self, Self::Error> {
        let notes = value
            .notes
            .into_iter()
            .enumerate()
            .map(|(index, note)| InputNote::try_from(note).context(format!("notes[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(notes).map_err(ConversionError::new)
    }
}

impl From<&TransactionInputs> for proto::transaction::TransactionInputsV1 {
    fn from(value: &TransactionInputs) -> Self {
        Self {
            account: Some(value.account().into()),
            block_header: Some(value.block_header().into()),
            protocol_config: Some(value.protocol_config().into()),
            partial_blockchain: Some(value.blockchain().into()),
            input_notes: Some(value.input_notes().into()),
            tx_args: Some(value.tx_args().into()),
            advice_inputs: Some(value.advice_inputs().into()),
            foreign_account_code: value.foreign_account_code().iter().map(Into::into).collect(),
            foreign_account_slot_names: value
                .foreign_account_slot_names()
                .iter()
                .map(|(slot_id, slot_name)| proto::transaction::ForeignAccountSlotName {
                    slot_id: Some(slot_id.into()),
                    slot_name: String::from(slot_name.as_str()),
                })
                .collect(),
        }
    }
}

impl From<&TransactionInputs> for proto::transaction::TransactionInputs {
    fn from(value: &TransactionInputs) -> Self {
        use proto::transaction::transaction_inputs::Version;

        Self { version: Some(Version::V1(value.into())) }
    }
}

impl From<TransactionInputs> for proto::transaction::TransactionInputs {
    fn from(value: TransactionInputs) -> Self {
        (&value).into()
    }
}

impl TryFrom<proto::transaction::TransactionInputsV1> for TransactionInputs {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::TransactionInputsV1) -> Result<Self, Self::Error> {
        let account = decode_required::<proto::transaction::TransactionInputsV1, _, _>(
            "account",
            value.account,
        )?;
        let block_header = decode_required::<proto::transaction::TransactionInputsV1, _, _>(
            "block_header",
            value.block_header,
        )?;
        let protocol_config = decode_required::<proto::transaction::TransactionInputsV1, _, _>(
            "protocol_config",
            value.protocol_config,
        )?;
        let partial_blockchain = decode_required::<proto::transaction::TransactionInputsV1, _, _>(
            "partial_blockchain",
            value.partial_blockchain,
        )?;
        let input_notes = decode_required::<proto::transaction::TransactionInputsV1, _, _>(
            "input_notes",
            value.input_notes,
        )?;
        let tx_args = decode_required::<proto::transaction::TransactionInputsV1, _, _>(
            "tx_args",
            value.tx_args,
        )?;
        let advice_inputs = decode_required::<proto::transaction::TransactionInputsV1, _, _>(
            "advice_inputs",
            value.advice_inputs,
        )?;
        let foreign_account_code = value
            .foreign_account_code
            .into_iter()
            .enumerate()
            .map(|(index, code)| {
                AccountCode::try_from(code).context(format!("foreign_account_code[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut foreign_account_slot_names = BTreeMap::new();
        for (index, entry) in value.foreign_account_slot_names.into_iter().enumerate() {
            let decoder = entry.decoder();
            let slot_id: StorageSlotId = required!(decoder, entry.slot_id)
                .context(format!("foreign_account_slot_names[{index}]"))?;
            let slot_name = StorageSlotName::new(entry.slot_name)
                .map_err(ConversionError::new)
                .context(format!("foreign_account_slot_names[{index}].slot_name"))?;
            if slot_name.id() != slot_id {
                return Err(ConversionError::message("storage slot ID does not match slot name")
                    .context(format!("foreign_account_slot_names[{index}].slot_id")));
            }
            if foreign_account_slot_names.insert(slot_id, slot_name).is_some() {
                return Err(ConversionError::message("duplicate foreign account storage slot ID")
                    .context(format!("foreign_account_slot_names[{index}].slot_id")));
            }
        }

        TransactionInputs::try_from_parts(
            account,
            block_header,
            protocol_config,
            partial_blockchain,
            input_notes,
            tx_args,
            advice_inputs,
            foreign_account_code,
            foreign_account_slot_names,
        )
        .map_err(ConversionError::new)
    }
}

impl TryFrom<proto::transaction::TransactionInputs> for TransactionInputs {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::TransactionInputs) -> Result<Self, Self::Error> {
        use proto::transaction::transaction_inputs::Version;

        match value.version {
            Some(Version::V1(v1)) => Self::try_from(v1).context("v1"),
            None => Err(ConversionError::missing_field::<proto::transaction::TransactionInputs>(
                "version",
            )),
        }
    }
}
