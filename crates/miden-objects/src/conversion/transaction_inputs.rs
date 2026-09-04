use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use miden_protocol::account::{AccountCode, PartialAccount, StorageSlotId, StorageSlotName};
use miden_protocol::block::BlockHeader;
use miden_protocol::note::{Note, NoteId, NoteInclusionProof};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    TransactionArgs,
    TransactionInputs,
    UnverifiedPartialBlockchain,
    UnverifiedTransactionInputs,
};
use miden_protocol::vm::AdviceInputs;

use crate::{ConversionError, ConversionResultExt, proto};

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

pub(crate) fn decode_authenticated_input_note(
    note: Note,
    (proof_note_id, proof): (NoteId, NoteInclusionProof),
) -> Result<InputNote, ConversionError> {
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

pub(crate) fn decode_input_notes(
    notes: Vec<InputNote>,
) -> Result<InputNotes<InputNote>, ConversionError> {
    InputNotes::new(notes).map_err(ConversionError::new)
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

pub(crate) fn decode_foreign_account_slot_name(
    slot_id: StorageSlotId,
    slot_name: String,
) -> Result<(StorageSlotId, StorageSlotName), ConversionError> {
    let slot_name = StorageSlotName::new(slot_name)
        .map_err(ConversionError::new)
        .context("slot_name")?;
    if slot_name.id() != slot_id {
        return Err(
            ConversionError::message("storage slot ID does not match slot name").context("slot_id")
        );
    }
    Ok((slot_id, slot_name))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_unverified_transaction_inputs_v1(
    account: PartialAccount,
    block_header: BlockHeader,
    protocol_config: ProtocolConfig,
    partial_blockchain: UnverifiedPartialBlockchain,
    input_notes: InputNotes<InputNote>,
    tx_args: TransactionArgs,
    advice_inputs: AdviceInputs,
    foreign_account_code: Vec<AccountCode>,
    decoded_slot_names: Vec<(StorageSlotId, StorageSlotName)>,
) -> Result<UnverifiedTransactionInputs, ConversionError> {
    let mut foreign_account_slot_names = BTreeMap::new();
    for (index, (slot_id, slot_name)) in decoded_slot_names.into_iter().enumerate() {
        if foreign_account_slot_names.insert(slot_id, slot_name).is_some() {
            return Err(ConversionError::message("duplicate foreign account storage slot ID")
                .context(format!("foreign_account_slot_names[{index}].slot_id")));
        }
    }

    Ok(UnverifiedTransactionInputs::from_parts(
        account,
        block_header,
        protocol_config,
        partial_blockchain,
        input_notes,
        tx_args,
        advice_inputs,
        foreign_account_code,
        foreign_account_slot_names,
    ))
}
