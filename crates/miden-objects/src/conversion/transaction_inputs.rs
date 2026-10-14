use alloc::string::String;

use miden_protocol::transaction::{InputNote, InputNotes, TransactionInputs};

use crate::proto;

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

impl From<&InputNotes<InputNote>> for proto::transaction::InputNotes {
    fn from(value: &InputNotes<InputNote>) -> Self {
        Self {
            notes: value.iter().map(Into::into).collect(),
        }
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
