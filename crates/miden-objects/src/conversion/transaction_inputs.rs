use miden_protocol::Word;
use miden_protocol::account::auth::{Signature, SignatureKey};
use miden_protocol::transaction::{AccountInputs, InputNote, InputNotes, TransactionInputs};
use miden_protocol::utils::serde::Serializable;

use crate::proto;
use crate::proto::transaction::auth_signature::Signature as ProtoSignature;

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

impl From<&Signature> for proto::transaction::AuthSignature {
    fn from(signature: &Signature) -> Self {
        let signature = match signature {
            Signature::Falcon512Poseidon2(signature) => {
                ProtoSignature::Falcon512Poseidon2(signature.to_bytes())
            },
            Signature::EcdsaK256Keccak(signature) => {
                ProtoSignature::EcdsaK256Keccak(signature.to_bytes())
            },
        };

        Self { signature: Some(signature) }
    }
}

impl From<(&SignatureKey, &Signature)> for proto::transaction::SignatureEntry {
    fn from((key, signature): (&SignatureKey, &Signature)) -> Self {
        Self {
            pub_key_commitment: Some(Word::from(key.pub_key_commitment()).into()),
            message: Some(key.message().into()),
            signature: Some(signature.into()),
        }
    }
}

impl From<&AccountInputs> for proto::transaction::AccountInputs {
    fn from(value: &AccountInputs) -> Self {
        Self {
            account: Some(value.account().into()),
            witness: Some(value.witness().into()),
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
            foreign_accounts: value.foreign_accounts().values().map(Into::into).collect(),
            note_scripts: value.note_scripts().values().map(Into::into).collect(),
            signatures: value.signatures().iter().map(Into::into).collect(),
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
