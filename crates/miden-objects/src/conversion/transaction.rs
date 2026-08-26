use alloc::format;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountUpdateDetails};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteHeader, Nullifier};
use miden_protocol::transaction::{
    InputNoteCommitment,
    InputNotes,
    OutputNote,
    PrivateOutputNote,
    ProvenTransaction,
    PublicOutputNote,
    TransactionHeader,
    TransactionId,
    TxAccountUpdate,
};

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

// PROVEN TRANSACTION
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

impl TryFrom<proto::transaction::TxAccountUpdate> for TxAccountUpdate {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::TxAccountUpdate) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let account_id: AccountId = required!(decoder, value.account_id)?;
        let initial_state_commitment = required!(decoder, value.initial_state_commitment)?;
        let final_state_commitment = required!(decoder, value.final_state_commitment)?;
        let account_patch_commitment = required!(decoder, value.account_patch_commitment)?;
        let details: AccountUpdateDetails = required!(decoder, value.details)?;
        Self::new(
            account_id,
            initial_state_commitment,
            final_state_commitment,
            account_patch_commitment,
            details,
        )
        .map_err(ConversionError::new)
    }
}

impl From<&ProvenTransaction> for proto::transaction::ProvenTransactionData {
    fn from(value: &ProvenTransaction) -> Self {
        Self {
            account_update: Some(value.account_update().into()),
            input_notes: value.input_notes().iter().map(Into::into).collect(),
            output_notes: value.output_notes().iter().map(Into::into).collect(),
            reference_block_num: value.ref_block_num().as_u32(),
            reference_block_commitment: Some(value.ref_block_commitment().into()),
            expiration_block_num: value.expiration_block_num().as_u32(),
            proof: Some(value.proof().into()),
        }
    }
}

impl From<ProvenTransaction> for proto::transaction::ProvenTransactionData {
    fn from(value: ProvenTransaction) -> Self {
        Self::from(&value)
    }
}

impl TryFrom<proto::transaction::ProvenTransactionData> for ProvenTransaction {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::ProvenTransactionData) -> Result<Self, Self::Error> {
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
        let proof = required!(decoder, value.proof)?;

        Self::new(
            account_update,
            input_notes,
            output_notes,
            BlockNumber::from(value.reference_block_num),
            reference_block_commitment,
            BlockNumber::from(value.expiration_block_num),
            proof,
        )
        .map_err(ConversionError::new)
    }
}

// FROM TRANSACTION ID
// ================================================================================================

impl From<&TransactionId> for proto::primitives::Digest {
    fn from(value: &TransactionId) -> Self {
        value.as_word().into()
    }
}

impl From<TransactionId> for proto::primitives::Digest {
    fn from(value: TransactionId) -> Self {
        value.as_word().into()
    }
}

impl From<&TransactionId> for proto::transaction::TransactionId {
    fn from(value: &TransactionId) -> Self {
        proto::transaction::TransactionId { id: Some(value.into()) }
    }
}

impl From<TransactionId> for proto::transaction::TransactionId {
    fn from(value: TransactionId) -> Self {
        (&value).into()
    }
}

// INTO TRANSACTION ID
// ================================================================================================

impl TryFrom<proto::primitives::Digest> for TransactionId {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Digest) -> Result<Self, Self::Error> {
        let digest: Word = value.try_into()?;
        Ok(TransactionId::from_raw(digest))
    }
}

impl TryFrom<proto::transaction::TransactionId> for TransactionId {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::TransactionId) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        required!(decoder, value.id)
    }
}

// NULLIFIER
// ================================================================================================

impl From<&Nullifier> for proto::primitives::Digest {
    fn from(value: &Nullifier) -> Self {
        value.as_word().into()
    }
}

impl From<Nullifier> for proto::primitives::Digest {
    fn from(value: Nullifier) -> Self {
        (&value).into()
    }
}

impl TryFrom<proto::primitives::Digest> for Nullifier {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Digest) -> Result<Self, Self::Error> {
        let word: Word = value.try_into()?;
        Ok(Nullifier::from_raw(word))
    }
}

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
            nullifier: Some(value.nullifier().into()),
            header: value.header().copied().map(Into::into),
        }
    }
}

impl TryFrom<proto::transaction::InputNoteCommitment> for InputNoteCommitment {
    type Error = ConversionError;

    fn try_from(value: proto::transaction::InputNoteCommitment) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let nullifier: Nullifier = required!(decoder, value.nullifier)?;

        let header: Option<miden_protocol::note::NoteHeader> =
            value.header.map(TryInto::try_into).transpose().context("header")?;

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
        let transmitted_id: TransactionId = required!(decoder, header.transaction_id)?;
        let account_id: AccountId = required!(decoder, header.account_id)?;
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
        let details = proto::note::NoteDetails {
            assets: note.assets().iter().copied().map(Into::into).collect(),
            recipient: Some(note.recipient().into()),
        };
        Self {
            metadata: Some((*note.metadata()).into()),
            details: Some(details),
            attachments: Some(note.as_note().attachments().into()),
        }
    }
}

impl From<PublicOutputNote> for proto::transaction::PublicOutputNote {
    fn from(note: PublicOutputNote) -> Self {
        Self::from(&note)
    }
}

impl TryFrom<proto::transaction::PublicOutputNote> for PublicOutputNote {
    type Error = ConversionError;

    fn try_from(note: proto::transaction::PublicOutputNote) -> Result<Self, Self::Error> {
        let domain_note = Note::try_from(proto::note::Note {
            metadata: note.metadata,
            note_details: note.details,
            note_attachments: note.attachments,
        })?;
        PublicOutputNote::new(domain_note).map_err(ConversionError::new)
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

impl TryFrom<proto::transaction::PrivateOutputNote> for PrivateOutputNote {
    type Error = ConversionError;

    fn try_from(note: proto::transaction::PrivateOutputNote) -> Result<Self, Self::Error> {
        let decoder = note.decoder();
        let header = required!(decoder, note.header)?;
        let attachments = required!(decoder, note.attachments)?;
        PrivateOutputNote::new(header, attachments).map_err(ConversionError::new)
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
