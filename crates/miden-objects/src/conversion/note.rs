use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_protocol::asset::Asset;
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentHeader,
    NoteAttachmentScheme,
    NoteAttachments,
    NoteDetails,
    NoteDetailsCommitment,
    NoteHeader,
    NoteId,
    NoteInclusionProof,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Felt, MastForest, MastNodeId, Word};

use super::{DecodeBytesExt, MessageDecodeExt, MessageDecoder, required};
use crate::{ConversionError, ConversionResultExt, proto};

// NOTE TYPE
// ================================================================================================

impl From<NoteType> for proto::note::NoteType {
    fn from(note_type: NoteType) -> Self {
        match note_type {
            NoteType::Public => proto::note::NoteType::Public,
            NoteType::Private => proto::note::NoteType::Private,
        }
    }
}

impl TryFrom<proto::note::NoteType> for NoteType {
    type Error = ConversionError;

    fn try_from(note_type: proto::note::NoteType) -> Result<Self, Self::Error> {
        match note_type {
            proto::note::NoteType::Public => Ok(NoteType::Public),
            proto::note::NoteType::Private => Ok(NoteType::Private),
            proto::note::NoteType::Unspecified => {
                Err(ConversionError::message("enum variant discriminant out of range"))
            },
        }
    }
}

// NOTE METADATA
// ================================================================================================

impl From<NoteMetadata> for proto::note::NoteMetadata {
    fn from(val: NoteMetadata) -> Self {
        let sender = Some(val.sender().into());
        let note_type = proto::note::NoteType::from(val.note_type()) as i32;
        let tag = val.tag().as_u32();
        let attachment_schemes = val
            .attachment_headers()
            .iter()
            .map(|header| u32::from(header.scheme().map_or(0, |s| s.as_u16())))
            .collect();
        let attachments_commitment = Some(val.attachments_commitment().into());

        proto::note::NoteMetadata {
            sender,
            note_type,
            tag,
            attachment_schemes,
            attachments_commitment,
        }
    }
}

impl TryFrom<proto::note::NoteMetadata> for NoteMetadata {
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteMetadata) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let sender = required!(decoder, value.sender)?;
        let note_type = proto::note::NoteType::try_from(value.note_type)
            .map_err(|_| ConversionError::message("enum variant discriminant out of range"))?
            .try_into()
            .context("note_type")?;
        let tag = NoteTag::new(value.tag);
        let attachments_commitment: Word = required!(decoder, value.attachments_commitment)?;

        if value.attachment_schemes.len() > NoteAttachments::MAX_COUNT {
            return Err(ConversionError::message("too many attachment schemes"));
        }
        let mut attachment_headers = [NoteAttachmentHeader::absent(); NoteAttachments::MAX_COUNT];
        for (slot, raw) in attachment_headers.iter_mut().zip(value.attachment_schemes) {
            let raw = u16::try_from(raw)
                .map_err(|_| ConversionError::message("attachment scheme out of u16 range"))?;
            *slot = if raw == 0 {
                NoteAttachmentHeader::absent()
            } else {
                NoteAttachmentHeader::new(NoteAttachmentScheme::new(raw)?)
            };
        }

        let partial = PartialNoteMetadata::new(sender, note_type).with_tag(tag);
        Ok(NoteMetadata::from_parts(partial, attachment_headers, attachments_commitment))
    }
}

// NOTE
// ================================================================================================

impl From<&NoteAttachment> for proto::note::NoteAttachment {
    fn from(attachment: &NoteAttachment) -> Self {
        Self {
            scheme: u32::from(attachment.attachment_scheme().as_u16()),
            words: attachment.content().as_words().iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<proto::note::NoteAttachment> for NoteAttachment {
    type Error = ConversionError;

    fn try_from(attachment: proto::note::NoteAttachment) -> Result<Self, Self::Error> {
        let scheme = u16::try_from(attachment.scheme).context("scheme")?;
        let scheme = NoteAttachmentScheme::new(scheme)
            .map_err(ConversionError::from)
            .context("scheme")?;
        let words = attachment
            .words
            .into_iter()
            .map(Word::try_from)
            .collect::<Result<Vec<_>, _>>()
            .context("words")?;

        NoteAttachment::with_words(scheme, words)
            .map_err(ConversionError::from)
            .context("words")
    }
}

impl From<NoteAttachments> for proto::note::NoteAttachments {
    fn from(attachments: NoteAttachments) -> Self {
        Self::from(&attachments)
    }
}

impl From<&NoteAttachments> for proto::note::NoteAttachments {
    fn from(attachments: &NoteAttachments) -> Self {
        Self {
            attachments: attachments.iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<proto::note::NoteAttachments> for NoteAttachments {
    type Error = ConversionError;

    fn try_from(attachments: proto::note::NoteAttachments) -> Result<Self, Self::Error> {
        let attachments = attachments
            .attachments
            .into_iter()
            .map(NoteAttachment::try_from)
            .collect::<Result<Vec<_>, _>>()
            .context("attachments")?;

        NoteAttachments::new(attachments)
            .map_err(ConversionError::from)
            .context("attachments")
    }
}

// NOTE DETAILS
// ================================================================================================

impl From<NoteStorage> for proto::note::NoteStorage {
    fn from(storage: NoteStorage) -> Self {
        Self::from(&storage)
    }
}

impl From<&NoteStorage> for proto::note::NoteStorage {
    fn from(storage: &NoteStorage) -> Self {
        Self {
            items: storage.items().iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<proto::note::NoteStorage> for NoteStorage {
    type Error = ConversionError;

    fn try_from(storage: proto::note::NoteStorage) -> Result<Self, Self::Error> {
        let items = storage
            .items
            .into_iter()
            .map(Felt::try_from)
            .collect::<Result<Vec<_>, _>>()
            .context("items")?;

        NoteStorage::new(items).map_err(ConversionError::from).context("items")
    }
}

impl From<NoteRecipient> for proto::note::NoteRecipient {
    fn from(recipient: NoteRecipient) -> Self {
        Self::from(&recipient)
    }
}

impl From<&NoteRecipient> for proto::note::NoteRecipient {
    fn from(recipient: &NoteRecipient) -> Self {
        Self {
            serial_num: Some(recipient.serial_num().into()),
            script: Some(recipient.script().into()),
            storage: Some(recipient.storage().into()),
        }
    }
}

impl TryFrom<proto::note::NoteRecipient> for NoteRecipient {
    type Error = ConversionError;

    fn try_from(recipient: proto::note::NoteRecipient) -> Result<Self, Self::Error> {
        let decoder = recipient.decoder();
        let serial_num = required!(decoder, recipient.serial_num)?;
        let script = required!(decoder, recipient.script)?;
        let storage = required!(decoder, recipient.storage)?;

        Ok(NoteRecipient::new(serial_num, script, storage))
    }
}

impl From<NoteDetails> for proto::note::NoteDetails {
    fn from(details: NoteDetails) -> Self {
        Self::from(&details)
    }
}

impl From<&NoteDetails> for proto::note::NoteDetails {
    fn from(details: &NoteDetails) -> Self {
        Self {
            assets: details.assets().iter().copied().map(Into::into).collect(),
            recipient: Some(details.recipient().into()),
        }
    }
}

impl TryFrom<proto::note::NoteDetails> for NoteDetails {
    type Error = ConversionError;

    fn try_from(details: proto::note::NoteDetails) -> Result<Self, Self::Error> {
        let decoder = details.decoder();
        let assets = details
            .assets
            .into_iter()
            .map(Asset::try_from)
            .collect::<Result<Vec<_>, _>>()
            .context("assets")?;
        let assets = NoteAssets::new(assets).map_err(ConversionError::from).context("assets")?;
        let recipient = required!(decoder, details.recipient)?;

        Ok(NoteDetails::new(assets, recipient))
    }
}

impl From<Note> for proto::note::Note {
    fn from(note: Note) -> Self {
        let (assets, metadata, recipient, attachments) = note.into_parts();
        Self {
            metadata: Some(metadata.into()),
            note_details: Some(NoteDetails::new(assets, recipient).into()),
            note_attachments: Some(attachments.into()),
        }
    }
}

impl TryFrom<proto::note::Note> for Note {
    type Error = ConversionError;

    fn try_from(proto_note: proto::note::Note) -> Result<Self, Self::Error> {
        let decoder = proto_note.decoder();
        let proto::note::Note { metadata, note_details, note_attachments } = proto_note;

        let metadata = required!(decoder, metadata)?;
        let partial_metadata = partial_note_metadata_from_proto(metadata)?;

        let note_details = decode_note_details::<proto::note::Note>(note_details, true)?
            .expect("required note details decoder must return a value");
        let (assets, recipient) = note_details.into_parts();
        let attachments = decode_note_attachments::<proto::note::Note>(note_attachments)?;

        Ok(Note::with_attachments(assets, partial_metadata, recipient, attachments))
    }
}

// NOTE ID
// ================================================================================================

impl From<Word> for proto::note::NoteId {
    fn from(digest: Word) -> Self {
        Self { id: Some(digest.into()) }
    }
}

impl TryFrom<proto::note::NoteId> for Word {
    type Error = ConversionError;

    fn try_from(note_id: proto::note::NoteId) -> Result<Self, Self::Error> {
        let decoder = note_id.decoder();
        required!(decoder, note_id.id)
    }
}

impl From<&NoteId> for proto::note::NoteId {
    fn from(note_id: &NoteId) -> Self {
        Self { id: Some(note_id.into()) }
    }
}

impl From<(&NoteId, &NoteInclusionProof)> for proto::note::NoteInclusionInBlockProof {
    fn from((note_id, proof): (&NoteId, &NoteInclusionProof)) -> Self {
        Self {
            note_id: Some(note_id.into()),
            block_num: proof.location().block_num().as_u32(),
            note_index_in_block: proof.location().block_note_tree_index().into(),
            inclusion_path: Some(proof.note_path().clone().into()),
        }
    }
}

impl TryFrom<&proto::note::NoteInclusionInBlockProof> for (NoteId, NoteInclusionProof) {
    type Error = ConversionError;

    fn try_from(
        proof: &proto::note::NoteInclusionInBlockProof,
    ) -> Result<(NoteId, NoteInclusionProof), Self::Error> {
        let decoder = proof.decoder();
        let inclusion_path: SparseMerklePath =
            decoder.decode_field("inclusion_path", proof.inclusion_path.clone())?;
        let note_id: Word = required!(decoder, proof.note_id)?;

        Ok((
            NoteId::from_raw(note_id),
            NoteInclusionProof::new(
                proof.block_num.into(),
                proof.note_index_in_block.try_into().context("note_index_in_block")?,
                inclusion_path,
            )?,
        ))
    }
}

// NOTE HEADER
// ================================================================================================

impl From<NoteHeader> for proto::note::NoteHeader {
    fn from(header: NoteHeader) -> Self {
        Self {
            details_commitment: Some(header.details_commitment().as_word().into()),
            metadata: Some(header.into_metadata().into()),
        }
    }
}

impl TryFrom<proto::note::NoteHeader> for NoteHeader {
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteHeader) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let details_commitment_word: Word = required!(decoder, value.details_commitment)?;
        let metadata: NoteMetadata = required!(decoder, value.metadata)?;

        Ok(NoteHeader::new(
            NoteDetailsCommitment::from_raw(details_commitment_word),
            metadata,
        ))
    }
}

// NOTE SCRIPT
// ================================================================================================

impl From<NoteScript> for proto::note::NoteScript {
    fn from(script: NoteScript) -> Self {
        Self::from(&script)
    }
}

impl From<&NoteScript> for proto::note::NoteScript {
    fn from(script: &NoteScript) -> Self {
        Self {
            entrypoint: script.entrypoint().into(),
            mast: script.mast().to_bytes(),
        }
    }
}

impl TryFrom<proto::note::NoteScript> for NoteScript {
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteScript) -> Result<Self, Self::Error> {
        let proto::note::NoteScript { entrypoint, mast } = value;

        let mast = MastForest::decode_bytes(&mast, "note_script.mast")?;
        let entrypoint = MastNodeId::from_u32_safe(entrypoint, &mast)
            .map_err(|err| ConversionError::deserialization("note_script.entrypoint", err))?;

        Self::from_parts(Arc::new(mast), entrypoint).map_err(ConversionError::new)
    }
}

// HELPERS
// ================================================================================================

/// Decodes the `(sender, note_type, tag)` triple from a proto `NoteMetadata` into a
/// [`PartialNoteMetadata`]. The attachment-related fields on the proto are ignored — when full
/// attachments are also transmitted, the receiver derives the canonical headers and commitment from
/// those instead.
fn partial_note_metadata_from_proto(
    value: proto::note::NoteMetadata,
) -> Result<PartialNoteMetadata, ConversionError> {
    let decoder = value.decoder();
    let sender = required!(decoder, value.sender)?;
    let note_type = proto::note::NoteType::try_from(value.note_type)
        .map_err(|_| ConversionError::message("enum variant discriminant out of range"))?
        .try_into()
        .context("note_type")?;
    let tag = NoteTag::new(value.tag);
    Ok(PartialNoteMetadata::new(sender, note_type).with_tag(tag))
}

/// Requires and decodes the structured attachments carried by a note message.
fn decode_note_attachments<M: prost::Message>(
    attachments: Option<proto::note::NoteAttachments>,
) -> Result<NoteAttachments, ConversionError> {
    MessageDecoder::<M>::default().decode_field("note_attachments", attachments)
}

/// Decodes structured note details, optionally allowing the field to be absent.
fn decode_note_details<M: prost::Message>(
    details: Option<proto::note::NoteDetails>,
    required: bool,
) -> Result<Option<NoteDetails>, ConversionError> {
    match details {
        Some(details) => details.try_into().map(Some).context("note_details"),
        None if required => Err(ConversionError::missing_field::<M>("note_details")),
        None => Ok(None),
    }
}
