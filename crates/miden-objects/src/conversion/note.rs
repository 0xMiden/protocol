use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_protocol::asset::Asset;
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
use miden_protocol::{Felt, MastNodeId, Word};

use super::{MessageDecodeExt, MessageDecoder, required};
use crate::{ConversionError, ConversionResultExt, proto};

// NOTE TYPE
// ================================================================================================

impl From<NoteType> for proto::note::NoteType {
    fn from(note_type: NoteType) -> Self {
        match note_type {
            NoteType::Private => proto::note::NoteType::Private,
            NoteType::Public => proto::note::NoteType::Public,
        }
    }
}

impl TryFrom<proto::note::NoteType> for NoteType {
    type Error = ConversionError;

    fn try_from(note_type: proto::note::NoteType) -> Result<Self, Self::Error> {
        match note_type {
            proto::note::NoteType::Private => Ok(NoteType::Private),
            proto::note::NoteType::Public => Ok(NoteType::Public),
            proto::note::NoteType::Unspecified => {
                Err(ConversionError::message("enum variant discriminant out of range"))
            },
        }
    }
}

// NOTE METADATA
// ================================================================================================

impl From<NoteMetadata> for proto::note::NoteMetadata {
    fn from(metadata: NoteMetadata) -> Self {
        Self {
            version: proto::note::NoteVersion::V1 as i32,
            sender: Some(metadata.sender().into()),
            note_type: proto::note::NoteType::from(metadata.note_type()) as i32,
            tag: metadata.tag().as_u32(),
            attachment_schemes: metadata
                .attachment_headers()
                .iter()
                .map(|header| u32::from(header.scheme().map_or(0, |scheme| scheme.as_u16())))
                .collect(),
            attachments_commitment: Some(metadata.attachments_commitment().into()),
        }
    }
}

impl TryFrom<proto::note::NoteMetadata> for NoteMetadata {
    type Error = ConversionError;

    fn try_from(metadata: proto::note::NoteMetadata) -> Result<Self, Self::Error> {
        decode_note_version(metadata.version).context("version")?;
        decode_note_metadata(metadata)
    }
}

// NOTE ATTACHMENTS
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
            .map_err(ConversionError::new)
            .context("scheme")?;
        let words = attachment
            .words
            .into_iter()
            .map(Word::try_from)
            .collect::<Result<Vec<_>, _>>()
            .context("words")?;

        NoteAttachment::with_words(scheme, words)
            .map_err(ConversionError::new)
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
            .map_err(ConversionError::new)
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

        NoteStorage::new(items).map_err(ConversionError::new).context("items")
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
        let assets = NoteAssets::new(assets).map_err(ConversionError::new).context("assets")?;
        let recipient = required!(decoder, details.recipient)?;

        Ok(NoteDetails::new(assets, recipient))
    }
}

// NOTE
// ================================================================================================

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

        let note_details: NoteDetails = required!(decoder, note_details)?;
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
        Self { id: Some(note_id.as_word().into()) }
    }
}

impl From<(&NoteId, &NoteInclusionProof)> for proto::note::NoteInclusionProof {
    fn from((note_id, proof): (&NoteId, &NoteInclusionProof)) -> Self {
        Self {
            note_id: Some(note_id.into()),
            block_num: Some(proof.location().block_num().into()),
            note_index_in_block: proof.location().block_note_tree_index().into(),
            inclusion_path: Some(proof.note_path().clone().into()),
        }
    }
}

impl TryFrom<&proto::note::NoteInclusionProof> for (NoteId, NoteInclusionProof) {
    type Error = ConversionError;

    fn try_from(
        proof: &proto::note::NoteInclusionProof,
    ) -> Result<(NoteId, NoteInclusionProof), Self::Error> {
        let proof = proof.clone();
        let decoder = proof.decoder();
        let inclusion_path = required!(decoder, proof.inclusion_path)?;
        let note_id = required!(decoder, proof.note_id)?;
        let block_num = required!(decoder, proof.block_num).context("block_num")?;

        Ok((
            NoteId::from_raw(note_id),
            NoteInclusionProof::new(
                block_num,
                proof.note_index_in_block.try_into().context("note_index_in_block")?,
                inclusion_path,
            )
            .map_err(ConversionError::new)?,
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
        let details_commitment_word = required!(decoder, value.details_commitment)?;
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
            mast: Some(script.mast().as_ref().into()),
        }
    }
}

impl TryFrom<proto::note::NoteScript> for NoteScript {
    type Error = ConversionError;

    fn try_from(value: proto::note::NoteScript) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let mast = required!(decoder, value.mast)?;
        let entrypoint = value.entrypoint;
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
    decode_note_version(value.version).context("version")?;
    decode_partial_note_metadata(value.sender, value.note_type, value.tag)
}

fn decode_note_version(version: i32) -> Result<(), ConversionError> {
    match proto::note::NoteVersion::try_from(version) {
        Ok(proto::note::NoteVersion::V1) => Ok(()),
        Ok(proto::note::NoteVersion::Unspecified) => {
            Err(ConversionError::message("note metadata version is unspecified"))
        },
        Err(error) => Err(ConversionError::with_source(
            format!("unknown note metadata version {version}"),
            error,
        )),
    }
}

fn decode_note_metadata(
    metadata: proto::note::NoteMetadata,
) -> Result<NoteMetadata, ConversionError> {
    let proto::note::NoteMetadata {
        sender,
        note_type,
        tag,
        attachment_schemes,
        attachments_commitment,
        ..
    } = metadata;

    let partial = decode_partial_note_metadata(sender, note_type, tag)?;
    let decoder = MessageDecoder::<proto::note::NoteMetadata>::default();
    let attachments_commitment = required!(decoder, attachments_commitment)?;

    if attachment_schemes.len() > NoteAttachments::MAX_COUNT {
        return Err(ConversionError::message("too many attachment schemes"));
    }
    let mut attachment_headers = [NoteAttachmentHeader::absent(); NoteAttachments::MAX_COUNT];
    for (slot, raw) in attachment_headers.iter_mut().zip(attachment_schemes) {
        let raw = u16::try_from(raw)
            .map_err(|_| ConversionError::message("attachment scheme out of u16 range"))?;
        *slot = if raw == 0 {
            NoteAttachmentHeader::absent()
        } else {
            NoteAttachmentHeader::new(NoteAttachmentScheme::new(raw)?)
        };
    }

    Ok(NoteMetadata::from_parts(partial, attachment_headers, attachments_commitment))
}

fn decode_partial_note_metadata(
    sender: Option<proto::account::AccountId>,
    note_type: i32,
    tag: u32,
) -> Result<PartialNoteMetadata, ConversionError> {
    let decoder = MessageDecoder::<proto::note::NoteMetadata>::default();
    let sender = required!(decoder, sender)?;
    let note_type = proto::note::NoteType::try_from(note_type)
        .map_err(|_| ConversionError::message("enum variant discriminant out of range"))?
        .try_into()
        .context("note_type")?;
    let tag = NoteTag::new(tag);
    Ok(PartialNoteMetadata::new(sender, note_type).with_tag(tag))
}

/// Requires and decodes the structured attachments carried by a note message.
fn decode_note_attachments<M: prost::Message>(
    note_attachments: Option<proto::note::NoteAttachments>,
) -> Result<NoteAttachments, ConversionError> {
    let decoder = MessageDecoder::<M>::default();
    required!(decoder, note_attachments)
}
