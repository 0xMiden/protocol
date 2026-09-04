use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_protobuf::{DecodeRepeated, RepeatedField};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
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
use miden_protocol::{Felt, MastNodeId, Word};

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

impl From<PartialNoteMetadata> for proto::note::PartialNoteMetadata {
    fn from(metadata: PartialNoteMetadata) -> Self {
        Self {
            version: proto::note::NoteVersion::V1 as i32,
            sender: Some(metadata.sender().into()),
            note_type: proto::note::NoteType::from(metadata.note_type()) as i32,
            tag: metadata.tag().as_u32(),
        }
    }
}

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

pub(crate) fn decode_note_attachment(
    scheme: u32,
    words: Vec<Word>,
) -> Result<NoteAttachment, ConversionError> {
    let scheme = u16::try_from(scheme).context("scheme")?;
    let scheme = NoteAttachmentScheme::new(scheme)
        .map_err(ConversionError::new)
        .context("scheme")?;

    NoteAttachment::with_words(scheme, words)
        .map_err(ConversionError::new)
        .context("words")
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

pub(crate) fn validate_note_attachments(
    attachments: Vec<NoteAttachment>,
) -> Result<NoteAttachments, ConversionError> {
    NoteAttachments::new(attachments)
        .map_err(ConversionError::new)
        .context("attachments")
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

pub(crate) fn decode_note_storage(items: Vec<Felt>) -> Result<NoteStorage, ConversionError> {
    NoteStorage::new(items).map_err(ConversionError::new).context("items")
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

impl DecodeRepeated<proto::asset::Asset> for NoteAssets {
    fn decode_repeated(field: RepeatedField<proto::asset::Asset>) -> Result<Self, ConversionError> {
        let name = field.name();
        let assets = field.decode_items()?;
        Self::new(assets).map_err(ConversionError::new).context(name)
    }
}

// NOTE
// ================================================================================================

impl From<Note> for proto::note::Note {
    fn from(note: Note) -> Self {
        let (assets, metadata, recipient, attachments) = note.into_parts();
        Self {
            metadata: Some(metadata.into_partial_metadata().into()),
            note_details: Some(NoteDetails::new(assets, recipient).into()),
            note_attachments: Some(attachments.into()),
        }
    }
}

pub(crate) fn decode_note(
    metadata: PartialNoteMetadata,
    note_details: NoteDetails,
    note_attachments: NoteAttachments,
) -> Note {
    let (assets, recipient) = note_details.into_parts();
    Note::with_attachments(assets, metadata, recipient, note_attachments)
}

// NOTE ID
// ================================================================================================

impl From<Word> for proto::note::NoteId {
    fn from(digest: Word) -> Self {
        Self { id: Some(digest.into()) }
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

pub(crate) fn decode_note_inclusion_proof(
    note_id: NoteId,
    block_num: BlockNumber,
    note_index_in_block: u32,
    inclusion_path: SparseMerklePath,
) -> Result<(NoteId, NoteInclusionProof), ConversionError> {
    let note_index_in_block = note_index_in_block.try_into().context("note_index_in_block")?;
    let proof = NoteInclusionProof::new(block_num, note_index_in_block, inclusion_path)
        .map_err(ConversionError::new)
        .context("note_index_in_block")?;

    Ok((note_id, proof))
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

impl TryFrom<proto::primitives::Word> for NoteDetailsCommitment {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Word) -> Result<Self, Self::Error> {
        Word::try_from(value).map(Self::from_raw)
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

pub(crate) fn decode_note_script(
    mast: miden_protocol::MastForest,
    entrypoint: u32,
) -> Result<NoteScript, ConversionError> {
    let entrypoint = MastNodeId::from_u32_safe(entrypoint, &mast)
        .map_err(|err| ConversionError::deserialization("note_script.entrypoint", err))?;

    NoteScript::from_parts(Arc::new(mast), entrypoint).map_err(ConversionError::new)
}

// HELPERS
// ================================================================================================

pub(crate) fn decode_note_attachment_schemes(
    attachment_schemes: Vec<u32>,
) -> Result<[NoteAttachmentHeader; NoteAttachments::MAX_COUNT], ConversionError> {
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
            NoteAttachmentHeader::new(NoteAttachmentScheme::new(raw).map_err(ConversionError::new)?)
        };
    }

    Ok(attachment_headers)
}

pub(crate) fn decode_note_metadata(
    sender: AccountId,
    note_type: NoteType,
    tag: u32,
    attachment_headers: [NoteAttachmentHeader; NoteAttachments::MAX_COUNT],
    attachments_commitment: Word,
) -> NoteMetadata {
    let partial = decode_partial_note_metadata(sender, note_type, tag);
    NoteMetadata::from_parts(partial, attachment_headers, attachments_commitment)
}

pub(crate) fn decode_partial_note_metadata(
    sender: AccountId,
    note_type: NoteType,
    tag: u32,
) -> PartialNoteMetadata {
    let tag = NoteTag::new(tag);
    PartialNoteMetadata::new(sender, note_type).with_tag(tag)
}
