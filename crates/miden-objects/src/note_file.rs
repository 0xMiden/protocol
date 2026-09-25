//! The note file format.

use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::path::Path;

use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteDetails, NoteId, NoteInclusionProof, NoteTag};

use crate::{ConversionError, DecodeMessageExt, proto};

#[cfg(test)]
mod tests;

// NOTE SYNC HINT
// ================================================================================================

/// Hints used by a client to find a note on chain after importing a note file.
///
/// The values in this type are intended to guide note synchronization without requiring an exact
/// [`NoteId`] lookup. A client can sync notes by `tag` (starting from `after_block_num`) and get a
/// set of notes that may contain the expected note. Because a tag does not uniquely identify a note
/// but rather expresses a use-case, the client does not need to leak a commitment to a specific
/// note (i.e., its ID) when syncing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteSyncHint {
    /// The block after which the note is expected to appear on chain.
    ///
    /// This should be treated as a lower-bound hint: there is no guarantee that the note will
    /// appear on chain, or that it will appear after this block.
    after_block_num: BlockNumber,
    /// The tag expected to be associated with the note.
    tag: NoteTag,
}

impl NoteSyncHint {
    /// Returns a new [`NoteSyncHint`] instantiated from the provided parameters.
    pub fn new(after_block_num: BlockNumber, tag: NoteTag) -> Self {
        Self { after_block_num, tag }
    }

    /// Returns the block after which the note is expected to appear on chain.
    pub fn after_block_num(&self) -> BlockNumber {
        self.after_block_num
    }

    /// Returns the tag expected to be associated with the note.
    pub fn tag(&self) -> NoteTag {
        self.tag
    }
}

// NOTE FILE
// ================================================================================================

/// A serialized representation of a note.
///
/// A [`NoteFile`] can be used to communicate details of a note across network clients.
/// Each variant covers a specific subset of use-cases and commit to specific trade-offs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum NoteFile {
    /// The note's details aren't known, only its ID is.
    /// A client can import all the note details from the network. As such, the note that the ID
    /// commits to should be public.
    NoteId(NoteId),
    /// The note's details are known, but its metadata and attachments must be recovered from the
    /// chain.
    ///
    /// This is useful for importing an expected note while avoiding an exact [`NoteId`] lookup.
    /// Looking a note up by its exact ID would reveal to the node which note the importer is
    /// interested in, leaking the receiver's privacy. Instead, the importer can use the sync hint
    /// to search for matching notes by tag, then, for each returned note, recompute the note ID as
    /// `NoteId::new(details_commitment, returned_metadata)` using this variant's details
    /// commitment; the returned note whose recomputed ID matches is the expected one. This recovers
    /// its metadata without revealing the note ID to the node.
    ///
    /// Only the note's details are carried here, as they may be private. Metadata and attachments
    /// are always public, so they are recovered from the chain rather than carried: once the note
    /// is found via the tag-based sync, its attachments can be fetched for the whole returned set
    /// (e.g. via `get_notes_by_id`) without revealing which note is the expected one.
    ExpectedNote {
        details: NoteDetails,
        sync_hint: NoteSyncHint,
    },
    /// The note has been committed to the chain and its inclusion proof is known.
    Committed { note: Note, proof: NoteInclusionProof },
}

impl NoteFile {
    // SERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Returns the encoded file as a Protobuf message.
    pub fn to_bytes(&self) -> Vec<u8> {
        prost::Message::encode_to_vec(&proto::note_file::NoteFile::from(self))
    }

    /// Decodes a [`NoteFile`] from the provided bytes.
    ///
    /// The encoded note carries its script, whose size is unbounded. A caller that decodes
    /// untrusted bytes must cap their length first.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid note file.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, NoteFileError> {
        <proto::note_file::NoteFile as prost::Message>::decode(bytes)
            .map_err(|error| NoteFileError::Decode(ConversionError::new(error)))?
            .decode_and_verify()
            .map_err(NoteFileError::Decode)
    }

    /// Writes the encoded file to the provided path.
    #[cfg(feature = "std")]
    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), NoteFileError> {
        std::fs::write(path, self.to_bytes()).map_err(NoteFileError::Io)
    }

    /// Reads a [`NoteFile`] from the provided path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, or if [`Self::try_from_bytes`] rejects its
    /// contents.
    #[cfg(feature = "std")]
    pub fn read(path: impl AsRef<Path>) -> Result<Self, NoteFileError> {
        let bytes = std::fs::read(path).map_err(NoteFileError::Io)?;
        Self::try_from_bytes(&bytes)
    }
}

impl From<Note> for NoteFile {
    fn from(note: Note) -> Self {
        let (assets, metadata, recipient, _attachments) = note.into_parts();
        NoteFile::ExpectedNote {
            details: NoteDetails::new(assets, recipient),
            sync_hint: NoteSyncHint::new(0.into(), metadata.tag()),
        }
    }
}

impl From<NoteId> for NoteFile {
    fn from(note_id: NoteId) -> Self {
        NoteFile::NoteId(note_id)
    }
}

// NOTE FILE ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NoteFileError {
    #[error("failed to decode the note file")]
    Decode(#[source] ConversionError),
    #[cfg(feature = "std")]
    #[error("failed to read or write the note file")]
    Io(#[source] std::io::Error),
}
