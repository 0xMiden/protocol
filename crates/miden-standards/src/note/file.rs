#[cfg(feature = "std")]
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
    vec::Vec,
};

use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteDetails, NoteId, NoteInclusionProof, NoteTag};
#[cfg(feature = "std")]
use miden_protocol::utils::serde::SliceReader;
use miden_protocol::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

const MAGIC: &str = "note";

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

#[cfg(feature = "std")]
impl NoteFile {
    /// Serializes and writes binary [NoteFile] to specified file
    pub fn write(&self, filepath: impl AsRef<Path>) -> io::Result<()> {
        fs::write(filepath, self.to_bytes())
    }

    /// Reads from file and tries to deserialize an [NoteFile]
    pub fn read(filepath: impl AsRef<Path>) -> io::Result<Self> {
        let mut file = File::open(filepath)?;
        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer)?;
        let mut reader = SliceReader::new(&buffer);

        Ok(NoteFile::read_from(&mut reader).map_err(|_| io::ErrorKind::InvalidData)?)
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

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteFile {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(MAGIC.as_bytes());
        match self {
            NoteFile::NoteId(note_id) => {
                target.write_u8(0);
                note_id.write_into(target);
            },
            NoteFile::ExpectedNote { details, sync_hint } => {
                target.write_u8(1);
                details.write_into(target);
                sync_hint.write_into(target);
            },
            NoteFile::Committed { note, proof } => {
                target.write_u8(2);
                note.write_into(target);
                proof.write_into(target);
            },
        }
    }
}

impl Serializable for NoteSyncHint {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.after_block_num.write_into(target);
        self.tag.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.after_block_num.get_size_hint() + self.tag.get_size_hint()
    }
}

impl Deserializable for NoteFile {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let magic_value = source.read_string(4)?;
        if magic_value != MAGIC {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid note file marker: {magic_value}"
            )));
        }
        match source.read_u8()? {
            0 => Ok(NoteFile::NoteId(NoteId::read_from(source)?)),
            1 => {
                let details = NoteDetails::read_from(source)?;
                let sync_hint = NoteSyncHint::read_from(source)?;
                Ok(NoteFile::ExpectedNote { details, sync_hint })
            },
            2 => {
                let note = Note::read_from(source)?;
                let proof = NoteInclusionProof::read_from(source)?;
                Ok(NoteFile::Committed { note, proof })
            },
            v => {
                Err(DeserializationError::InvalidValue(format!("unknown variant {v} for NoteFile")))
            },
        }
    }
}

impl Deserializable for NoteSyncHint {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let after_block_num = BlockNumber::read_from(source)?;
        let tag = NoteTag::read_from(source)?;
        Ok(Self { after_block_num, tag })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_protocol::Word;
    use miden_protocol::account::AccountId;
    use miden_protocol::asset::{Asset, FungibleAsset};
    use miden_protocol::block::BlockNumber;
    use miden_protocol::note::{
        Note,
        NoteAssets,
        NoteDetails,
        NoteInclusionProof,
        NoteRecipient,
        NoteScript,
        NoteStorage,
        NoteTag,
        NoteType,
        PartialNoteMetadata,
    };
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    };
    use miden_protocol::utils::serde::{Deserializable, Serializable};

    use super::{NoteFile, NoteSyncHint};

    fn create_example_note() -> Note {
        let faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
        let target =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE).unwrap();

        let serial_num = Word::from([0, 1, 2, 3u32]);
        let script = NoteScript::mock();
        let note_storage = NoteStorage::new(vec![target.prefix().into()]).unwrap();
        let recipient = NoteRecipient::new(serial_num, script, note_storage);

        let asset = Asset::from(FungibleAsset::new(faucet, 100).unwrap());
        let metadata =
            PartialNoteMetadata::new(faucet, NoteType::Public).with_tag(NoteTag::from(123));

        Note::new(NoteAssets::new(vec![asset]).unwrap(), metadata, recipient)
    }

    #[test]
    fn serialized_note_magic() {
        let note = create_example_note();
        let file = NoteFile::NoteId(note.id());
        let mut buffer = Vec::new();
        file.write_into(&mut buffer);

        let magic_value = &buffer[..4];
        assert_eq!(magic_value, b"note");
    }

    /// Asserts that `file` survives a serialization round-trip unchanged.
    fn assert_roundtrip(file: NoteFile) {
        assert_eq!(NoteFile::read_from_bytes(&file.to_bytes()).unwrap(), file);
    }

    #[test]
    fn serialize_id() {
        assert_roundtrip(NoteFile::NoteId(create_example_note().id()));
    }

    #[test]
    fn serialize_expected_note() {
        let note = create_example_note();
        assert_roundtrip(NoteFile::ExpectedNote {
            details: NoteDetails::from(&note),
            sync_hint: NoteSyncHint::new(456.into(), NoteTag::from(123)),
        });
    }

    #[test]
    fn serialize_committed_note() {
        let note = create_example_note();
        let proof = NoteInclusionProof::new(BlockNumber::from(0), 0, Default::default()).unwrap();
        assert_roundtrip(NoteFile::Committed { note, proof });
    }
}
