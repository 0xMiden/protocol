#[cfg(feature = "std")]
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
    vec::Vec,
};

use super::{Note, NoteAttachments, NoteDetails, NoteId, NoteInclusionProof, NoteTag};
use crate::block::BlockNumber;
#[cfg(feature = "std")]
use crate::utils::serde::SliceReader;
use crate::utils::serde::{
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
    pub after_block_num: BlockNumber,
    /// The tag expected to be associated with the note.
    pub tag: NoteTag,
}

impl NoteSyncHint {
    /// Returns a new [`NoteSyncHint`] instantiated from the provided parameters.
    pub fn new(after_block_num: BlockNumber, tag: NoteTag) -> Self {
        Self { after_block_num, tag }
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
    /// The note's details and attachments are known, but its metadata must be recovered from the
    /// chain.
    ///
    /// This is useful for importing an expected note while avoiding an exact [`NoteId`] lookup. The
    /// importer can use the sync hint to search for matching notes by tag, then verify that a
    /// returned note's metadata reproduces the expected [`NoteId`] from the details commitment.
    ///
    /// Attachments are carried here rather than fetched by ID because attachment content is not
    /// returned by a tag-based sync, so fetching it would otherwise require leaking the note ID.
    ExpectedNote {
        details: NoteDetails,
        attachments: NoteAttachments,
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
        let (assets, metadata, recipient, attachments) = note.into_parts();
        NoteFile::ExpectedNote {
            details: NoteDetails::new(assets, recipient),
            attachments,
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
            NoteFile::ExpectedNote { details, attachments, sync_hint } => {
                target.write_u8(1);
                details.write_into(target);
                attachments.write_into(target);
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
                let attachments = NoteAttachments::read_from(source)?;
                let sync_hint = NoteSyncHint::read_from(source)?;
                Ok(NoteFile::ExpectedNote { details, attachments, sync_hint })
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

    use crate::Word;
    use crate::account::AccountId;
    use crate::asset::{Asset, FungibleAsset};
    use crate::block::BlockNumber;
    use crate::note::{
        Note,
        NoteAssets,
        NoteAttachment,
        NoteAttachmentScheme,
        NoteAttachments,
        NoteFile,
        NoteInclusionProof,
        NoteRecipient,
        NoteScript,
        NoteStorage,
        NoteSyncHint,
        NoteTag,
        NoteType,
        PartialNoteMetadata,
    };
    use crate::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    };
    use crate::utils::serde::{Deserializable, Serializable};

    fn create_example_note() -> Note {
        let faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
        let target =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE).unwrap();

        let serial_num = Word::from([0, 1, 2, 3u32]);
        let script = NoteScript::mock();
        let note_storage = NoteStorage::new(vec![target.prefix().into()]).unwrap();
        let recipient = NoteRecipient::new(serial_num, script, note_storage);

        let asset = Asset::Fungible(FungibleAsset::new(faucet, 100).unwrap());
        let metadata =
            PartialNoteMetadata::new(faucet, NoteType::Public).with_tag(NoteTag::from(123));

        Note::new(NoteAssets::new(vec![asset]).unwrap(), metadata, recipient)
    }

    fn create_example_note_with_attachment() -> Note {
        let faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
        let target =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE).unwrap();

        let serial_num = Word::from([0, 1, 2, 3u32]);
        let script = NoteScript::mock();
        let note_storage = NoteStorage::new(vec![target.prefix().into()]).unwrap();
        let recipient = NoteRecipient::new(serial_num, script, note_storage);

        let asset = Asset::Fungible(FungibleAsset::new(faucet, 100).unwrap());
        let metadata =
            PartialNoteMetadata::new(faucet, NoteType::Public).with_tag(NoteTag::from(123));
        let attachment = NoteAttachment::with_word(
            NoteAttachmentScheme::new(42).unwrap(),
            Word::from([10, 20, 30, 40u32]),
        );
        let attachments = NoteAttachments::from(attachment);

        Note::with_attachments(
            NoteAssets::new(vec![asset]).unwrap(),
            metadata,
            recipient,
            attachments,
        )
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

    #[test]
    fn serialize_id() {
        let note = create_example_note();
        let file = NoteFile::NoteId(note.id());
        let mut buffer = Vec::new();
        file.write_into(&mut buffer);

        let file_copy = NoteFile::read_from_bytes(&buffer).unwrap();

        match file_copy {
            NoteFile::NoteId(note_id) => {
                assert_eq!(note.id(), note_id);
            },
            _ => panic!("Invalid note file variant"),
        }
    }

    #[test]
    fn serialize_expected_note() {
        let note = create_example_note();
        let sync_hint = NoteSyncHint::new(456.into(), NoteTag::from(123));
        let file = NoteFile::ExpectedNote {
            details: note.details.clone(),
            attachments: NoteAttachments::empty(),
            sync_hint,
        };
        let mut buffer = Vec::new();
        file.write_into(&mut buffer);

        let file_copy = NoteFile::read_from_bytes(&buffer).unwrap();

        match file_copy {
            NoteFile::ExpectedNote {
                details,
                attachments,
                sync_hint: actual_sync_hint,
            } => {
                assert_eq!(details, note.details);
                assert!(attachments.is_empty());
                assert_eq!(actual_sync_hint, sync_hint);
            },
            _ => panic!("Invalid note file variant"),
        }
    }

    #[test]
    fn serialize_expected_note_with_attachments() {
        let note = create_example_note_with_attachment();
        let sync_hint = NoteSyncHint::new(456.into(), NoteTag::from(123));
        let file = NoteFile::ExpectedNote {
            details: note.details.clone(),
            attachments: note.attachments().clone(),
            sync_hint,
        };
        let mut buffer = Vec::new();
        file.write_into(&mut buffer);

        let file_copy = NoteFile::read_from_bytes(&buffer).unwrap();

        match file_copy {
            NoteFile::ExpectedNote {
                details,
                attachments,
                sync_hint: actual_sync_hint,
            } => {
                assert_eq!(details, note.details);
                assert_eq!(&attachments, note.attachments());
                assert!(!attachments.is_empty());
                assert_eq!(actual_sync_hint, sync_hint);
            },
            _ => panic!("Invalid note file variant"),
        }
    }

    #[test]
    fn serialize_committed_note() {
        let note = create_example_note();
        let mock_inclusion_proof =
            NoteInclusionProof::new(BlockNumber::from(0), 0, Default::default()).unwrap();
        let file = NoteFile::Committed {
            note: note.clone(),
            proof: mock_inclusion_proof.clone(),
        };
        let mut buffer = Vec::new();
        file.write_into(&mut buffer);

        let file_copy = NoteFile::read_from_bytes(&buffer).unwrap();

        match file_copy {
            NoteFile::Committed {
                note: note_copy,
                proof: inclusion_proof_copy,
            } => {
                assert_eq!(note, note_copy);
                assert_eq!(inclusion_proof_copy, mock_inclusion_proof);
            },
            _ => panic!("Invalid note file variant"),
        }
    }
}
