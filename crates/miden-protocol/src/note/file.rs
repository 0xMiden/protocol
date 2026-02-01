#[cfg(feature = "std")]
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
    vec::Vec,
};

#[cfg(feature = "std")]
use miden_core::utils::SliceReader;
use miden_core::utils::{ByteReader, ByteWriter, Deserializable, Serializable};
use miden_processor::DeserializationError;

use super::{Note, NoteDetails, NoteId, NoteInclusionProof, NoteTag};
use crate::block::BlockNumber;

const MAGIC: &str = "note";

// NOTE FILE
// ================================================================================================

/// A serialized representation of a note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoteFile {
    /// The note's details aren't known.
    NoteId(NoteId),
    /// The note may or may not have already been recorded on chain.
    ///
    /// The `after_block_num` specifies the block after which the note is expected to appear on
    /// chain. Though this should be treated as a hint (i.e., there is no guarantee that the note
    /// will appear on chain or that it will in fact appear after the specified block).
    ///
    /// An optional tag specifies the tag associated with the note, though this also should be
    /// treated as a hint.
    NoteDetails {
        details: NoteDetails,
        after_block_num: BlockNumber,
        tag: Option<NoteTag>,
    },
    /// The note has been recorded on chain.
    NoteWithProof(Note, NoteInclusionProof),
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

impl From<NoteDetails> for NoteFile {
    fn from(details: NoteDetails) -> Self {
        NoteFile::NoteDetails {
            details,
            after_block_num: 0.into(),
            tag: None,
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
            NoteFile::NoteDetails { details, after_block_num, tag } => {
                target.write_u8(1);
                details.write_into(target);
                after_block_num.write_into(target);
                tag.write_into(target);
            },
            NoteFile::NoteWithProof(note, proof) => {
                target.write_u8(2);
                note.write_into(target);
                proof.write_into(target);
            },
        }
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
                let after_block_num = BlockNumber::read_from(source)?;
                let tag = Option::<NoteTag>::read_from(source)?;
                Ok(NoteFile::NoteDetails { details, after_block_num, tag })
            },
            2 => {
                let note = Note::read_from(source)?;
                let proof = NoteInclusionProof::read_from(source)?;
                Ok(NoteFile::NoteWithProof(note, proof))
            },
            v => {
                Err(DeserializationError::InvalidValue(format!("unknown variant {v} for NoteFile")))
            },
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::utils::{Deserializable, Serializable};

    use crate::Word;
    use crate::account::AccountId;
    use crate::asset::{Asset, FungibleAsset};
    use crate::block::BlockNumber;
    use crate::note::{
        Note,
        NoteAssets,
        NoteFile,
        NoteInclusionProof,
        NoteMetadata,
        NoteRecipient,
        NoteScript,
        NoteStorage,
        NoteTag,
        NoteType,
    };
    use crate::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    };

    fn create_example_note() -> Note {
        let faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
        let target =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE).unwrap();

        let serial_num = Word::from([0, 1, 2, 3u32]);
        let script = NoteScript::mock();
        let note_storage = NoteStorage::new(vec![target.prefix().into()]).unwrap();
        let recipient = NoteRecipient::new(serial_num, script, note_storage);

        let asset = Asset::Fungible(FungibleAsset::new(faucet, 100).unwrap());
        let metadata = NoteMetadata::new(faucet, NoteType::Public, NoteTag::from(123));

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
    fn serialize_details() {
        let note = create_example_note();
        let file = NoteFile::NoteDetails {
            details: note.details.clone(),
            after_block_num: 456.into(),
            tag: Some(NoteTag::from(123)),
        };
        let mut buffer = Vec::new();
        file.write_into(&mut buffer);

        let file_copy = NoteFile::read_from_bytes(&buffer).unwrap();

        match file_copy {
            NoteFile::NoteDetails { details, after_block_num, tag } => {
                assert_eq!(details, note.details);
                assert_eq!(after_block_num, 456.into());
                assert_eq!(tag, Some(NoteTag::from(123)));
            },
            _ => panic!("Invalid note file variant"),
        }
    }

    #[test]
    fn serialize_with_proof() {
        let note = create_example_note();
        let mock_inclusion_proof =
            NoteInclusionProof::new(BlockNumber::from(0), 0, Default::default()).unwrap();
        let file = NoteFile::NoteWithProof(note.clone(), mock_inclusion_proof.clone());
        let mut buffer = Vec::new();
        file.write_into(&mut buffer);

        let file_copy = NoteFile::read_from_bytes(&buffer).unwrap();

        match file_copy {
            NoteFile::NoteWithProof(note_copy, inclusion_proof_copy) => {
                assert_eq!(note, note_copy);
                assert_eq!(inclusion_proof_copy, mock_inclusion_proof);
            },
            _ => panic!("Invalid note file variant"),
        }
    }
}
