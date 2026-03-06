use core::fmt::Debug;

use super::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Hasher,
    NoteScript,
    NoteStorage,
    Serializable,
    Word,
};

/// Value that describes under which condition a note can be consumed.
///
/// The recipient is not an account address, instead it is a value that describes when a note
/// can be consumed. Because not all notes have predetermined consumer addresses, e.g. swap
/// notes can be consumed by anyone, the recipient is defined as the code and its storage, that
/// when successfully executed results in the note's consumption.
///
/// Recipient is computed as:
///
/// > hash(hash(hash(serial_num, [0; 4]), script_root), storage_commitment)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteRecipient {
    serial_num: Word,
    script: NoteScript,
    storage: NoteStorage,
    digest: Word,
}

impl NoteRecipient {
    pub fn new(serial_num: Word, script: NoteScript, storage: NoteStorage) -> Self {
        let digest = compute_recipient_digest(serial_num, &script, &storage);
        Self { serial_num, script, storage, digest }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// The recipient's serial_num, the secret required to consume the note.
    pub fn serial_num(&self) -> Word {
        self.serial_num
    }

    /// The recipients's script which locks the assets of this note.
    pub fn script(&self) -> &NoteScript {
        &self.script
    }

    /// The recipient's storage which customizes the script's behavior.
    pub fn storage(&self) -> &NoteStorage {
        &self.storage
    }

    /// The recipient's digest, which commits to its details.
    ///
    /// This is the public data required to create a note.
    pub fn digest(&self) -> Word {
        self.digest
    }

    /// Consumes self and returns the underlying parts of the [`NoteRecipient`].
    pub fn into_parts(self) -> (Word, NoteScript, NoteStorage) {
        (self.serial_num, self.script, self.storage)
    }
}

fn compute_recipient_digest(serial_num: Word, script: &NoteScript, storage: &NoteStorage) -> Word {
    let serial_num_hash = Hasher::merge(&[serial_num, Word::empty()]);
    let merge_script = Hasher::merge(&[serial_num_hash, script.root()]);
    Hasher::merge(&[merge_script, storage.commitment()])
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteRecipient {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self {
            script,
            storage,
            serial_num,

            // These attributes don't have to be serialized, they can be re-computed from the rest
            // of the data
            digest: _,
        } = self;

        script.write_into(target);
        storage.write_into(target);
        serial_num.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.script.get_size_hint() + self.storage.get_size_hint() + Word::SERIALIZED_SIZE
    }
}

impl Deserializable for NoteRecipient {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let script = NoteScript::read_from(source)?;
        let storage = NoteStorage::read_from(source)?;
        let serial_num = Word::read_from(source)?;

        Ok(Self::new(serial_num, script, storage))
    }
}
