use alloc::vec::Vec;
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
use crate::Felt;

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
        let (_, _, digest) = compute_recipient_chain(serial_num, &script, &storage);
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

    /// Returns the advice map entries opening every link of the recipient's hash chain.
    ///
    /// They allow the VM to recover the note's script root and storage commitment from the
    /// recipient alone, which is all a note is committed to on chain.
    pub fn to_advice_map_entries(&self) -> [(Word, Vec<Felt>); 5] {
        let (serial_commitment, serial_script_commitment, digest) =
            compute_recipient_chain(self.serial_num, &self.script, &self.storage);
        let script_root = Word::from(self.script.root());
        let script_encoded = <Vec<Felt>>::from(&self.script);

        [
            (serial_commitment, concat_words(self.serial_num, Word::empty())),
            (serial_script_commitment, concat_words(serial_commitment, script_root)),
            (digest, concat_words(serial_script_commitment, self.storage.commitment())),
            (self.storage().commitment(), self.storage().to_elements()),
            (script_root, script_encoded),
        ]
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Removes debug info associated with the script, if any.
    pub fn clear_debug_info(&mut self) {
        self.script.clear_debug_info();
    }

    /// Consumes self and returns the underlying parts of the [`NoteRecipient`].
    pub fn into_parts(self) -> (Word, NoteScript, NoteStorage) {
        (self.serial_num, self.script, self.storage)
    }
}

/// Returns the links of the recipient's hash chain: the serial commitment, the serial-script
/// commitment and the recipient digest itself.
fn compute_recipient_chain(
    serial_num: Word,
    script: &NoteScript,
    storage: &NoteStorage,
) -> (Word, Word, Word) {
    let serial_commitment = Hasher::merge(&[serial_num, Word::empty()]);
    let serial_script_commitment = Hasher::merge(&[serial_commitment, script.root().into()]);
    let recipient_digest = Hasher::merge(&[serial_script_commitment, storage.commitment()]);

    (serial_commitment, serial_script_commitment, recipient_digest)
}

fn concat_words(first: Word, second: Word) -> Vec<Felt> {
    let mut elements = Vec::with_capacity(2 * Word::NUM_ELEMENTS);
    elements.extend(first);
    elements.extend(second);
    elements
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
