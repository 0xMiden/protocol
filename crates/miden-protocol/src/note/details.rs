use miden_processor::DeserializationError;

use super::{NoteAssets, NoteId, NoteRecipient, NoteScript, NoteStorage, Nullifier};
use crate::Word;
use crate::utils::serde::{ByteReader, ByteWriter, Deserializable, Serializable};

// NOTE DETAILS
// ================================================================================================

/// Details of a note consisting of assets, script, storage, and a serial number.
///
/// See [super::Note] for more details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteDetails {
    assets: NoteAssets,
    recipient: NoteRecipient,
}

impl NoteDetails {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new note created with the specified parameters.
    pub fn new(assets: NoteAssets, recipient: NoteRecipient) -> Self {
        Self { assets, recipient }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the note's unique identifier.
    ///
    /// This value is both an unique identifier and a commitment to the note.
    pub fn id(&self) -> NoteId {
        NoteId::from(self)
    }

    /// Returns the note's assets.
    pub fn assets(&self) -> &NoteAssets {
        &self.assets
    }

    /// Returns the note's recipient serial_num, the secret required to consume the note.
    pub fn serial_num(&self) -> Word {
        self.recipient.serial_num()
    }

    /// Returns the note's recipient script which locks the assets of this note.
    pub fn script(&self) -> &NoteScript {
        self.recipient.script()
    }

    /// Returns the note's recipient storage which customizes the script's behavior.
    pub fn storage(&self) -> &NoteStorage {
        self.recipient.storage()
    }

    /// Returns the note's recipient.
    pub fn recipient(&self) -> &NoteRecipient {
        &self.recipient
    }

    /// Returns the note's nullifier.
    ///
    /// This is public data, used to prevent double spend.
    pub fn nullifier(&self) -> Nullifier {
        Nullifier::from(self)
    }

    /// Decomposes note details into underlying assets and recipient.
    pub fn into_parts(self) -> (NoteAssets, NoteRecipient) {
        (self.assets, self.recipient)
    }
}

// AS REF
// ================================================================================================

impl AsRef<NoteRecipient> for NoteDetails {
    fn as_ref(&self) -> &NoteRecipient {
        self.recipient()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteDetails {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { assets, recipient } = self;

        assets.write_into(target);
        recipient.write_into(target);
    }
}

impl Deserializable for NoteDetails {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let assets = NoteAssets::read_from(source)?;
        let recipient = NoteRecipient::read_from(source)?;
        Ok(Self::new(assets, recipient))
    }
}
