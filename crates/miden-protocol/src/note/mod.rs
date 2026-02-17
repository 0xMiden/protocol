use miden_crypto::Word;
use miden_crypto::utils::{ByteReader, ByteWriter, Deserializable, Serializable};
use miden_processor::DeserializationError;

use crate::account::AccountId;
use crate::errors::NoteError;
use crate::{Felt, Hasher, WORD_SIZE, ZERO};

mod assets;
pub use assets::NoteAssets;

mod details;
pub use details::NoteDetails;

mod header;
pub use header::{NoteHeader, compute_note_commitment};

mod storage;
pub use storage::NoteStorage;

mod metadata;
pub use metadata::NoteMetadata;

mod attachment;
pub use attachment::{
    NoteAttachment,
    NoteAttachmentArray,
    NoteAttachmentContent,
    NoteAttachmentKind,
    NoteAttachmentScheme,
};

mod note_id;
pub use note_id::NoteId;

mod note_tag;
pub use note_tag::NoteTag;

mod note_type;
pub use note_type::NoteType;

mod nullifier;
pub use nullifier::Nullifier;

mod location;
pub use location::{NoteInclusionProof, NoteLocation};

mod partial;
pub use partial::PartialNote;

mod recipient;
pub use recipient::NoteRecipient;

mod script;
pub use script::NoteScript;

mod file;
pub use file::NoteFile;

// NOTE
// ================================================================================================

/// A note with all the data required for it to be consumed by executing it against the transaction
/// kernel.
///
/// Notes consist of note metadata and details. Note metadata is always public, but details may be
/// either public, encrypted, or private, depending on the note type. Note details consist of note
/// assets, script, storage, and a serial number, the three latter grouped into a recipient object.
///
/// Note details can be reduced to two unique identifiers: [NoteId] and [Nullifier]. The former is
/// publicly associated with a note, while the latter is known only to entities which have access
/// to full note details.
///
/// Fungible and non-fungible asset transfers are done by moving assets to the note's assets. The
/// note's script determines the conditions required for the note consumption, i.e. the target
/// account of a P2ID or conditions of a SWAP, and the effects of the note. The serial number has
/// a double duty of preventing double spend, and providing unlikability to the consumer of a note.
/// The note's storage allows for customization of its script.
///
/// To create a note, the kernel does not require all the information above, a user can create a
/// note only with the commitment to the script, storage, the serial number (i.e., the recipient),
/// and the kernel only verifies the source account has the assets necessary for the note creation.
/// See [NoteRecipient] for more details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    header: NoteHeader,
    details: NoteDetails,

    nullifier: Nullifier,
}

impl Note {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [Note] created with the specified parameters.
    pub fn new(assets: NoteAssets, metadata: NoteMetadata, recipient: NoteRecipient) -> Self {
        let details = NoteDetails::new(assets, recipient);
        let header = NoteHeader::new(details.id(), metadata);
        let nullifier = details.nullifier();

        Self { header, details, nullifier }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the note's header.
    pub fn header(&self) -> &NoteHeader {
        &self.header
    }

    /// Returns the note's unique identifier.
    ///
    /// This value is both an unique identifier and a commitment to the note.
    pub fn id(&self) -> NoteId {
        self.header.id()
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        self.header.metadata()
    }

    /// Returns the note's assets.
    pub fn assets(&self) -> &NoteAssets {
        self.details.assets()
    }

    /// Returns the note's recipient serial_num, the secret required to consume the note.
    pub fn serial_num(&self) -> Word {
        self.details.serial_num()
    }

    /// Returns the note's recipient script which locks the assets of this note.
    pub fn script(&self) -> &NoteScript {
        self.details.script()
    }

    /// Returns the note's recipient storage which customizes the script's behavior.
    pub fn storage(&self) -> &NoteStorage {
        self.details.storage()
    }

    /// Returns the note's recipient.
    pub fn recipient(&self) -> &NoteRecipient {
        self.details.recipient()
    }

    /// Returns the note's nullifier.
    ///
    /// This is public data, used to prevent double spend.
    pub fn nullifier(&self) -> Nullifier {
        self.nullifier
    }

    /// Returns a commitment to the note and its metadata.
    ///
    /// > hash(NOTE_ID || NOTE_METADATA_COMMITMENT)
    ///
    /// This value is used primarily for authenticating notes consumed when the are consumed
    /// in a transaction.
    pub fn commitment(&self) -> Word {
        self.header.commitment()
    }
}

// AS REF
// ================================================================================================

impl AsRef<NoteRecipient> for Note {
    fn as_ref(&self) -> &NoteRecipient {
        self.recipient()
    }
}

// CONVERSIONS FROM NOTE
// ================================================================================================

impl From<Note> for NoteHeader {
    fn from(note: Note) -> Self {
        note.header
    }
}

impl From<&Note> for NoteDetails {
    fn from(note: &Note) -> Self {
        note.details.clone()
    }
}

impl From<Note> for NoteDetails {
    fn from(note: Note) -> Self {
        note.details
    }
}

impl From<Note> for PartialNote {
    fn from(note: Note) -> Self {
        let (assets, recipient, ..) = note.details.into_parts();
        PartialNote::new(note.header.into_metadata(), recipient.digest(), assets)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Note {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self {
            header,
            details,

            // nullifier is not serialized as it can be computed from the rest of the data
            nullifier: _,
        } = self;

        // only metadata is serialized as note ID can be computed from note details
        header.metadata().write_into(target);
        details.write_into(target);
    }
}

impl Deserializable for Note {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let metadata = NoteMetadata::read_from(source)?;
        let details = NoteDetails::read_from(source)?;
        let (assets, recipient) = details.into_parts();

        Ok(Self::new(assets, metadata, recipient))
    }
}
