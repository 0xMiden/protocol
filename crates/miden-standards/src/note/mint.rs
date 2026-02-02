use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS, Word};

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the MINT note script procedure in the standards library.
const MINT_SCRIPT_PATH: &str = "::miden::standards::notes::mint::main";

// Initialize the MINT note script only once
static MINT_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(MINT_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains MINT note script procedure")
});

// MINT NOTE
// ================================================================================================

/// TODO: add docs
pub struct MintNote;

impl MintNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the MINT note (private mode).
    pub const NUM_STORAGE_ITEMS_PRIVATE: usize = 8;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the MINT note.
    pub fn script() -> NoteScript {
        MINT_SCRIPT.clone()
    }

    /// Returns the MINT note script root.
    pub fn script_root() -> Word {
        MINT_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Generates a MINT note - a note that instructs a network faucet to mint fungible assets.
    ///
    /// This script enables the creation of a PUBLIC note that, when consumed by a network faucet,
    /// will mint the specified amount of fungible assets and create either a PRIVATE or PUBLIC
    /// output note depending on the input configuration. The MINT note uses note-based
    /// authentication, checking if the note sender equals the faucet owner to authorize
    /// minting.
    ///
    /// MINT notes are always PUBLIC (for network execution). Output notes can be either PRIVATE
    /// or PUBLIC depending on the MintNoteStorage variant used.
    ///
    /// The passed-in `rng` is used to generate a serial number for the note. The note's tag
    /// is automatically set to the faucet's account ID for proper routing.
    ///
    /// # Parameters
    /// - `faucet_id`: The account ID of the network faucet that will mint the assets
    /// - `sender`: The account ID of the note creator (must be the faucet owner)
    /// - `mint_storage`: The storage configuration specifying private or public output mode
    /// - `attachment`: The [`NoteAttachment`] of the MINT note
    /// - `rng`: Random number generator for creating the serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        faucet_id: AccountId,
        sender: AccountId,
        mint_storage: MintNoteStorage,
        attachment: NoteAttachment,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let note_script = Self::script();
        let serial_num = rng.draw_word();

        // MINT notes are always public for network execution
        let note_type = NoteType::Public;

        // Convert MintNoteStorage to NoteStorage
        let storage = NoteStorage::from(mint_storage);

        let tag = NoteTag::with_account_target(faucet_id);

        let metadata = NoteMetadata::new(sender, note_type, tag).with_attachment(attachment);
        let assets = NoteAssets::new(vec![])?; // MINT notes have no assets
        let recipient = NoteRecipient::new(serial_num, note_script, storage);

        Ok(Note::new(assets, metadata, recipient))
    }
}

// MINT NOTE STORAGE
// ================================================================================================

/// Represents the different storage formats for MINT notes.
/// - Private: Creates a private output note using a precomputed recipient digest (12 MINT note
///   storage items)
/// - Public: Creates a public output note by providing script root, serial number, and
///   variable-length storage (16+ MINT note storage items: 16 fixed + variable number of output
///   note storage items)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintNoteStorage {
    Private {
        recipient_digest: Word,
        amount: Felt,
        tag: Felt,
        attachment: NoteAttachment,
    },
    Public {
        recipient: NoteRecipient,
        amount: Felt,
        tag: Felt,
        attachment: NoteAttachment,
    },
}

impl MintNoteStorage {
    pub fn new_private(recipient_digest: Word, amount: Felt, tag: Felt) -> Self {
        Self::Private {
            recipient_digest,
            amount,
            tag,
            attachment: NoteAttachment::default(),
        }
    }

    pub fn new_public(
        recipient: NoteRecipient,
        amount: Felt,
        tag: Felt,
    ) -> Result<Self, NoteError> {
        // Calculate total number of storage items that will be created:
        // 16 fixed items (tag, amount, attachment_kind, attachment_scheme, ATTACHMENT,
        // SCRIPT_ROOT, SERIAL_NUM) + variable recipient number of storage items
        const FIXED_PUBLIC_STORAGE_ITEMS: usize = 16;
        let total_storage_items =
            FIXED_PUBLIC_STORAGE_ITEMS + recipient.storage().num_items() as usize;

        if total_storage_items > MAX_NOTE_STORAGE_ITEMS {
            return Err(NoteError::TooManyStorageItems(total_storage_items));
        }

        Ok(Self::Public {
            recipient,
            amount,
            tag,
            attachment: NoteAttachment::default(),
        })
    }

    /// Overwrites the [`NoteAttachment`] of the note storage.
    pub fn with_attachment(self, attachment: NoteAttachment) -> Self {
        match self {
            MintNoteStorage::Private {
                recipient_digest,
                amount,
                tag,
                attachment: _,
            } => MintNoteStorage::Private {
                recipient_digest,
                amount,
                tag,
                attachment,
            },
            MintNoteStorage::Public { recipient, amount, tag, attachment: _ } => {
                MintNoteStorage::Public { recipient, amount, tag, attachment }
            },
        }
    }
}

impl From<MintNoteStorage> for NoteStorage {
    fn from(mint_storage: MintNoteStorage) -> Self {
        match mint_storage {
            MintNoteStorage::Private {
                recipient_digest,
                amount,
                tag,
                attachment,
            } => {
                let attachment_scheme = Felt::from(attachment.attachment_scheme().as_u32());
                let attachment_kind = Felt::from(attachment.attachment_kind().as_u8());
                let attachment = attachment.content().to_word();

                let mut storage_values = Vec::with_capacity(12);
                storage_values.extend_from_slice(&[
                    tag,
                    amount,
                    attachment_kind,
                    attachment_scheme,
                ]);
                storage_values.extend_from_slice(attachment.as_elements());
                storage_values.extend_from_slice(recipient_digest.as_elements());
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
            MintNoteStorage::Public { recipient, amount, tag, attachment } => {
                let attachment_scheme = Felt::from(attachment.attachment_scheme().as_u32());
                let attachment_kind = Felt::from(attachment.attachment_kind().as_u8());
                let attachment = attachment.content().to_word();

                let mut storage_values = vec![tag, amount, attachment_kind, attachment_scheme];
                storage_values.extend_from_slice(attachment.as_elements());
                storage_values.extend_from_slice(recipient.script().root().as_elements());
                storage_values.extend_from_slice(recipient.serial_num().as_elements());
                storage_values.extend_from_slice(recipient.storage().items());
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
        }
    }
}
