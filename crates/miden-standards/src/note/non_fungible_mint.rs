use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachments,
    NoteRecipient,
    NoteScript,
    NoteScriptRoot,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS, Word};

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the non-fungible MINT note script procedure in the standards library.
const MINT_SCRIPT_PATH: &str = "::miden::standards::notes::mint_nft::main";

static MINT_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(MINT_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains non-fungible MINT note script procedure")
});

// NON-FUNGIBLE MINT NOTE
// ================================================================================================

/// A note that instructs a non-fungible network faucet to mint the NFT for the embedded
/// commitment.
pub struct NonFungibleMintNote;

impl NonFungibleMintNote {
    /// Expected number of storage items of the MINT note (private mode).
    ///
    /// Layout: RECIPIENT(4) + COMMITMENT(4) + tag(1).
    pub const NUM_STORAGE_ITEMS_PRIVATE: usize = 9;

    /// Minimum number of storage items of the MINT note (public mode).
    ///
    /// Layout: SCRIPT_ROOT(4) + SERIAL_NUM(4) + COMMITMENT(4) + tag(1) + padding(3) + variable
    /// output-note storage (word-aligned at offset 16).
    pub const MIN_NUM_STORAGE_ITEMS_PUBLIC: usize = 16;

    /// Returns the script of the non-fungible MINT note.
    pub fn script() -> NoteScript {
        MINT_SCRIPT.clone()
    }

    /// Returns the non-fungible MINT note script root.
    pub fn script_root() -> NoteScriptRoot {
        MINT_SCRIPT.root()
    }

    /// Generates a MINT note: a public note that, when consumed by a non-fungible network faucet,
    /// mints the NFT for the embedded commitment (calling `non_fungible::mint_and_send`).
    ///
    /// # Parameters
    /// - `faucet_id`: The account ID of the network faucet that will mint the asset (used for the
    ///   note tag / routing).
    /// - `sender`: The account ID of the note creator.
    /// - `mint_storage`: The storage configuration specifying private or public output mode.
    /// - `attachments`: The [`NoteAttachments`] of the MINT note.
    /// - `rng`: Random number generator for the serial number.
    pub fn create<R: FeltRng>(
        faucet_id: AccountId,
        sender: AccountId,
        mint_storage: NonFungibleMintNoteStorage,
        attachments: NoteAttachments,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let note_script = Self::script();
        let serial_num = rng.draw_word();
        let note_type = NoteType::Public;

        let storage = NoteStorage::from(mint_storage);
        let tag = NoteTag::with_account_target(faucet_id);

        let metadata = PartialNoteMetadata::new(sender, note_type).with_tag(tag);
        let assets = NoteAssets::new(vec![])?;
        let recipient = NoteRecipient::new(serial_num, note_script, storage);

        Ok(Note::with_attachments(assets, metadata, recipient, attachments))
    }
}

// NON-FUNGIBLE MINT NOTE STORAGE
// ================================================================================================

/// Storage formats for non-fungible MINT notes.
///
/// - Private: creates a private output note from a precomputed recipient digest (9 items: RECIPIENT
///   + COMMITMENT + tag).
/// - Public: creates a public output note from a script root, serial number, and variable-length
///   storage (16+ items, the variable section word-aligned at offset 16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonFungibleMintNoteStorage {
    Private {
        recipient_digest: Word,
        commitment: Word,
        tag: Felt,
    },
    Public {
        recipient: NoteRecipient,
        commitment: Word,
        tag: Felt,
    },
}

impl NonFungibleMintNoteStorage {
    pub fn new_private(recipient_digest: Word, commitment: Word, tag: Felt) -> Self {
        Self::Private { recipient_digest, commitment, tag }
    }

    pub fn new_public(
        recipient: NoteRecipient,
        commitment: Word,
        tag: Felt,
    ) -> Result<Self, NoteError> {
        let total_storage_items = NonFungibleMintNote::MIN_NUM_STORAGE_ITEMS_PUBLIC
            + recipient.storage().num_items() as usize;

        if total_storage_items > MAX_NOTE_STORAGE_ITEMS {
            return Err(NoteError::TooManyStorageItems(total_storage_items));
        }

        Ok(Self::Public { recipient, commitment, tag })
    }

    /// Returns the asset commitment that will be minted on consumption.
    pub fn commitment(&self) -> Word {
        match self {
            Self::Private { commitment, .. } | Self::Public { commitment, .. } => *commitment,
        }
    }
}

impl From<NonFungibleMintNoteStorage> for NoteStorage {
    fn from(mint_storage: NonFungibleMintNoteStorage) -> Self {
        match mint_storage {
            NonFungibleMintNoteStorage::Private { recipient_digest, commitment, tag } => {
                let mut storage_values =
                    Vec::with_capacity(NonFungibleMintNote::NUM_STORAGE_ITEMS_PRIVATE);
                storage_values.extend_from_slice(recipient_digest.as_elements());
                storage_values.extend_from_slice(commitment.as_elements());
                storage_values.push(tag);
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
            NonFungibleMintNoteStorage::Public { recipient, commitment, tag } => {
                let mut storage_values = Vec::new();
                storage_values.extend_from_slice(recipient.script().root().as_elements());
                storage_values.extend_from_slice(recipient.serial_num().as_elements());
                storage_values.extend_from_slice(commitment.as_elements());
                storage_values.extend_from_slice(&[tag, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
                storage_values.extend_from_slice(recipient.storage().items());
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
        }
    }
}
