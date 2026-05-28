use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::{Asset, FungibleAsset};
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
    ///
    /// Layout: RECIPIENT(4) + ASSET_KEY(4) + ASSET_VALUE(4) + tag(1).
    pub const NUM_STORAGE_ITEMS_PRIVATE: usize = 13;

    /// Minimum number of storage items of the MINT note (public mode).
    ///
    /// Layout: SCRIPT_ROOT(4) + SERIAL_NUM(4) + ASSET_KEY(4) + ASSET_VALUE(4) + tag(1) +
    /// padding(3) + variable output-note storage. The variable portion starts at offset 20
    /// (word-aligned) and may contain zero or more items.
    pub const MIN_NUM_STORAGE_ITEMS_PUBLIC: usize = 20;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the MINT note.
    pub fn script() -> NoteScript {
        MINT_SCRIPT.clone()
    }

    /// Returns the MINT note script root.
    pub fn script_root() -> NoteScriptRoot {
        MINT_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Generates a MINT note: a note that instructs a network faucet to mint the asset
    /// embedded in its storage.
    ///
    /// The MINT script reads the asset (`ASSET_KEY` + `ASSET_VALUE`) directly from the note's
    /// storage and passes it to the faucet's `mint_and_send` procedure, which rejects an asset
    /// that does not belong to the consuming faucet. A MINT note bound to faucet A therefore
    /// cannot be redirected to faucet B even when both share an owner.
    ///
    /// MINT notes are always PUBLIC (for network execution). Output notes can be either PRIVATE
    /// or PUBLIC depending on the [`MintNoteStorage`] variant used.
    ///
    /// The passed-in `rng` is used to generate a serial number for the note. The note's tag
    /// is automatically set to the faucet's account ID for proper routing.
    ///
    /// # Parameters
    /// - `faucet_id`: The account ID of the network faucet that will mint the asset. Must equal the
    ///   faucet ID of the asset embedded in `mint_storage`.
    /// - `sender`: The account ID of the note creator (must be the faucet owner)
    /// - `mint_storage`: The storage configuration specifying private or public output mode
    /// - `attachments`: The [`NoteAttachments`] of the MINT note
    /// - `rng`: Random number generator for creating the serial number
    ///
    /// # Errors
    /// Returns an error if `faucet_id` does not match the faucet of the embedded asset, or if
    /// note creation fails.
    pub fn create<R: FeltRng>(
        faucet_id: AccountId,
        sender: AccountId,
        mint_storage: MintNoteStorage,
        attachments: NoteAttachments,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        if faucet_id != mint_storage.asset().faucet_id() {
            return Err(NoteError::other(
                "faucet_id must equal the faucet ID of the asset embedded in mint_storage",
            ));
        }

        let note_script = Self::script();
        let serial_num = rng.draw_word();

        // MINT notes are always public for network execution
        let note_type = NoteType::Public;

        // Convert MintNoteStorage to NoteStorage
        let storage = NoteStorage::from(mint_storage);

        let tag = NoteTag::with_account_target(faucet_id);

        let metadata = PartialNoteMetadata::new(sender, note_type).with_tag(tag);
        let assets = NoteAssets::new(vec![])?; // MINT notes have no assets
        let recipient = NoteRecipient::new(serial_num, note_script, storage);

        Ok(Note::with_attachments(assets, metadata, recipient, attachments))
    }
}

// MINT NOTE STORAGE
// ================================================================================================

/// Represents the different storage formats for MINT notes.
///
/// - Private: Creates a private output note using a precomputed recipient digest (13 MINT note
///   storage items: RECIPIENT + ASSET_KEY + ASSET_VALUE + tag).
/// - Public: Creates a public output note by providing script root, serial number, and
///   variable-length storage (20+ MINT note storage items: 20 fixed + variable output note storage
///   items, with the variable section word-aligned at offset 20).
///
/// The asset (`ASSET_KEY` + `ASSET_VALUE`, 8 felts) is embedded in storage so that the
/// faucet executing the MINT note can be checked against the asset's faucet ID at mint time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintNoteStorage {
    Private {
        recipient_digest: Word,
        asset: FungibleAsset,
        tag: Felt,
    },
    Public {
        recipient: NoteRecipient,
        asset: FungibleAsset,
        tag: Felt,
    },
}

impl MintNoteStorage {
    pub fn new_private(recipient_digest: Word, asset: FungibleAsset, tag: Felt) -> Self {
        Self::Private { recipient_digest, asset, tag }
    }

    pub fn new_public(
        recipient: NoteRecipient,
        asset: FungibleAsset,
        tag: Felt,
    ) -> Result<Self, NoteError> {
        let total_storage_items =
            MintNote::MIN_NUM_STORAGE_ITEMS_PUBLIC + recipient.storage().num_items() as usize;

        if total_storage_items > MAX_NOTE_STORAGE_ITEMS {
            return Err(NoteError::TooManyStorageItems(total_storage_items));
        }

        Ok(Self::Public { recipient, asset, tag })
    }

    /// Returns the asset that will be minted on consumption.
    pub fn asset(&self) -> FungibleAsset {
        match self {
            Self::Private { asset, .. } | Self::Public { asset, .. } => *asset,
        }
    }
}

impl From<MintNoteStorage> for NoteStorage {
    fn from(mint_storage: MintNoteStorage) -> Self {
        match mint_storage {
            MintNoteStorage::Private { recipient_digest, asset, tag } => {
                let mut storage_values = Vec::with_capacity(MintNote::NUM_STORAGE_ITEMS_PRIVATE);
                storage_values.extend_from_slice(recipient_digest.as_elements());
                storage_values.extend_from_slice(&Asset::from(asset).as_elements());
                storage_values.push(tag);
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
            MintNoteStorage::Public { recipient, asset, tag } => {
                let mut storage_values = Vec::new();
                storage_values.extend_from_slice(recipient.script().root().as_elements());
                storage_values.extend_from_slice(recipient.serial_num().as_elements());
                storage_values.extend_from_slice(&Asset::from(asset).as_elements());
                // tag followed by 3 padding felts so the variable storage that follows starts at
                // a word-aligned offset (20).
                storage_values.extend_from_slice(&[tag, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
                storage_values.extend_from_slice(recipient.storage().items());
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
        }
    }
}
