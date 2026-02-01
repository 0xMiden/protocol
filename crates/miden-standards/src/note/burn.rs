use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::assembly::Library;
use miden_protocol::asset::Asset;
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
use miden_protocol::utils::Deserializable;
use miden_protocol::utils::sync::LazyLock;

// NOTE SCRIPT
// ================================================================================================

// Initialize the BURN note script only once
static BURN_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/burn.masl"));
    let library = Library::read_from_bytes(bytes).expect("Shipped BURN library is well-formed");
    NoteScript::from_library(&library).expect("BURN library contains note script procedure")
});

// BURN NOTE
// ================================================================================================

/// TODO: add docs
pub struct BurnNote;

impl BurnNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the BURN note.
    pub const NUM_STORAGE_ITEMS: usize = 0;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the BURN note.
    pub fn script() -> NoteScript {
        BURN_SCRIPT.clone()
    }

    /// Returns the BURN note script root.
    pub fn script_root() -> Word {
        BURN_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Generates a BURN note - a note that instructs a faucet to burn a fungible asset.
    ///
    /// This script enables the creation of a PUBLIC note that, when consumed by a faucet (either
    /// basic or network), will burn the fungible assets contained in the note. Both basic and
    /// network fungible faucets export the same `burn` procedure with identical MAST roots,
    /// allowing a single BURN note script to work with either faucet type.
    ///
    /// BURN notes are always PUBLIC for network execution.
    ///
    /// The passed-in `rng` is used to generate a serial number for the note. The note's tag
    /// is automatically set to the faucet's account ID for proper routing.
    ///
    /// # Parameters
    /// - `sender`: The account ID of the note creator
    /// - `faucet_id`: The account ID of the faucet that will burn the assets
    /// - `fungible_asset`: The fungible asset to be burned
    /// - `attachment`: The [`NoteAttachment`] of the BURN note
    /// - `rng`: Random number generator for creating the serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        fungible_asset: Asset,
        attachment: NoteAttachment,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let note_script = Self::script();
        let serial_num = rng.draw_word();

        // BURN notes are always public
        let note_type = NoteType::Public;

        let inputs = NoteStorage::new(vec![])?;
        let tag = NoteTag::with_account_target(faucet_id);

        let metadata = NoteMetadata::new(sender, note_type, tag).with_attachment(attachment);
        let assets = NoteAssets::new(vec![fungible_asset])?; // BURN notes contain the asset to burn
        let recipient = NoteRecipient::new(serial_num, note_script, inputs);

        Ok(Note::new(assets, metadata, recipient))
    }
}
