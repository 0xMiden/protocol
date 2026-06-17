use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::Asset;
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

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the non-fungible BURN note script procedure in the standards library.
const BURN_SCRIPT_PATH: &str = "::miden::standards::notes::burn_nft::main";

static BURN_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(BURN_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains non-fungible BURN note script procedure")
});

// NON-FUNGIBLE BURN NOTE
// ================================================================================================

/// A note that instructs a non-fungible faucet to burn the NFT it carries.
pub struct NonFungibleBurnNote;

impl NonFungibleBurnNote {
    /// Expected number of storage items of the BURN note.
    pub const NUM_STORAGE_ITEMS: usize = 0;

    /// Returns the script of the non-fungible BURN note.
    pub fn script() -> NoteScript {
        BURN_SCRIPT.clone()
    }

    /// Returns the non-fungible BURN note script root.
    pub fn script_root() -> NoteScriptRoot {
        BURN_SCRIPT.root()
    }

    /// Generates a BURN note: a public note that, when consumed by a non-fungible faucet, burns
    /// the NFT it carries (calling `non_fungible::receive_and_burn`).
    ///
    /// # Parameters
    /// - `sender`: The account ID of the note creator.
    /// - `faucet_id`: The account ID of the faucet that will burn the asset (used for routing).
    /// - `asset`: The non-fungible asset to be burned.
    /// - `attachments`: The [`NoteAttachments`] of the BURN note.
    /// - `rng`: Random number generator for the serial number.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        asset: Asset,
        attachments: NoteAttachments,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let note_script = Self::script();
        let serial_num = rng.draw_word();
        let note_type = NoteType::Public;

        let inputs = NoteStorage::new(vec![])?;
        let tag = NoteTag::with_account_target(faucet_id);

        let metadata = PartialNoteMetadata::new(sender, note_type).with_tag(tag);
        let assets = NoteAssets::new(vec![asset])?;
        let recipient = NoteRecipient::new(serial_num, note_script, inputs);

        Ok(Note::with_attachments(assets, metadata, recipient, attachments))
    }
}
