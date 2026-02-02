use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
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
use miden_protocol::utils::sync::LazyLock;

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the P2ID note script procedure in the standards library.
const P2ID_SCRIPT_PATH: &str = "::miden::standards::notes::p2id::main";

// Initialize the P2ID note script only once
static P2ID_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(P2ID_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains P2ID note script procedure")
});

// P2ID NOTE
// ================================================================================================

/// TODO: add docs
pub struct P2idNote;

impl P2idNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the P2ID note.
    pub const NUM_STORAGE_ITEMS: usize = 2;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the P2ID (Pay-to-ID) note.
    pub fn script() -> NoteScript {
        P2ID_SCRIPT.clone()
    }

    /// Returns the P2ID (Pay-to-ID) note script root.
    pub fn script_root() -> Word {
        P2ID_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Generates a P2ID note - Pay-to-ID note.
    ///
    /// This script enables the transfer of assets from the `sender` account to the `target` account
    /// by specifying the target's account ID.
    ///
    /// The passed-in `rng` is used to generate a serial number for the note. The returned note's
    /// tag is set to the target's account ID.
    ///
    /// # Errors
    /// Returns an error if deserialization or compilation of the `P2ID` script fails.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        target: AccountId,
        assets: Vec<Asset>,
        note_type: NoteType,
        attachment: NoteAttachment,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let serial_num = rng.draw_word();
        let recipient = Self::build_recipient(target, serial_num)?;

        let tag = NoteTag::with_account_target(target);

        let metadata = NoteMetadata::new(sender, note_type, tag).with_attachment(attachment);
        let vault = NoteAssets::new(assets)?;

        Ok(Note::new(vault, metadata, recipient))
    }

    /// Creates a [NoteRecipient] for the P2ID note.
    ///
    /// Notes created with this recipient will be P2ID notes consumable by the specified target
    /// account.
    pub fn build_recipient(
        target: AccountId,
        serial_num: Word,
    ) -> Result<NoteRecipient, NoteError> {
        let note_script = Self::script();
        let note_storage = NoteStorage::new(vec![target.suffix(), target.prefix().as_felt()])?;

        Ok(NoteRecipient::new(serial_num, note_script, note_storage))
    }
}
