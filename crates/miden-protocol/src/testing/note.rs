use alloc::vec::Vec;

use crate::Word;
use crate::account::AccountId;
use crate::assembly::Assembler;
use crate::asset::FungibleAsset;
use crate::note::{Note, NoteAssets, NoteRecipient, NoteScript, NoteStorage, NoteTag};
use crate::testing::account_id::ACCOUNT_ID_SENDER;

pub const DEFAULT_NOTE_SCRIPT: &str = "\
@note_script
pub proc main
    nop
end";

impl Note {
    /// Returns a note with no-op code and one asset.
    pub fn mock_noop(serial_num: Word) -> Note {
        let sender_id = AccountId::try_from(ACCOUNT_ID_SENDER).unwrap();
        let note_script = NoteScript::mock();
        let assets =
            NoteAssets::new(vec![FungibleAsset::mock(200)]).expect("note assets should be valid");
        let inputs = NoteStorage::new(Vec::new()).unwrap();
        let recipient = NoteRecipient::new(serial_num, note_script, inputs);

        Note::builder()
            .sender(sender_id)
            .recipient(recipient)
            .assets(assets)
            .note_tag(NoteTag::with_account_target(sender_id))
            .build()
    }
}

// NOTE SCRIPT
// ================================================================================================

impl NoteScript {
    pub fn mock() -> Self {
        let assembler = Assembler::default();
        let library = assembler.assemble_library([DEFAULT_NOTE_SCRIPT]).unwrap();
        Self::from_library(&library).unwrap()
    }
}
