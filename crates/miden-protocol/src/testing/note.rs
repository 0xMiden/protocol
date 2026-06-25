use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::Word;
use crate::assembly::{Assembler, DefaultSourceManager, ModuleKind, ModuleParser, Path};
use crate::asset::FungibleAsset;
use crate::note::{
    Note,
    NoteAssets,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use crate::testing::account_id::ACCOUNT_ID_SENDER;

pub const DEFAULT_NOTE_SCRIPT: &str = "\
@note_script
pub proc main
    nop
end";

impl Note {
    /// Returns a note with no-op code and one asset.
    pub fn mock_noop(serial_num: Word) -> Note {
        let sender_id = ACCOUNT_ID_SENDER.try_into().unwrap();
        let note_script = NoteScript::mock();
        let assets =
            NoteAssets::new(vec![FungibleAsset::mock(200)]).expect("note assets should be valid");
        let metadata = PartialNoteMetadata::new(sender_id, NoteType::Private)
            .with_tag(NoteTag::with_account_target(sender_id));
        let inputs = NoteStorage::new(Vec::new()).unwrap();
        let recipient = NoteRecipient::new(serial_num, note_script, inputs);

        Note::new(assets, metadata, recipient)
    }
}

// NOTE SCRIPT
// ================================================================================================

impl NoteScript {
    pub fn mock() -> Self {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let root = ModuleParser::new(Some(ModuleKind::Library))
            .parse_str(
                Some(Path::new("miden::testing::note")),
                DEFAULT_NOTE_SCRIPT,
                source_manager.clone(),
            )
            .expect("mock note script should parse");
        let library = Assembler::new(source_manager)
            .assemble_library("miden-testing-note", root, None::<&str>)
            .unwrap();
        Self::from_library(&library).unwrap()
    }
}
