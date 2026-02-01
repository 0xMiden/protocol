use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::debuginfo::{SourceLanguage, SourceManagerSync, Uri};
use miden_protocol::assembly::{DefaultSourceManager, Library};
use miden_protocol::asset::Asset;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteMetadata,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_protocol::testing::note::DEFAULT_NOTE_CODE;
use miden_protocol::{Felt, Word};
use rand::Rng;

use crate::code_builder::CodeBuilder;

// NOTE BUILDER
// ================================================================================================

#[derive(Debug, Clone)]
pub struct NoteBuilder {
    sender: AccountId,
    storage: Vec<Felt>,
    assets: Vec<Asset>,
    note_type: NoteType,
    serial_num: Word,
    tag: NoteTag,
    code: String,
    attachment: NoteAttachment,
    dyn_libraries: Vec<Library>,
    source_manager: Arc<dyn SourceManagerSync>,
}

impl NoteBuilder {
    pub fn new<T: Rng>(sender: AccountId, mut rng: T) -> Self {
        let serial_num = Word::from([
            Felt::new(rng.random()),
            Felt::new(rng.random()),
            Felt::new(rng.random()),
            Felt::new(rng.random()),
        ]);

        Self {
            sender,
            storage: vec![],
            assets: vec![],
            note_type: NoteType::Public,
            serial_num,
            // The note tag is not under test, so we choose a value that is always valid.
            tag: NoteTag::with_account_target(sender),
            code: DEFAULT_NOTE_CODE.to_string(),
            attachment: NoteAttachment::default(),
            dyn_libraries: Vec::new(),
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }

    /// Set the note's storage to `storage`.
    ///
    /// Note: This overwrite the inputs, the previous input values are discarded.
    pub fn note_storage(
        mut self,
        storage: impl IntoIterator<Item = Felt>,
    ) -> Result<Self, NoteError> {
        let validate = NoteStorage::new(storage.into_iter().collect())?;
        self.storage = validate.into();
        Ok(self)
    }

    pub fn add_assets(mut self, assets: impl IntoIterator<Item = Asset>) -> Self {
        self.assets.extend(assets);
        self
    }

    pub fn tag(mut self, tag: u32) -> Self {
        self.tag = tag.into();
        self
    }

    pub fn note_type(mut self, note_type: NoteType) -> Self {
        self.note_type = note_type;
        self
    }

    pub fn code<S: AsRef<str>>(mut self, code: S) -> Self {
        self.code = code.as_ref().to_string();
        self
    }

    /// Overwrites the generated serial number with a custom one.
    pub fn serial_number(mut self, serial_number: Word) -> Self {
        self.serial_num = serial_number;
        self
    }

    /// Overwrites the attachment.
    pub fn attachment(mut self, attachment: impl Into<NoteAttachment>) -> Self {
        self.attachment = attachment.into();
        self
    }

    /// Extends the set of dynamically linked libraries that are passed to the assembler at
    /// build-time.
    pub fn dynamically_linked_libraries(
        mut self,
        dyn_libraries: impl IntoIterator<Item = Library>,
    ) -> Self {
        self.dyn_libraries.extend(dyn_libraries);
        self
    }

    pub fn source_manager(mut self, source_manager: Arc<dyn SourceManagerSync>) -> Self {
        self.source_manager = source_manager;
        self
    }

    pub fn build(self) -> Result<Note, NoteError> {
        // Generate a unique file name from the note's serial number, which should be unique per
        // note. Only includes two elements in the file name which should be enough for the
        // uniqueness in the testing context and does not result in overly long file names which do
        // not render well in all situations.
        let virtual_source_file = self.source_manager.load(
            SourceLanguage::Masm,
            Uri::new(format!(
                "note_{:x}{:x}",
                self.serial_num[0].as_int(),
                self.serial_num[1].as_int()
            )),
            self.code,
        );

        let mut builder = CodeBuilder::with_source_manager(self.source_manager.clone());
        for dyn_library in self.dyn_libraries {
            builder
                .link_dynamic_library(&dyn_library)
                .expect("library should link successfully");
        }

        let note_script = builder
            .compile_note_script(virtual_source_file)
            .expect("note script should compile");
        let vault = NoteAssets::new(self.assets)?;
        let metadata = NoteMetadata::new(self.sender, self.note_type, self.tag)
            .with_attachment(self.attachment);
        let storage = NoteStorage::new(self.storage)?;
        let recipient = NoteRecipient::new(self.serial_num, note_script, storage);

        Ok(Note::new(vault, metadata, recipient))
    }
}
