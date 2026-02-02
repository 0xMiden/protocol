use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;
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
use miden_protocol::{Felt, Word};

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the P2IDE note script procedure in the standards library.
const P2IDE_SCRIPT_PATH: &str = "::miden::standards::notes::p2ide::main";

// Initialize the P2IDE note script only once
static P2IDE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(P2IDE_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains P2IDE note script procedure")
});

// P2IDE NOTE
// ================================================================================================

/// TODO: add docs
pub struct P2ideNote;

impl P2ideNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the P2IDE note.
    pub const NUM_STORAGE_ITEMS: usize = 4;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the P2IDE (Pay-to-ID extended) note.
    pub fn script() -> NoteScript {
        P2IDE_SCRIPT.clone()
    }

    /// Returns the P2IDE (Pay-to-ID extended) note script root.
    pub fn script_root() -> Word {
        P2IDE_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Generates a P2IDE note - Pay-to-ID note with optional reclaim after a certain block height
    /// and optional timelock.
    ///
    /// This script enables the transfer of assets from the `sender` account to the `target`
    /// account by specifying the target's account ID. It adds the optional possibility for the
    /// sender to reclaiming the assets if the note has not been consumed by the target within the
    /// specified timeframe and the optional possibility to add a timelock to the asset transfer.
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
        reclaim_height: Option<BlockNumber>,
        timelock_height: Option<BlockNumber>,
        note_type: NoteType,
        attachment: NoteAttachment,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let serial_num = rng.draw_word();
        let recipient = Self::build_recipient(target, reclaim_height, timelock_height, serial_num)?;
        let tag = NoteTag::with_account_target(target);

        let metadata =
            NoteMetadata::new(sender, note_type).with_tag(tag).with_attachment(attachment);
        let vault = NoteAssets::new(assets)?;

        Ok(Note::new(vault, metadata, recipient))
    }

    /// Creates a [NoteRecipient] for the P2IDE note.
    ///
    /// Notes created with this recipient will be P2IDE notes consumable by the specified target
    /// account.
    pub fn build_recipient(
        target: AccountId,
        reclaim_block_height: Option<BlockNumber>,
        timelock_block_height: Option<BlockNumber>,
        serial_num: Word,
    ) -> Result<NoteRecipient, NoteError> {
        let note_script = Self::script();

        let storage = P2ideNoteStorage::new(target, reclaim_block_height, timelock_block_height);

        Ok(NoteRecipient::new(serial_num, note_script, storage.into()))
    }
}

/// Storage layout for P2IDE (Pay-to-ID Extended) notes.
///
/// Layout (4 items):
/// [0] target account ID suffix
/// [1] target account ID prefix
/// [2] reclaim block height (0 = disabled)
/// [3] timelock block height (0 = disabled)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2ideNoteStorage {
    target: AccountId,
    reclaim_block_height: Option<BlockNumber>,
    timelock_block_height: Option<BlockNumber>,
}

impl P2ideNoteStorage {
    pub const NUM_STORAGE_ITEMS: usize = 4;

    pub fn new(
        target: AccountId,
        reclaim_block_height: Option<BlockNumber>,
        timelock_block_height: Option<BlockNumber>,
    ) -> Self {
        Self {
            target,
            reclaim_block_height,
            timelock_block_height,
        }
    }

    pub fn target(&self) -> AccountId {
        self.target
    }

    pub fn reclaim_block_height(&self) -> Option<BlockNumber> {
        self.reclaim_block_height
    }

    pub fn timelock_block_height(&self) -> Option<BlockNumber> {
        self.timelock_block_height
    }
}

impl From<P2ideNoteStorage> for NoteStorage {
    fn from(storage: P2ideNoteStorage) -> Self {
        let reclaim_height = storage.reclaim_block_height.map_or(0, |bn| bn.as_u32());

        let timelock_height = storage.timelock_block_height.map_or(0, |bn| bn.as_u32());

        NoteStorage::new(vec![
            storage.target.suffix(),
            storage.target.prefix().as_felt(),
            Felt::new(reclaim_height as u64),
            Felt::new(timelock_height as u64),
        ])
        .expect("P2IDE note storage is always valid")
    }
}

impl TryFrom<NoteStorage> for P2ideNoteStorage {
    type Error = NoteError;

    fn try_from(storage: NoteStorage) -> Result<Self, Self::Error> {
        let items = storage.items();

        if items.len() != Self::NUM_STORAGE_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: Self::NUM_STORAGE_ITEMS,
                actual: items.len(),
            });
        }

        let target =
            AccountId::new(items[1], items[0]).map_err(|_| NoteError::InvalidNoteStorage)?;

        let reclaim_height = if items[2].as_u64() == 0 {
            None
        } else {
            Some(BlockNumber::new(items[2].as_u64() as u32))
        };

        let timelock_height = if items[3].as_u64() == 0 {
            None
        } else {
            Some(BlockNumber::new(items[3].as_u64() as u32))
        };

        Ok(Self {
            target,
            reclaim_block_height: reclaim_height,
            timelock_block_height: timelock_height,
        })
    }
}
