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
use miden_protocol::{Felt, FieldElement, Word};

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

/// Pay-to-ID Extended (P2IDE) note abstraction.
///
/// A P2IDE note enables transferring assets to a target account specified in the note storage.
/// The note may optionally include:
///
/// - A reclaim height allowing the sender to recover assets if the note remains unconsumed
/// - A timelock height preventing consumption before a given block
///
/// These constraints are encoded in `P2ideNoteStorage` and enforced by the associated note script.
pub struct P2ideNote;

impl P2ideNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the P2IDE note.
    pub const NUM_STORAGE_ITEMS: usize = P2ideNoteStorage::NUM_ITEMS;

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

    /// Generates a P2IDE note using the provided storage configuration.
    ///
    /// The note recipient and execution constraints are derived from
    /// `P2ideNoteStorage`. A random serial number is generated using `rng`,
    /// and the note tag is set to the storage target account.
    ///
    /// # Errors
    /// Returns an error if construction of the note recipient or asset vault fails.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        storage: P2ideNoteStorage,
        assets: Vec<Asset>,
        note_type: NoteType,
        attachment: NoteAttachment,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let serial_num = rng.draw_word();
        let recipient = storage.into_recipient(serial_num)?;
        let tag = NoteTag::with_account_target(storage.target());

        let metadata =
            NoteMetadata::new(sender, note_type).with_tag(tag).with_attachment(attachment);
        let vault = NoteAssets::new(assets)?;

        Ok(Note::new(vault, metadata, recipient))
    }
}

// P2IDE NOTE STORAGE
// ================================================================================================

/// Canonical storage representation for a P2IDE note.
///
/// Stores the target account ID together with optional
/// reclaim and timelock constraints controlling when
/// the note can be spent or reclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P2ideNoteStorage {
    pub target: AccountId,
    pub reclaim_height: Option<BlockNumber>,
    pub timelock_height: Option<BlockNumber>,
}

impl P2ideNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the P2IDE note.
    pub const NUM_ITEMS: usize = 4;

    /// Creates new P2IDE note storage.
    pub fn new(
        target: AccountId,
        reclaim_height: Option<BlockNumber>,
        timelock_height: Option<BlockNumber>,
    ) -> Self {
        Self { target, reclaim_height, timelock_height }
    }

    /// Consumes the storage and returns a P2IDE [`NoteRecipient`] with the provided serial number.
    pub fn into_recipient(self, serial_num: Word) -> Result<NoteRecipient, NoteError> {
        let note_script = P2ideNote::script();
        Ok(NoteRecipient::new(serial_num, note_script, self.into()))
    }

    /// Returns the target account ID.
    pub fn target(&self) -> AccountId {
        self.target
    }

    /// Returns the reclaim block height (if any).
    pub fn reclaim_height(&self) -> Option<BlockNumber> {
        self.reclaim_height
    }

    /// Returns the timelock block height (if any).
    pub fn timelock_height(&self) -> Option<BlockNumber> {
        self.timelock_height
    }
}

impl From<P2ideNoteStorage> for NoteStorage {
    fn from(storage: P2ideNoteStorage) -> Self {
        let reclaim = storage.reclaim_height.map(Felt::from).unwrap_or(Felt::ZERO);
        let timelock = storage.timelock_height.map(Felt::from).unwrap_or(Felt::ZERO);

        NoteStorage::new(vec![
            storage.target.suffix(),
            storage.target.prefix().as_felt(),
            reclaim,
            timelock,
        ])
        .expect("number of storage items should not exceed max storage items")
    }
}

impl TryFrom<&[Felt]> for P2ideNoteStorage {
    type Error = NoteError;

    fn try_from(note_storage: &[Felt]) -> Result<Self, Self::Error> {
        if note_storage.len() != P2ideNote::NUM_STORAGE_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: P2ideNote::NUM_STORAGE_ITEMS,
                actual: note_storage.len(),
            });
        }

        let target = AccountId::try_from([note_storage[1], note_storage[0]])
            .map_err(|e| NoteError::other_with_source("failed to create account id", e))?;

        let reclaim_height = if note_storage[2] == Felt::ZERO {
            None
        } else {
            let height: u32 = note_storage[2]
                .as_int()
                .try_into()
                .map_err(|e| NoteError::other_with_source("invalid note storage", e))?;

            Some(BlockNumber::from(height))
        };

        let timelock_height = if note_storage[3] == Felt::ZERO {
            None
        } else {
            let height: u32 = note_storage[3]
                .as_int()
                .try_into()
                .map_err(|e| NoteError::other_with_source("invalid note storage", e))?;

            Some(BlockNumber::from(height))
        };

        Ok(Self { target, reclaim_height, timelock_height })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
    use miden_protocol::block::BlockNumber;
    use miden_protocol::errors::NoteError;
    use miden_protocol::{Felt, FieldElement};

    use super::*;

    fn dummy_account() -> AccountId {
        AccountId::dummy(
            [3u8; 15],
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Private,
        )
    }

    #[test]
    fn try_from_valid_storage_with_all_fields_succeeds() {
        let target = dummy_account();

        let storage = vec![
            target.suffix(),
            target.prefix().as_felt(),
            Felt::from(42u32),
            Felt::from(100u32),
        ];

        let decoded = P2ideNoteStorage::try_from(storage.as_slice())
            .expect("valid P2IDE storage should decode");

        assert_eq!(decoded.target(), target);
        assert_eq!(decoded.reclaim_height(), Some(BlockNumber::from(42u32)));
        assert_eq!(decoded.timelock_height(), Some(BlockNumber::from(100u32)));
    }

    #[test]
    fn try_from_zero_heights_map_to_none() {
        let target = dummy_account();

        let storage = vec![target.suffix(), target.prefix().as_felt(), Felt::ZERO, Felt::ZERO];

        let decoded = P2ideNoteStorage::try_from(storage.as_slice()).unwrap();

        assert_eq!(decoded.reclaim_height(), None);
        assert_eq!(decoded.timelock_height(), None);
    }

    #[test]
    fn try_from_invalid_length_fails() {
        let storage = vec![Felt::ZERO; 3];

        let err =
            P2ideNoteStorage::try_from(storage.as_slice()).expect_err("wrong length must fail");

        assert!(matches!(
            err,
            NoteError::InvalidNoteStorageLength {
                expected: P2ideNote::NUM_STORAGE_ITEMS,
                actual: 3
            }
        ));
    }

    #[test]
    fn try_from_invalid_account_id_fails() {
        let storage = vec![Felt::new(999u64), Felt::new(888u64), Felt::ZERO, Felt::ZERO];

        let err = P2ideNoteStorage::try_from(storage.as_slice())
            .expect_err("invalid account id encoding must fail");

        assert!(matches!(err, NoteError::Other { source: Some(_), .. }));
    }

    #[test]
    fn try_from_reclaim_height_overflow_fails() {
        let target = dummy_account();

        // > u32::MAX
        let overflow = Felt::new(u64::from(u32::MAX) + 1);

        let storage = vec![target.suffix(), target.prefix().as_felt(), overflow, Felt::ZERO];

        let err = P2ideNoteStorage::try_from(storage.as_slice())
            .expect_err("overflow reclaim height must fail");

        assert!(matches!(err, NoteError::Other { source: Some(_), .. }));
    }

    #[test]
    fn try_from_timelock_height_overflow_fails() {
        let target = dummy_account();

        let overflow = Felt::new(u64::from(u32::MAX) + 10);

        let storage = vec![target.suffix(), target.prefix().as_felt(), Felt::ZERO, overflow];

        let err = P2ideNoteStorage::try_from(storage.as_slice())
            .expect_err("overflow timelock height must fail");

        assert!(matches!(err, NoteError::Other { source: Some(_), .. }));
    }
}
