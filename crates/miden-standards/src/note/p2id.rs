use alloc::vec::Vec;

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
use miden_protocol::{Felt, Word};

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
    pub const NUM_STORAGE_ITEMS: usize = P2idNoteStorage::NUM_ITEMS;

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
        let recipient = P2idNoteStorage::new(target).into_recipient(serial_num);

        let tag = NoteTag::with_account_target(target);

        let metadata =
            NoteMetadata::new(sender, note_type).with_tag(tag).with_attachment(attachment);
        let vault = NoteAssets::new(assets)?;

        Ok(Note::new(vault, metadata, recipient))
    }
}

/// Canonical storage representation for a P2ID note.
///
/// Contains the identifier of the target account that is authorized
/// to consume the note. Only the account matching this ID can execute
/// the note and claim its assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P2idNoteStorage {
    target: AccountId,
}

impl P2idNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the P2ID note.
    pub const NUM_ITEMS: usize = 2;

    /// Creates new P2ID note storage targeting the given account.
    pub fn new(target: AccountId) -> Self {
        Self { target }
    }

    /// Consumes the storage and returns a P2ID [`NoteRecipient`] with the provided serial number.
    ///
    /// Notes created with this recipient will be P2ID notes consumable by the specified target
    /// account stored in this [`P2idNoteStorage`].
    pub fn into_recipient(self, serial_num: Word) -> NoteRecipient {
        NoteRecipient::new(serial_num, P2idNote::script(), NoteStorage::from(self))
    }

    /// Returns the target account ID.
    pub fn target(&self) -> AccountId {
        self.target
    }
}

impl From<P2idNoteStorage> for NoteStorage {
    fn from(storage: P2idNoteStorage) -> Self {
        // Storage layout:
        // [ account_id_suffix, account_id_prefix ]
        NoteStorage::new(vec![storage.target.suffix(), storage.target.prefix().as_felt()])
            .expect("number of storage items should not exceed max storage items")
    }
}

impl TryFrom<&[Felt]> for P2idNoteStorage {
    type Error = NoteError;

    fn try_from(note_storage: &[Felt]) -> Result<Self, Self::Error> {
        if note_storage.len() != P2idNote::NUM_STORAGE_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: P2idNote::NUM_STORAGE_ITEMS,
                actual: note_storage.len(),
            });
        }

        let target = AccountId::try_from([note_storage[1], note_storage[0]])
            .map_err(|e| NoteError::other_with_source("failed to create account id", e))?;

        Ok(Self { target })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
    use miden_protocol::errors::NoteError;
    use miden_protocol::{Felt, FieldElement};

    use super::*;

    #[test]
    fn try_from_valid_storage_succeeds() {
        let target = AccountId::dummy(
            [1u8; 15],
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Private,
        );

        let storage = vec![target.suffix(), target.prefix().as_felt()];

        let parsed =
            P2idNoteStorage::try_from(storage.as_slice()).expect("storage should be valid");

        assert_eq!(parsed.target(), target);
    }

    #[test]
    fn try_from_invalid_length_returns_error() {
        let storage = vec![Felt::ZERO];

        let err = P2idNoteStorage::try_from(storage.as_slice())
            .expect_err("should fail due to invalid length");

        assert!(matches!(
            err,
            NoteError::InvalidNoteStorageLength {
                expected: P2idNote::NUM_STORAGE_ITEMS,
                actual: 1
            }
        ));
    }

    #[test]
    fn try_from_invalid_storage_contents_returns_error() {
        let storage = vec![Felt::new(999u64), Felt::new(888u64)];

        let err = P2idNoteStorage::try_from(storage.as_slice())
            .expect_err("should fail due to invalid account id encoding");

        assert!(matches!(err, NoteError::Other { source: Some(_), .. }));
    }
}
