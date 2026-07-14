use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
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
use miden_protocol::{Felt, Word};

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the UPGRADE note script procedure in the standards library.
const UPGRADE_SCRIPT_PATH: &str = "::miden::standards::notes::upgrade::main";

// Initialize the UPGRADE note script only once.
static UPGRADE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(UPGRADE_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains UPGRADE note script procedure")
});

// UPGRADE NOTE
// ================================================================================================

/// An Upgrade note: triggers the
/// [`UpgradeManager`](crate::account::extensions::UpgradeManager) `upgrade` procedure on the
/// account that consumes it, recording the code and storage upgrade commitments carried in the
/// note.
///
/// Authorization is enforced by the `upgrade` procedure through the account-wide `Authority`
/// component against the note sender, so the note carries no assets and its authorization is bound
/// to `sender` at creation time. The two commitment words live in the note's storage.
///
/// The note is always public (for network execution) and tagged for `target` — the account
/// carrying the `UpgradeManager` component to be upgraded. The `sender` is the account authorized
/// for the action per the account's `Authority` configuration.
///
/// Construct one with the [builder](UpgradeNote::builder); convert it into a protocol [`Note`]
/// infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct UpgradeNote {
    sender: AccountId,
    target: AccountId,
    storage: UpgradeNoteStorage,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl UpgradeNote {
    /// Builds a new [`UpgradeNote`] that triggers an upgrade on `target`, recording the given code
    /// and storage upgrade commitments.
    ///
    /// # Errors
    ///
    /// Returns an error if the attachments exceed their protocol limit (see
    /// [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        storage: UpgradeNoteStorage,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            target,
            storage,
            serial_number,
            attachments,
        })
    }
}

impl UpgradeNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the Upgrade note.
    pub const NUM_STORAGE_ITEMS: usize = UpgradeNoteStorage::NUM_ITEMS;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the Upgrade note.
    pub fn script() -> NoteScript {
        UPGRADE_SCRIPT.clone()
    }

    /// Returns the Upgrade note script root.
    pub fn script_root() -> NoteScriptRoot {
        UPGRADE_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the upgrade).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the account to be upgraded (the account the note is tagged for).
    pub fn account(&self) -> AccountId {
        self.target
    }

    /// Returns the note's storage.
    pub fn storage(&self) -> UpgradeNoteStorage {
        self.storage
    }

    /// Returns the code upgrade commitment carried by the note.
    pub fn code_upgrade_commitment(&self) -> Word {
        self.storage.code_upgrade_commitment()
    }

    /// Returns the storage upgrade commitment carried by the note.
    pub fn storage_upgrade_commitment(&self) -> Word {
        self.storage.storage_upgrade_commitment()
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the attachments carried by the note.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: upgrade_note_builder::State> UpgradeNoteBuilder<S> {
    /// Adds a single attachment to the note.
    pub fn attachment(mut self, attachment: impl Into<NoteAttachment>) -> Self {
        self.attachments.push(attachment.into());
        self
    }

    /// Adds multiple attachments to the note.
    pub fn attachments(
        mut self,
        attachments: impl IntoIterator<Item = impl Into<NoteAttachment>>,
    ) -> Self {
        self.attachments.extend(attachments.into_iter().map(Into::into));
        self
    }
}

impl<S: upgrade_note_builder::State> UpgradeNoteBuilder<S>
where
    S::SerialNumber: upgrade_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> UpgradeNoteBuilder<upgrade_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<UpgradeNote> for Note {
    fn from(note: UpgradeNote) -> Self {
        // Upgrade notes carry no assets and are always public for network execution; the
        // commitments live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = note.storage.into_recipient(note.serial_number);

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// UPGRADE NOTE STORAGE
// ================================================================================================

/// The storage of an [`UpgradeNote`].
///
/// Contains the two commitment words recorded by the
/// [`UpgradeManager`](crate::account::extensions::UpgradeManager) `upgrade` procedure when the note
/// is consumed: the new account code commitment and the new account storage commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeNoteStorage {
    code_upgrade_commitment: Word,
    storage_upgrade_commitment: Word,
}

impl UpgradeNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the Upgrade note: the code and storage commitment words.
    pub const NUM_ITEMS: usize = 8;

    /// Creates new Upgrade note storage recording the given code and storage upgrade commitments.
    pub fn new(code_upgrade_commitment: Word, storage_upgrade_commitment: Word) -> Self {
        Self {
            code_upgrade_commitment,
            storage_upgrade_commitment,
        }
    }

    /// Consumes the storage and returns an Upgrade [`NoteRecipient`] with the provided serial
    /// number.
    ///
    /// Notes created with this recipient will be Upgrade notes whose storage encodes the code and
    /// storage upgrade commitments stored in this [`UpgradeNoteStorage`].
    pub fn into_recipient(self, serial_num: Word) -> NoteRecipient {
        NoteRecipient::new(serial_num, UpgradeNote::script(), NoteStorage::from(self))
    }

    /// Returns the code upgrade commitment.
    pub fn code_upgrade_commitment(&self) -> Word {
        self.code_upgrade_commitment
    }

    /// Returns the storage upgrade commitment.
    pub fn storage_upgrade_commitment(&self) -> Word {
        self.storage_upgrade_commitment
    }
}

impl From<UpgradeNoteStorage> for NoteStorage {
    fn from(storage: UpgradeNoteStorage) -> Self {
        let mut storage_values = Vec::with_capacity(UpgradeNoteStorage::NUM_ITEMS);
        storage_values.extend_from_slice(storage.code_upgrade_commitment.as_elements());
        storage_values.extend_from_slice(storage.storage_upgrade_commitment.as_elements());

        NoteStorage::new(storage_values)
            .expect("number of storage items should not exceed max storage items")
    }
}

/// Deserializes [`UpgradeNoteStorage`] from a slice of exactly [`UpgradeNoteStorage::NUM_ITEMS`]
/// [`Felt`]s.
impl TryFrom<&[Felt]> for UpgradeNoteStorage {
    type Error = NoteError;

    fn try_from(note_storage: &[Felt]) -> Result<Self, Self::Error> {
        if note_storage.len() != Self::NUM_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: Self::NUM_ITEMS,
                actual: note_storage.len(),
            });
        }

        let code_upgrade_commitment =
            Word::new([note_storage[0], note_storage[1], note_storage[2], note_storage[3]]);
        let storage_upgrade_commitment =
            Word::new([note_storage[4], note_storage[5], note_storage[6], note_storage[7]]);

        Ok(Self::new(code_upgrade_commitment, storage_upgrade_commitment))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::rand::RandomCoin;

    use super::*;

    fn account_id(seed: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([seed; 32])
    }

    // STORAGE TESTS
    // --------------------------------------------------------------------------------------------

    /// The note storage round-trips through the felt encoding.
    #[test]
    fn storage_round_trip() {
        let code_commitment = Word::from([1, 2, 3, 4u32]);
        let storage_commitment = Word::from([5, 6, 7, 8u32]);
        let storage = UpgradeNoteStorage::new(code_commitment, storage_commitment);

        let note_storage = NoteStorage::from(storage);

        let mut expected = Vec::new();
        expected.extend_from_slice(code_commitment.as_elements());
        expected.extend_from_slice(storage_commitment.as_elements());
        assert_eq!(note_storage.items(), expected.as_slice());
        assert_eq!(note_storage.items().len(), UpgradeNoteStorage::NUM_ITEMS);

        let parsed =
            UpgradeNoteStorage::try_from(note_storage.items()).expect("storage should round-trip");
        assert_eq!(parsed, storage);
    }

    /// Parsing storage of the wrong length is rejected.
    #[test]
    fn try_from_invalid_length_returns_error() {
        let storage = vec![Felt::ZERO];

        let err = UpgradeNoteStorage::try_from(storage.as_slice())
            .expect_err("should fail due to invalid length");

        assert_matches!(
            err,
            NoteError::InvalidNoteStorageLength {
                expected: UpgradeNoteStorage::NUM_ITEMS,
                actual: 1
            }
        );
    }

    // BUILDER TESTS
    // --------------------------------------------------------------------------------------------

    /// The builder produces a public, asset-less note tagged for the upgraded account.
    #[test]
    fn builder_builds_upgrade_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let upgraded = account_id(1);
        let sender = account_id(2);
        let code_commitment = Word::from([1, 2, 3, 4u32]);
        let storage_commitment = Word::from([5, 6, 7, 8u32]);

        let note = UpgradeNote::builder()
            .sender(sender)
            .target(upgraded)
            .storage(UpgradeNoteStorage::new(code_commitment, storage_commitment))
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender);
        assert_eq!(note.account(), upgraded);
        assert_eq!(note.code_upgrade_commitment(), code_commitment);
        assert_eq!(note.storage_upgrade_commitment(), storage_commitment);
        assert_eq!(note.storage(), UpgradeNoteStorage::new(code_commitment, storage_commitment));

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(upgraded));
        assert_eq!(note.assets().num_assets(), 0);
    }
}
