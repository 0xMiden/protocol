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
#[derive(Debug, Clone)]
pub struct P2ideNote {
    sender: AccountId,
    storage: P2ideNoteStorage,
    serial_number: Word,
    note_type: NoteType,
    assets: NoteAssets,
    attachments: NoteAttachments,
}

#[bon::bon]
impl P2ideNote {
    /// Builds a new [`P2ideNote`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No assets were provided ([`NoteError::MissingAsset`]).
    /// - The assets or attachments exceed their protocol limits (see [`NoteAssets::new`] and
    ///   [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] assets: Vec<Asset>,
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        reclaim_height: Option<BlockNumber>,
        timelock_height: Option<BlockNumber>,
        serial_number: Word,
        #[builder(default)] note_type: NoteType,
    ) -> Result<Self, NoteError> {
        if assets.is_empty() {
            return Err(NoteError::MissingAsset);
        }

        let storage = P2ideNoteStorage::new(target, reclaim_height, timelock_height);
        let assets = NoteAssets::new(assets)?;
        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            storage,
            serial_number,
            note_type,
            assets,
            attachments,
        })
    }
}

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
    pub fn script_root() -> NoteScriptRoot {
        P2IDE_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the note's storage.
    pub fn storage(&self) -> P2ideNoteStorage {
        self.storage
    }

    /// Returns the account ID of the note's target (the only account that can consume it).
    pub fn target(&self) -> AccountId {
        self.storage.target()
    }

    /// Returns the reclaim block height (if any).
    pub fn reclaim_height(&self) -> Option<BlockNumber> {
        self.storage.reclaim_height()
    }

    /// Returns the timelock block height (if any).
    pub fn timelock_height(&self) -> Option<BlockNumber> {
        self.storage.timelock_height()
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the note's type.
    pub fn note_type(&self) -> NoteType {
        self.note_type
    }

    /// Returns the assets carried by the note.
    pub fn assets(&self) -> &NoteAssets {
        &self.assets
    }

    /// Returns the attachments carried by the note.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: p2ide_note_builder::State> P2ideNoteBuilder<S> {
    /// Adds a single asset to the note. At least one asset is required for `.build()` to succeed.
    pub fn asset(mut self, asset: impl Into<Asset>) -> Self {
        self.assets.push(asset.into());
        self
    }

    /// Adds multiple assets to the note.
    pub fn assets(mut self, assets: impl IntoIterator<Item = impl Into<Asset>>) -> Self {
        self.assets.extend(assets.into_iter().map(Into::into));
        self
    }

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

impl<S: p2ide_note_builder::State> P2ideNoteBuilder<S>
where
    S::SerialNumber: p2ide_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> P2ideNoteBuilder<p2ide_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<P2ideNote> for Note {
    fn from(note: P2ideNote) -> Self {
        let recipient = note.storage.into_recipient(note.serial_number);
        let tag = NoteTag::with_account_target(note.storage.target());
        let metadata = PartialNoteMetadata::new(note.sender, note.note_type).with_tag(tag);

        Note::with_attachments(note.assets, metadata, recipient, note.attachments)
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
    pub fn into_recipient(self, serial_num: Word) -> NoteRecipient {
        NoteRecipient::new(serial_num, P2ideNote::script(), self.into())
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

        let target = AccountId::try_from_elements(note_storage[0], note_storage[1])
            .map_err(|err| NoteError::other_with_source("failed to create account id", err))?;

        let reclaim_height = if note_storage[2] == Felt::ZERO {
            None
        } else {
            let height: u32 = note_storage[2]
                .as_canonical_u64()
                .try_into()
                .map_err(|e| NoteError::other_with_source("invalid note storage", e))?;

            Some(BlockNumber::from(height))
        };

        let timelock_height = if note_storage[3] == Felt::ZERO {
            None
        } else {
            let height: u32 = note_storage[3]
                .as_canonical_u64()
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
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountType};
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::block::BlockNumber;
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::errors::NoteError;
    use miden_protocol::{Felt, Word};

    use super::*;

    fn dummy_account() -> AccountId {
        AccountId::dummy([3u8; 15], AccountIdVersion::Version1, AccountType::Private)
    }

    // STORAGE TESTS
    // --------------------------------------------------------------------------------------------

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
        let storage = vec![Felt::from(999_u32), Felt::from(888_u32), Felt::ZERO, Felt::ZERO];

        let err = P2ideNoteStorage::try_from(storage.as_slice())
            .expect_err("invalid account id encoding must fail");

        assert!(matches!(err, NoteError::Other { source: Some(_), .. }));
    }

    #[test]
    fn try_from_reclaim_height_overflow_fails() {
        let target = dummy_account();

        // > u32::MAX
        let overflow = Felt::new_unchecked(u64::from(u32::MAX) + 1);

        let storage = vec![target.suffix(), target.prefix().as_felt(), overflow, Felt::ZERO];

        let err = P2ideNoteStorage::try_from(storage.as_slice())
            .expect_err("overflow reclaim height must fail");

        assert!(matches!(err, NoteError::Other { source: Some(_), .. }));
    }

    #[test]
    fn try_from_timelock_height_overflow_fails() {
        let target = dummy_account();

        let overflow = Felt::new_unchecked(u64::from(u32::MAX) + 10);

        let storage = vec![target.suffix(), target.prefix().as_felt(), Felt::ZERO, overflow];

        let err = P2ideNoteStorage::try_from(storage.as_slice())
            .expect_err("overflow timelock height must fail");

        assert!(matches!(err, NoteError::Other { source: Some(_), .. }));
    }

    // BUILDER TESTS
    // --------------------------------------------------------------------------------------------

    fn sender() -> AccountId {
        AccountId::dummy([1u8; 15], AccountIdVersion::Version1, AccountType::Private)
    }

    fn target() -> AccountId {
        AccountId::dummy([2u8; 15], AccountIdVersion::Version1, AccountType::Private)
    }

    fn faucet_a() -> AccountId {
        AccountId::dummy([3u8; 15], AccountIdVersion::Version1, AccountType::Public)
    }

    fn faucet_b() -> AccountId {
        AccountId::dummy([4u8; 15], AccountIdVersion::Version1, AccountType::Public)
    }

    /// The minimal builder uses defaults for everything but the required fields (no reclaim or
    /// timelock height, private note type).
    #[test]
    fn builder_minimal_uses_defaults() {
        let note = P2ideNote::builder()
            .sender(sender())
            .target(target())
            .serial_number(Word::empty())
            .asset(FungibleAsset::new(faucet_a(), 1).unwrap())
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender());
        assert_eq!(note.target(), target());
        assert_eq!(note.note_type(), NoteType::default());
        assert_eq!(note.reclaim_height(), None);
        assert_eq!(note.timelock_height(), None);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.attachments().num_attachments(), 0);
    }

    /// `.asset()` and `.assets()` both append, so they can be combined and called repeatedly.
    #[test]
    fn builder_accumulates_assets() {
        let note = P2ideNote::builder()
            .sender(sender())
            .target(target())
            .serial_number(Word::empty())
            .asset(FungibleAsset::new(faucet_a(), 100).unwrap())
            .assets([Asset::from(FungibleAsset::new(faucet_b(), 200).unwrap())])
            .build()
            .unwrap();

        assert_eq!(note.assets().num_assets(), 2);
    }

    /// A P2IDE note must carry at least one asset.
    #[test]
    fn builder_rejects_empty_assets() {
        let err = P2ideNote::builder()
            .sender(sender())
            .target(target())
            .serial_number(Word::empty())
            .build()
            .expect_err("a note without assets must be rejected");

        assert!(matches!(err, NoteError::MissingAsset));
    }

    /// The reclaim and timelock heights are optional and surfaced through the getters.
    #[test]
    fn builder_sets_reclaim_and_timelock() {
        let note = P2ideNote::builder()
            .sender(sender())
            .target(target())
            .serial_number(Word::empty())
            .asset(FungibleAsset::new(faucet_a(), 1).unwrap())
            .reclaim_height(BlockNumber::from(42u32))
            .timelock_height(BlockNumber::from(100u32))
            .build()
            .unwrap();

        assert_eq!(note.reclaim_height(), Some(BlockNumber::from(42u32)));
        assert_eq!(note.timelock_height(), Some(BlockNumber::from(100u32)));
    }

    /// `.generate_serial_number()` draws the serial from the RNG.
    #[test]
    fn builder_generates_serial_number() {
        let mut rng = RandomCoin::new(Word::empty());
        let note = P2ideNote::builder()
            .sender(sender())
            .target(target())
            .asset(FungibleAsset::new(faucet_a(), 1).unwrap())
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_ne!(note.serial_number(), Word::empty());
    }

    /// `Note::from(p2ide_note)` is infallible and preserves the assets.
    #[test]
    fn into_note_preserves_assets() {
        let p2ide_note = P2ideNote::builder()
            .sender(sender())
            .target(target())
            .serial_number(Word::empty())
            .asset(FungibleAsset::new(faucet_a(), 42).unwrap())
            .note_type(NoteType::Public)
            .build()
            .unwrap();

        let assets = p2ide_note.assets().clone();
        let note = Note::from(p2ide_note);

        assert_eq!(note.assets(), &assets);
    }
}
