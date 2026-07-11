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
/// - A reclaim height allowing the reclaimer to recover assets if the note remains unconsumed
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
    /// - No assets were provided.
    /// - The assets or attachments exceed their protocol limits (see [`NoteAssets::new`] and
    ///   [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] assets: Vec<Asset>,
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        reclaimer: Option<AccountId>,
        reclaim_height: Option<BlockNumber>,
        timelock_height: Option<BlockNumber>,
        serial_number: Word,
        #[builder(default)] note_type: NoteType,
    ) -> Result<Self, NoteError> {
        if assets.is_empty() {
            return Err(NoteError::other("a P2IDE note must contain at least one asset"));
        }

        // The reclaimer is the account allowed to reclaim the note; it defaults to the sender.
        let reclaimer = reclaimer.unwrap_or(sender);
        let storage = P2ideNoteStorage::new(reclaimer, target, reclaim_height, timelock_height);
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

    /// Returns the account ID of the note's reclaimer.
    pub fn reclaimer(&self) -> AccountId {
        self.storage.reclaimer()
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
/// Stores the reclaimer account ID and the target account ID together with optional reclaim
/// and timelock constraints controlling when the note can be spent or reclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P2ideNoteStorage {
    reclaimer: AccountId,
    target: AccountId,
    reclaim_height: Option<BlockNumber>,
    timelock_height: Option<BlockNumber>,
}

impl P2ideNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the P2IDE note.
    pub const NUM_ITEMS: usize = 6;

    // Indices of the storage items. Must match the `*_ITEM` offsets from `STORAGE_PTR` in
    // `asm/standards/notes/p2ide.masm`.
    const RECLAIMER_SUFFIX_IDX: usize = 0;
    const RECLAIMER_PREFIX_IDX: usize = 1;
    const TARGET_SUFFIX_IDX: usize = 2;
    const TARGET_PREFIX_IDX: usize = 3;
    const RECLAIM_HEIGHT_IDX: usize = 4;
    const TIMELOCK_HEIGHT_IDX: usize = 5;

    /// Creates new P2IDE note storage.
    pub fn new(
        reclaimer: AccountId,
        target: AccountId,
        reclaim_height: Option<BlockNumber>,
        timelock_height: Option<BlockNumber>,
    ) -> Self {
        Self {
            reclaimer,
            target,
            reclaim_height,
            timelock_height,
        }
    }

    /// Consumes the storage and returns a P2IDE [`NoteRecipient`] with the provided serial number.
    pub fn into_recipient(self, serial_num: Word) -> NoteRecipient {
        NoteRecipient::new(serial_num, P2ideNote::script(), self.into())
    }

    /// Returns the reclaimer account ID.
    pub fn reclaimer(&self) -> AccountId {
        self.reclaimer
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
        // an absent height is encoded as zero
        let reclaim = storage.reclaim_height.map_or(Felt::ZERO, Felt::from);
        let timelock = storage.timelock_height.map_or(Felt::ZERO, Felt::from);

        // the item order must match the `*_IDX` constants that `try_from` decodes with
        NoteStorage::new(vec![
            storage.reclaimer.suffix(),
            storage.reclaimer.prefix().as_felt(),
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

        let reclaimer = AccountId::try_from_elements(
            note_storage[Self::RECLAIMER_SUFFIX_IDX],
            note_storage[Self::RECLAIMER_PREFIX_IDX],
        )
        .map_err(|err| {
            NoteError::other_with_source("failed to create reclaimer account id", err)
        })?;

        let target = AccountId::try_from_elements(
            note_storage[Self::TARGET_SUFFIX_IDX],
            note_storage[Self::TARGET_PREFIX_IDX],
        )
        .map_err(|err| NoteError::other_with_source("failed to create target account id", err))?;

        let reclaim_height = decode_block_height(
            note_storage[Self::RECLAIM_HEIGHT_IDX],
            "invalid reclaim height in note storage",
        )?;
        let timelock_height = decode_block_height(
            note_storage[Self::TIMELOCK_HEIGHT_IDX],
            "invalid timelock height in note storage",
        )?;

        Ok(Self {
            reclaimer,
            target,
            reclaim_height,
            timelock_height,
        })
    }
}

/// Decodes an optional block height stored as a single storage item, where zero encodes `None`.
///
/// `error_msg` names the field being decoded so that a caller can tell the heights apart.
fn decode_block_height(
    item: Felt,
    error_msg: &'static str,
) -> Result<Option<BlockNumber>, NoteError> {
    if item == Felt::ZERO {
        return Ok(None);
    }

    let height: u32 = item
        .as_canonical_u64()
        .try_into()
        .map_err(|e| NoteError::other_with_source(error_msg, e))?;

    Ok(Some(BlockNumber::from(height)))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::{AccountId, AccountType};
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::block::BlockNumber;
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::errors::NoteError;
    use miden_protocol::{Felt, Word};

    use super::*;

    // The suffix and prefix of an ID that `AccountId::try_from_elements` rejects. Both felts are
    // individually invalid, but the prefix's version check runs first, so that is the error the
    // pair produces: the version is the prefix's least significant nibble, and `888 & 0xf == 8` is
    // not a known version.
    const INVALID_ID_SUFFIX: Felt = Felt::new_unchecked(999);
    const INVALID_ID_PREFIX: Felt = Felt::new_unchecked(888);

    fn dummy_account() -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Private)
            .build_with_seed([3u8; 32])
    }

    // STORAGE TESTS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn try_from_valid_storage_with_all_fields_succeeds() {
        let reclaimer = sender();
        let target = dummy_account();

        let storage = vec![
            reclaimer.suffix(),
            reclaimer.prefix().as_felt(),
            target.suffix(),
            target.prefix().as_felt(),
            Felt::from(42u32),
            Felt::from(100u32),
        ];

        let decoded = P2ideNoteStorage::try_from(storage.as_slice())
            .expect("valid P2IDE storage should decode");

        assert_eq!(decoded.reclaimer(), reclaimer);
        assert_eq!(decoded.target(), target);
        assert_eq!(decoded.reclaim_height(), Some(BlockNumber::from(42u32)));
        assert_eq!(decoded.timelock_height(), Some(BlockNumber::from(100u32)));
    }

    #[test]
    fn try_from_zero_heights_map_to_none() {
        let reclaimer = sender();
        let target = dummy_account();

        let storage = vec![
            reclaimer.suffix(),
            reclaimer.prefix().as_felt(),
            target.suffix(),
            target.prefix().as_felt(),
            Felt::ZERO,
            Felt::ZERO,
        ];

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

    /// The reclaimer and the target are decoded from different storage items, so each must
    /// be validated on its own.
    #[test]
    fn try_from_invalid_reclaimer_fails() {
        let target = dummy_account();

        let storage = vec![
            INVALID_ID_SUFFIX,
            INVALID_ID_PREFIX,
            target.suffix(),
            target.prefix().as_felt(),
            Felt::ZERO,
            Felt::ZERO,
        ];

        let err = P2ideNoteStorage::try_from(storage.as_slice())
            .expect_err("invalid reclaimer encoding must fail");

        assert_matches!(err, NoteError::Other { error_msg, source: Some(_), .. } => {
            assert!(error_msg.contains("reclaimer"));
        });
    }

    #[test]
    fn try_from_invalid_target_fails() {
        let reclaimer = sender();

        let storage = vec![
            reclaimer.suffix(),
            reclaimer.prefix().as_felt(),
            INVALID_ID_SUFFIX,
            INVALID_ID_PREFIX,
            Felt::ZERO,
            Felt::ZERO,
        ];

        let err = P2ideNoteStorage::try_from(storage.as_slice())
            .expect_err("invalid target encoding must fail");

        assert_matches!(err, NoteError::Other { error_msg, source: Some(_), .. } => {
            assert!(error_msg.contains("target"));
        });
    }

    /// The encoder and the decoder must agree on the item order. This does not pin the order to
    /// `p2ide.masm` - a transposition applied to both halves round-trips fine. That contract is
    /// held by the hand-built storage vectors in the `try_from_*` tests above, which spell the
    /// layout out literally, and by the note script execution tests in `miden-testing`.
    ///
    /// Zero means "disabled" rather than a height, so it is excluded here, see
    /// [`zero_reclaim_height_means_reclaim_disabled`].
    #[test]
    fn storage_round_trips_through_note_storage() {
        let storage = P2ideNoteStorage::new(
            sender(),
            target(),
            Some(BlockNumber::from(42u32)),
            Some(BlockNumber::from(100u32)),
        );

        let encoded: NoteStorage = storage.into();
        let decoded = P2ideNoteStorage::try_from(encoded.items()).unwrap();

        assert_eq!(decoded, storage);
    }

    /// A zero reclaim height means "reclaim disabled", both in the storage encoding and in the note
    /// script, which rejects it with `ERR_P2IDE_RECLAIM_DISABLED`. Zero is thus not a height, and
    /// `Some(BlockNumber::GENESIS)` encodes identically to `None`.
    #[test]
    fn zero_reclaim_height_means_reclaim_disabled() {
        let storage = P2ideNoteStorage::new(sender(), target(), Some(BlockNumber::GENESIS), None);

        let encoded: NoteStorage = storage.into();
        let decoded = P2ideNoteStorage::try_from(encoded.items()).unwrap();

        assert_eq!(decoded.reclaim_height(), None);
    }

    #[test]
    fn try_from_reclaim_height_overflow_fails() {
        let reclaimer = sender();
        let target = dummy_account();

        // > u32::MAX
        let overflow = Felt::new_unchecked(u64::from(u32::MAX) + 1);

        let storage = vec![
            reclaimer.suffix(),
            reclaimer.prefix().as_felt(),
            target.suffix(),
            target.prefix().as_felt(),
            overflow,
            Felt::ZERO,
        ];

        let err = P2ideNoteStorage::try_from(storage.as_slice())
            .expect_err("overflow reclaim height must fail");

        assert_matches!(err, NoteError::Other { error_msg, source: Some(_), .. } => {
            assert!(error_msg.contains("reclaim height"));
        });
    }

    #[test]
    fn try_from_timelock_height_overflow_fails() {
        let reclaimer = sender();
        let target = dummy_account();

        let overflow = Felt::new_unchecked(u64::from(u32::MAX) + 10);

        let storage = vec![
            reclaimer.suffix(),
            reclaimer.prefix().as_felt(),
            target.suffix(),
            target.prefix().as_felt(),
            Felt::ZERO,
            overflow,
        ];

        let err = P2ideNoteStorage::try_from(storage.as_slice())
            .expect_err("overflow timelock height must fail");

        assert_matches!(err, NoteError::Other { error_msg, source: Some(_), .. } => {
            assert!(error_msg.contains("timelock height"));
        });
    }

    // BUILDER TESTS
    // --------------------------------------------------------------------------------------------

    fn sender() -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Private)
            .build_with_seed([1u8; 32])
    }

    fn target() -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Private)
            .build_with_seed([2u8; 32])
    }

    fn faucet_a() -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([3u8; 32])
    }

    fn faucet_b() -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([4u8; 32])
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
        // the reclaimer defaults to the sender when not set explicitly
        assert_eq!(note.reclaimer(), sender());
        assert_eq!(note.note_type(), NoteType::default());
        assert_eq!(note.reclaim_height(), None);
        assert_eq!(note.timelock_height(), None);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.attachments().num_attachments(), 0);
    }

    /// `.asset()` and `.assets()` both append, so they can be combined and called repeatedly.
    #[test]
    fn builder_accumulates_assets() {
        let mut rng = RandomCoin::new(Word::empty());
        let note = P2ideNote::builder()
            .sender(sender())
            .target(target())
            .asset(FungibleAsset::new(faucet_a(), 100).unwrap())
            .assets([Asset::from(FungibleAsset::new(faucet_b(), 200).unwrap())])
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.assets().num_assets(), 2);
        assert_ne!(note.serial_number(), Word::empty());
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

        assert_matches!(err, NoteError::Other { error_msg, .. } => {
            assert!(error_msg.contains("note must contain at least one asset"))
        });
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

    /// An explicit reclaimer (distinct from the sender) is stored and surfaced via
    /// `reclaimer()`, and round-trips through the note storage.
    #[test]
    fn builder_explicit_reclaimer_differs_from_sender() {
        let note = P2ideNote::builder()
            .sender(sender())
            .target(target())
            .reclaimer(dummy_account())
            .serial_number(Word::empty())
            .asset(FungibleAsset::new(faucet_a(), 1).unwrap())
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender());
        assert_eq!(note.reclaimer(), dummy_account());
        assert_ne!(note.reclaimer(), note.sender());

        // the explicit reclaimer round-trips through the encoded note storage
        let storage: NoteStorage = note.storage().into();
        let decoded = P2ideNoteStorage::try_from(storage.items()).unwrap();
        assert_eq!(decoded.reclaimer(), dummy_account());
        assert_eq!(decoded.target(), target());
    }
}
