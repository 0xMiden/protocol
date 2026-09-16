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
use crate::note::costs::{NoteConsumptionCost, P2ID_CONSUMPTION_CYCLES};
// NOTE SCRIPT
// ================================================================================================

/// Path to the P2ID note script procedure in the standards library.
const P2ID_SCRIPT_PATH: &str = "::miden::standards::notes::p2id::main";

// Initialize the P2ID note script only once
static P2ID_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(P2ID_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains P2ID note script procedure")
});

// P2ID NOTE
// ================================================================================================

/// A Pay-to-ID (P2ID) note: transfers `assets` from `sender` to the `target` account.
///
/// Only the `target` account can consume the note and claim its assets.
///
/// Construct one with the [builder](P2idNote::builder), which sets sensible defaults for the
/// optional parameters (private note type, zero salt, no attachments) and requires at least one
/// asset. Convert a `P2idNote` into a protocol [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct P2idNote {
    sender: AccountId,
    storage: P2idNoteStorage,
    serial_number: Word,
    note_type: NoteType,
    assets: NoteAssets,
    attachments: NoteAttachments,
}

#[bon::bon]
impl P2idNote {
    /// Builds a new [`P2idNote`].
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
        serial_number: Word,
        #[builder(default)] note_type: NoteType,
        #[builder(default)] salt: [Felt; 2],
    ) -> Result<Self, NoteError> {
        if assets.is_empty() {
            return Err(NoteError::other("a P2ID note must contain at least one asset"));
        }

        let storage = P2idNoteStorage::new(target).with_salt(salt);
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
    pub fn script_root() -> NoteScriptRoot {
        P2ID_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the note's storage.
    pub fn storage(&self) -> P2idNoteStorage {
        self.storage
    }

    /// Returns the account ID of the note's target (the only account that can consume it).
    pub fn target(&self) -> AccountId {
        self.storage.target()
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

impl<S: p2id_note_builder::State> P2idNoteBuilder<S> {
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

impl<S: p2id_note_builder::State> P2idNoteBuilder<S>
where
    S::SerialNumber: p2id_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> P2idNoteBuilder<p2id_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<P2idNote> for Note {
    fn from(note: P2idNote) -> Self {
        let recipient = note.storage.into_recipient(note.serial_number);
        let tag = NoteTag::with_account_target(note.storage.target());
        let metadata = PartialNoteMetadata::new(note.sender, note.note_type).with_tag(tag);

        Note::with_attachments(note.assets, metadata, recipient, note.attachments)
    }
}

// P2ID NOTE STORAGE
// ================================================================================================

/// Canonical storage representation for a P2ID note.
///
/// Contains the identifier of the target account that is authorized
/// to consume the note. Only the account matching this ID can execute
/// the note and claim its assets.
///
/// The salt is included in the storage commitment. A random salt kept private prevents the target
/// account ID from being determined by comparing commitments for candidate account IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P2idNoteStorage {
    target: AccountId,
    salt: [Felt; 2],
}

impl P2idNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the P2ID note.
    pub const NUM_ITEMS: usize = 4;

    /// Creates P2ID note storage targeting the given account with a zero salt.
    pub fn new(target: AccountId) -> Self {
        Self { target, salt: [Felt::ZERO; 2] }
    }

    /// Sets the salt included in the storage commitment.
    ///
    /// # Privacy
    /// For privacy, sample both elements uniformly at random and keep them secret. The default zero
    /// salt does not prevent target-account enumeration. Salt does not hide account-derived note
    /// tags.
    pub fn with_salt(mut self, salt: [Felt; 2]) -> Self {
        self.salt = salt;
        self
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

    /// Returns the salt included in the storage commitment.
    pub fn salt(&self) -> [Felt; 2] {
        self.salt
    }
}

impl From<P2idNoteStorage> for NoteStorage {
    fn from(storage: P2idNoteStorage) -> Self {
        // Storage layout:
        // [ account_id_suffix, account_id_prefix, salt_0, salt_1 ]
        NoteStorage::new(vec![
            storage.target.suffix(),
            storage.target.prefix().as_felt(),
            storage.salt[0],
            storage.salt[1],
        ])
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

        let target = AccountId::try_from_elements(note_storage[0], note_storage[1])
            .map_err(|err| NoteError::other_with_source("failed to create account id", err))?;

        Ok(Self {
            target,
            salt: [note_storage[2], note_storage[3]],
        })
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for P2idNote {
    fn consumption_cycles() -> u32 {
        P2ID_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::{AccountId, AccountType};
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::errors::NoteError;
    use miden_protocol::{Felt, Word};

    use super::*;

    // STORAGE TESTS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn try_from_valid_storage_succeeds() {
        let target = AccountId::builder()
            .account_type(AccountType::Private)
            .build_with_seed([1u8; 32]);

        let salt = [Felt::ONE, Felt::from(2u32)];
        let storage = vec![target.suffix(), target.prefix().as_felt(), salt[0], salt[1]];

        let parsed =
            P2idNoteStorage::try_from(storage.as_slice()).expect("storage should be valid");

        assert_eq!(parsed.target(), target);
        assert_eq!(parsed.salt(), salt);
        assert_eq!(NoteStorage::from(parsed).items(), storage.as_slice());
    }

    #[test]
    fn try_from_invalid_length_returns_error() {
        for len in [0, 1, 2, 3, 5] {
            let storage = vec![Felt::ZERO; len];
            let err = P2idNoteStorage::try_from(storage.as_slice())
                .expect_err("should fail due to invalid length");

            assert_matches!(err, NoteError::InvalidNoteStorageLength {
                expected: P2idNote::NUM_STORAGE_ITEMS,
                actual,
            } => assert_eq!(actual, len));
        }
    }

    #[test]
    fn try_from_invalid_storage_contents_returns_error() {
        let storage = vec![
            Felt::new_unchecked(999_u64),
            Felt::new_unchecked(888_u64),
            Felt::ZERO,
            Felt::ZERO,
        ];

        let err = P2idNoteStorage::try_from(storage.as_slice())
            .expect_err("should fail due to invalid account id encoding");

        assert!(matches!(err, NoteError::Other { source: Some(_), .. }));
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

    /// The minimal builder uses defaults for everything but the required fields.
    #[test]
    fn builder_minimal_uses_defaults() {
        let note = P2idNote::builder()
            .sender(sender())
            .target(target())
            .serial_number(Word::empty())
            .asset(FungibleAsset::new(faucet_a(), 1).unwrap())
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender());
        assert_eq!(note.target(), target());
        assert_eq!(note.storage().salt(), [Felt::ZERO; 2]);
        assert_eq!(note.note_type(), NoteType::default());
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.attachments().num_attachments(), 0);
    }

    #[test]
    fn salt_changes_storage_and_recipient_commitments() {
        let storage = P2idNoteStorage::new(target());
        let recipient = storage.into_recipient(Word::empty());

        for salt in [[Felt::ONE, Felt::ZERO], [Felt::ZERO, Felt::ONE]] {
            let note: Note = P2idNote::builder()
                .sender(sender())
                .target(target())
                .salt(salt)
                .serial_number(Word::empty())
                .asset(FungibleAsset::new(faucet_a(), 1).unwrap())
                .build()
                .unwrap()
                .into();

            assert_eq!(note.recipient(), &storage.with_salt(salt).into_recipient(Word::empty()));
            assert_ne!(note.recipient().storage().commitment(), recipient.storage().commitment());
            assert_ne!(note.recipient().digest(), recipient.digest());
        }
    }

    /// Tests account ID enumeration against an exposed private P2ID storage commitment.
    /// This checks a bounded candidate search, not the cost of recovering an unknown salt.
    #[test]
    fn private_note_storage_commitment_account_id_search() {
        let candidates: Vec<_> = (0..16u8)
            .map(|seed| {
                AccountId::builder()
                    .account_type(AccountType::Private)
                    .build_with_seed([seed; 32])
            })
            .collect();
        let target = candidates[7];
        let salt_word = RandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
        let salt = [salt_word[0], salt_word[1]];

        let storage_commitment = |salt| {
            let note: Note = P2idNote::builder()
                .sender(sender())
                .target(target)
                .salt(salt)
                .note_type(NoteType::Private)
                .serial_number(Word::empty())
                .asset(FungibleAsset::new(faucet_a(), 1).unwrap())
                .build()
                .unwrap()
                .into();
            note.storage().commitment()
        };
        let find_target = |commitment, salt| {
            candidates.iter().copied().find(|candidate| {
                NoteStorage::from(P2idNoteStorage::new(*candidate).with_salt(salt)).commitment()
                    == commitment
            })
        };

        let unsalted_commitment = storage_commitment([Felt::ZERO; 2]);
        let salted_commitment = storage_commitment(salt);

        // With zero salt, checking the candidate account IDs identifies the target.
        assert_eq!(find_target(unsalted_commitment, [Felt::ZERO; 2]), Some(target));
        // The same search fails when the note has a secret salt, even with the target in the set.
        assert_eq!(find_target(salted_commitment, [Felt::ZERO; 2]), None);
        // Disclosing the salt makes the target identifiable again.
        assert_eq!(find_target(salted_commitment, salt), Some(target));
    }

    /// `.asset()` and `.assets()` both append, so they can be combined and called repeatedly.
    #[test]
    fn builder_accumulates_assets() {
        let mut rng = RandomCoin::new(Word::empty());
        let note = P2idNote::builder()
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

    /// A P2ID note must carry at least one asset.
    #[test]
    fn builder_rejects_empty_assets() {
        let err = P2idNote::builder()
            .sender(sender())
            .target(target())
            .serial_number(Word::empty())
            .build()
            .expect_err("a note without assets must be rejected");

        assert_matches!(err, NoteError::Other { error_msg, .. } => {
            assert!(error_msg.contains("note must contain at least one asset"))
        });
    }
}
