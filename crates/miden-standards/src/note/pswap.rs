use alloc::vec;

use miden_protocol::Hasher;
use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteMetadata, NoteRecipient,
    NoteScript, NoteStorage, NoteTag, NoteType,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word, ZERO};

use crate::StandardsLib;
use crate::note::P2idNoteStorage;

// NOTE SCRIPT
// ================================================================================================

/// Path to the PSWAP note script procedure in the standards library.
const PSWAP_SCRIPT_PATH: &str = "::miden::standards::notes::pswap::main";

// Initialize the PSWAP note script only once
static PSWAP_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(PSWAP_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains PSWAP note script procedure")
});

// PSWAP NOTE STORAGE
// ================================================================================================

/// Typed storage representation for a PSWAP note.
///
/// Encapsulates the 18-item storage layout used by the PSWAP MASM contract:
/// - [0-3]:   ASSET_KEY  (requested asset key from asset.to_key_word())
/// - [4-7]:   ASSET_VALUE (requested asset value from asset.to_value_word())
/// - [8]:     PSWAP tag
/// - [9]:     P2ID routing tag
/// - [10-11]: Reserved (zero)
/// - [12]:    Swap count
/// - [13-15]: Reserved (zero)
/// - [16]:    Creator account ID prefix
/// - [17]:    Creator account ID suffix
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PswapNoteStorage {
    requested_key: Word,
    requested_value: Word,
    pswap_tag: NoteTag,
    p2id_tag: NoteTag,
    swap_count: u64,
    creator_account_id: AccountId,
}

impl PswapNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for the PSWAP note.
    pub const NUM_STORAGE_ITEMS: usize = 18;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates storage for a new PSWAP note from the requested asset and creator.
    ///
    /// The `pswap_tag` is defaulted and will be computed when converting to a [`Note`].
    /// The `swap_count` starts at 0.
    pub fn new(requested_asset: Asset, creator_account_id: AccountId) -> Self {
        let p2id_tag = NoteTag::with_account_target(creator_account_id);
        Self {
            requested_key: requested_asset.to_key_word(),
            requested_value: requested_asset.to_value_word(),
            pswap_tag: NoteTag::new(0),
            p2id_tag,
            swap_count: 0,
            creator_account_id,
        }
    }

    /// Creates storage with all fields specified explicitly.
    ///
    /// Used for remainder notes where all fields (including swap count and tags) are known.
    pub fn from_parts(
        requested_key: Word,
        requested_value: Word,
        pswap_tag: NoteTag,
        p2id_tag: NoteTag,
        swap_count: u64,
        creator_account_id: AccountId,
    ) -> Self {
        Self {
            requested_key,
            requested_value,
            pswap_tag,
            p2id_tag,
            swap_count,
            creator_account_id,
        }
    }

    /// Consumes the storage and returns a PSWAP [`NoteRecipient`] with the provided serial number.
    pub fn into_recipient(self, serial_num: Word) -> NoteRecipient {
        NoteRecipient::new(serial_num, PswapNote::script(), NoteStorage::from(self))
    }

    /// Sets the pswap_tag on this storage, returning the modified storage.
    pub(crate) fn with_pswap_tag(mut self, tag: NoteTag) -> Self {
        self.pswap_tag = tag;
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the requested asset key word.
    pub fn requested_key(&self) -> Word {
        self.requested_key
    }

    /// Returns the requested asset value word.
    pub fn requested_value(&self) -> Word {
        self.requested_value
    }

    /// Returns the PSWAP note tag.
    pub fn pswap_tag(&self) -> NoteTag {
        self.pswap_tag
    }

    /// Returns the P2ID routing tag.
    pub fn p2id_tag(&self) -> NoteTag {
        self.p2id_tag
    }

    /// Returns the current swap count.
    pub fn swap_count(&self) -> u64 {
        self.swap_count
    }

    /// Returns the creator account ID.
    pub fn creator_account_id(&self) -> AccountId {
        self.creator_account_id
    }

    /// Reconstructs the requested asset from the key and value words.
    pub fn requested_asset(&self) -> Result<Asset, NoteError> {
        let faucet_id = self.requested_faucet_id()?;
        let amount = self.requested_amount();
        Ok(Asset::Fungible(FungibleAsset::new(faucet_id, amount).map_err(|e| {
            NoteError::other_with_source("failed to create requested asset", e)
        })?))
    }

    /// Extracts the faucet ID from the requested key word.
    pub fn requested_faucet_id(&self) -> Result<AccountId, NoteError> {
        // Key layout: [key[0], key[1], faucet_suffix, faucet_prefix]
        AccountId::try_from_elements(self.requested_key[2], self.requested_key[3]).map_err(|e| {
            NoteError::other_with_source("failed to parse faucet ID from key", e)
        })
    }

    /// Extracts the requested amount from the value word.
    pub fn requested_amount(&self) -> u64 {
        // ASSET_VALUE[0] = amount (from asset::fungible_to_amount)
        self.requested_value[0].as_canonical_u64()
    }
}

impl From<PswapNoteStorage> for NoteStorage {
    fn from(storage: PswapNoteStorage) -> Self {
        let inputs = vec![
            // ASSET_KEY [0-3]
            storage.requested_key[0],
            storage.requested_key[1],
            storage.requested_key[2],
            storage.requested_key[3],
            // ASSET_VALUE [4-7]
            storage.requested_value[0],
            storage.requested_value[1],
            storage.requested_value[2],
            storage.requested_value[3],
            // Tags [8-9]
            Felt::new(u32::from(storage.pswap_tag) as u64),
            Felt::new(u32::from(storage.p2id_tag) as u64),
            // Padding [10-11]
            ZERO,
            ZERO,
            // Swap count [12-15]
            Felt::new(storage.swap_count),
            ZERO,
            ZERO,
            ZERO,
            // Creator ID [16-17]
            storage.creator_account_id.prefix().as_felt(),
            storage.creator_account_id.suffix(),
        ];
        NoteStorage::new(inputs)
            .expect("number of storage items should not exceed max storage items")
    }
}

impl TryFrom<&[Felt]> for PswapNoteStorage {
    type Error = NoteError;

    fn try_from(inputs: &[Felt]) -> Result<Self, Self::Error> {
        if inputs.len() != Self::NUM_STORAGE_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: Self::NUM_STORAGE_ITEMS,
                actual: inputs.len(),
            });
        }

        let requested_key = Word::from([inputs[0], inputs[1], inputs[2], inputs[3]]);
        let requested_value = Word::from([inputs[4], inputs[5], inputs[6], inputs[7]]);
        let pswap_tag = NoteTag::new(inputs[8].as_canonical_u64() as u32);
        let p2id_tag = NoteTag::new(inputs[9].as_canonical_u64() as u32);
        let swap_count = inputs[12].as_canonical_u64();

        let creator_account_id =
            AccountId::try_from_elements(inputs[17], inputs[16]).map_err(|e| {
                NoteError::other_with_source("failed to parse creator account ID", e)
            })?;

        Ok(Self {
            requested_key,
            requested_value,
            pswap_tag,
            p2id_tag,
            swap_count,
            creator_account_id,
        })
    }
}

// PSWAP NOTE
// ================================================================================================

/// Partial swap (pswap) note for decentralized asset exchange.
///
/// This note implements a partially-fillable swap mechanism where:
/// - Creator offers an asset and requests another asset
/// - Note can be partially or fully filled by consumers
/// - Unfilled portions create remainder notes
/// - Creator receives requested assets via P2ID notes
#[derive(Debug, Clone, bon::Builder)]
pub struct PswapNote {
    sender: AccountId,
    storage: PswapNoteStorage,
    serial_number: Word,

    #[builder(default = NoteType::Private)]
    note_type: NoteType,

    #[builder(default)]
    assets: NoteAssets,

    #[builder(default)]
    attachment: NoteAttachment,
}

impl PswapNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for the PSWAP note.
    pub const NUM_STORAGE_ITEMS: usize = PswapNoteStorage::NUM_STORAGE_ITEMS;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the PSWAP note.
    pub fn script() -> NoteScript {
        PSWAP_SCRIPT.clone()
    }

    /// Returns the PSWAP note script root.
    pub fn script_root() -> Word {
        PSWAP_SCRIPT.root()
    }

    /// Returns the sender account ID.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns a reference to the note storage.
    pub fn storage(&self) -> &PswapNoteStorage {
        &self.storage
    }

    /// Returns the serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the note type.
    pub fn note_type(&self) -> NoteType {
        self.note_type
    }

    /// Returns a reference to the note assets.
    pub fn assets(&self) -> &NoteAssets {
        &self.assets
    }

    /// Returns a reference to the note attachment.
    pub fn attachment(&self) -> &NoteAttachment {
        &self.attachment
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates a PSWAP note offering one asset in exchange for another.
    ///
    /// This is a convenience method that constructs a [`PswapNote`] and converts it to a
    /// protocol [`Note`].
    ///
    /// # Errors
    ///
    /// Returns an error if assets are invalid or have the same faucet ID.
    pub fn create<R: FeltRng>(
        creator_account_id: AccountId,
        offered_asset: Asset,
        requested_asset: Asset,
        note_type: NoteType,
        note_attachment: NoteAttachment,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        if offered_asset.faucet_id().prefix() == requested_asset.faucet_id().prefix() {
            return Err(NoteError::other(
                "offered and requested assets must have different faucets",
            ));
        }

        let storage = PswapNoteStorage::new(requested_asset, creator_account_id);
        let pswap = PswapNote::builder()
            .sender(creator_account_id)
            .storage(storage)
            .serial_number(rng.draw_word())
            .note_type(note_type)
            .assets(NoteAssets::new(vec![offered_asset])?)
            .attachment(note_attachment)
            .build();

        Ok(Note::from(pswap))
    }

    // INSTANCE METHODS
    // --------------------------------------------------------------------------------------------

    /// Executes the swap by creating output notes for a fill.
    ///
    /// Handles both full and partial fills:
    /// - **Full fill**: Returns P2ID note with full requested amount, no remainder
    /// - **Partial fill**: Returns P2ID note with partial amount + remainder PswapNote
    ///
    /// # Arguments
    ///
    /// * `consumer_account_id` - The account consuming the swap note
    /// * `input_amount` - Amount debited from consumer's vault
    /// * `inflight_amount` - Amount added directly (no vault debit, for cross-swaps)
    ///
    /// # Returns
    ///
    /// Returns a tuple of `(p2id_note, Option<remainder_pswap_note>)`
    pub fn execute(
        &self,
        consumer_account_id: AccountId,
        input_amount: u64,
        inflight_amount: u64,
    ) -> Result<(Note, Option<PswapNote>), NoteError> {
        let fill_amount = input_amount + inflight_amount;

        let requested_faucet_id = self.storage.requested_faucet_id()?;
        let total_requested_amount = self.storage.requested_amount();

        // Ensure offered asset exists and is fungible
        if self.assets.num_assets() != 1 {
            return Err(NoteError::other("Swap note must have exactly 1 offered asset"));
        }
        let offered_asset =
            self.assets.iter().next().ok_or(NoteError::other("No offered asset found"))?;
        let (offered_faucet_id, total_offered_amount) = match offered_asset {
            Asset::Fungible(fa) => (fa.faucet_id(), fa.amount()),
            _ => return Err(NoteError::other("Non-fungible offered asset not supported")),
        };

        // Validate fill amount
        if fill_amount == 0 {
            return Err(NoteError::other("Fill amount must be greater than 0"));
        }
        if fill_amount > total_requested_amount {
            return Err(NoteError::other(alloc::format!(
                "Fill amount {} exceeds requested amount {}",
                fill_amount,
                total_requested_amount
            )));
        }

        // Calculate offered amounts separately for input and inflight, matching the MASM
        // which calls calculate_tokens_offered_for_requested twice.
        let offered_for_input = Self::calculate_output_amount(
            total_offered_amount,
            total_requested_amount,
            input_amount,
        );
        let offered_for_inflight = Self::calculate_output_amount(
            total_offered_amount,
            total_requested_amount,
            inflight_amount,
        );
        let offered_amount_for_fill = offered_for_input + offered_for_inflight;

        // Build the P2ID payback note
        let payback_asset =
            Asset::Fungible(FungibleAsset::new(requested_faucet_id, fill_amount).map_err(|e| {
                NoteError::other_with_source("failed to create P2ID asset", e)
            })?);

        let aux_word = Word::from([Felt::new(fill_amount), ZERO, ZERO, ZERO]);

        let p2id_note = self.build_p2id_payback_note(
            consumer_account_id,
            payback_asset,
            aux_word,
        )?;

        // Create remainder note if partial fill
        let remainder = if fill_amount < total_requested_amount {
            let remaining_offered = total_offered_amount - offered_amount_for_fill;
            let remaining_requested = total_requested_amount - fill_amount;

            let remaining_offered_asset =
                Asset::Fungible(FungibleAsset::new(offered_faucet_id, remaining_offered).map_err(
                    |e| NoteError::other_with_source("failed to create remainder asset", e),
                )?);

            Some(self.build_remainder_pswap_note(
                consumer_account_id,
                remaining_offered_asset,
                remaining_requested,
                offered_amount_for_fill,
            )?)
        } else {
            None
        };

        Ok((p2id_note, remainder))
    }

    /// Calculates how many offered tokens a consumer receives for a given requested input.
    ///
    /// This is the Rust equivalent of `calculate_tokens_offered_for_requested` in pswap.masm.
    pub fn calculate_offered_for_requested(
        &self,
        input_amount: u64,
    ) -> Result<u64, NoteError> {
        let total_requested = self.storage.requested_amount();

        let offered_asset = self
            .assets
            .iter()
            .next()
            .ok_or(NoteError::other("No offered asset found"))?;
        let total_offered = match offered_asset {
            Asset::Fungible(fa) => fa.amount(),
            _ => return Err(NoteError::other("Non-fungible offered asset not supported")),
        };

        Ok(Self::calculate_output_amount(total_offered, total_requested, input_amount))
    }

    // ASSOCIATED FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns a note tag for a pswap note with the specified parameters.
    ///
    /// Layout:
    /// ```text
    /// [ note_type (2 bits) | script_root (14 bits)
    ///   | offered_asset_faucet_id (8 bits) | requested_asset_faucet_id (8 bits) ]
    /// ```
    pub fn build_tag(
        note_type: NoteType,
        offered_asset: &Asset,
        requested_asset: &Asset,
    ) -> NoteTag {
        let pswap_root_bytes = Self::script().root().as_bytes();

        // Construct the pswap use case ID from the 14 most significant bits of the script root.
        // This leaves the two most significant bits zero.
        let mut pswap_use_case_id = (pswap_root_bytes[0] as u16) << 6;
        pswap_use_case_id |= (pswap_root_bytes[1] >> 2) as u16;

        // Get bits 0..8 from the faucet IDs of both assets which will form the tag payload.
        let offered_asset_id: u64 = offered_asset.faucet_id().prefix().into();
        let offered_asset_tag = (offered_asset_id >> 56) as u8;

        let requested_asset_id: u64 = requested_asset.faucet_id().prefix().into();
        let requested_asset_tag = (requested_asset_id >> 56) as u8;

        let asset_pair = ((offered_asset_tag as u16) << 8) | (requested_asset_tag as u16);

        let tag = ((note_type as u8 as u32) << 30)
            | ((pswap_use_case_id as u32) << 16)
            | asset_pair as u32;

        NoteTag::new(tag)
    }

    /// Calculates the output amount for a fill using u64 integer arithmetic
    /// with a precision factor of 1e5 (matching the MASM on-chain calculation).
    pub fn calculate_output_amount(
        offered_total: u64,
        requested_total: u64,
        input_amount: u64,
    ) -> u64 {
        const PRECISION_FACTOR: u64 = 100_000;

        if requested_total == input_amount {
            return offered_total;
        }

        if offered_total > requested_total {
            let ratio = (offered_total * PRECISION_FACTOR) / requested_total;
            (input_amount * ratio) / PRECISION_FACTOR
        } else {
            let ratio = (requested_total * PRECISION_FACTOR) / offered_total;
            (input_amount * PRECISION_FACTOR) / ratio
        }
    }

    /// Builds a P2ID (Pay-to-ID) payback note for the swap creator.
    ///
    /// The P2ID note inherits the note type from this PSWAP note.
    /// Derives a unique serial number matching the MASM: `hmerge(swap_count_word, serial_num)`.
    pub fn build_p2id_payback_note(
        &self,
        consumer_account_id: AccountId,
        payback_asset: Asset,
        aux_word: Word,
    ) -> Result<Note, NoteError> {
        let p2id_tag = self.storage.p2id_tag();
        // Derive P2ID serial matching PSWAP.masm
        let swap_count_word =
            Word::from([Felt::new(self.storage.swap_count + 1), ZERO, ZERO, ZERO]);
        let p2id_serial_digest =
            Hasher::merge(&[swap_count_word.into(), self.serial_number.into()]);
        let p2id_serial_num: Word = Word::from(p2id_serial_digest);

        // P2ID recipient targets the creator
        let recipient =
            P2idNoteStorage::new(self.storage.creator_account_id).into_recipient(p2id_serial_num);

        let attachment = NoteAttachment::new_word(NoteAttachmentScheme::none(), aux_word);

        let p2id_assets = NoteAssets::new(vec![payback_asset])?;
        let p2id_metadata = NoteMetadata::new(consumer_account_id, self.note_type)
            .with_tag(p2id_tag)
            .with_attachment(attachment);

        Ok(Note::new(p2id_assets, p2id_metadata, recipient))
    }

    /// Builds a remainder note for partial fills.
    ///
    /// Builds updated note storage with the remaining requested amount and incremented
    /// swap count, returning a [`PswapNote`] that can be converted to a protocol [`Note`].
    pub fn build_remainder_pswap_note(
        &self,
        consumer_account_id: AccountId,
        remaining_offered_asset: Asset,
        remaining_requested_amount: u64,
        offered_amount_for_fill: u64,
    ) -> Result<PswapNote, NoteError> {
        let requested_faucet_id = self.storage.requested_faucet_id()?;
        let remaining_requested_asset = Asset::Fungible(
            FungibleAsset::new(requested_faucet_id, remaining_requested_amount).map_err(|e| {
                NoteError::other_with_source("failed to create remaining requested asset", e)
            })?,
        );

        let key_word = remaining_requested_asset.to_key_word();
        let value_word = remaining_requested_asset.to_value_word();

        let new_storage = PswapNoteStorage::from_parts(
            key_word,
            value_word,
            self.storage.pswap_tag,
            self.storage.p2id_tag,
            self.storage.swap_count + 1,
            self.storage.creator_account_id,
        );

        // Remainder serial: increment top element (matching MASM add.1 on Word[0])
        let remainder_serial_num = Word::from([
            Felt::new(self.serial_number[0].as_canonical_u64() + 1),
            self.serial_number[1],
            self.serial_number[2],
            self.serial_number[3],
        ]);

        let aux_word = Word::from([Felt::new(offered_amount_for_fill), ZERO, ZERO, ZERO]);
        let attachment = NoteAttachment::new_word(NoteAttachmentScheme::none(), aux_word);

        let assets = NoteAssets::new(vec![remaining_offered_asset])?;

        Ok(PswapNote {
            sender: consumer_account_id,
            storage: new_storage,
            serial_number: remainder_serial_num,
            note_type: self.note_type,
            assets,
            attachment,
        })
    }
}

// CONVERSIONS
// ================================================================================================

impl From<PswapNote> for Note {
    fn from(pswap: PswapNote) -> Self {
        let offered_asset = pswap
            .assets
            .iter()
            .next()
            .expect("PswapNote must have an offered asset");
        let requested_asset = pswap
            .storage
            .requested_asset()
            .expect("PswapNote must have a valid requested asset");
        let tag = PswapNote::build_tag(pswap.note_type, &offered_asset, &requested_asset);

        let storage = pswap.storage.with_pswap_tag(tag);
        let recipient = storage.into_recipient(pswap.serial_number);

        let metadata = NoteMetadata::new(pswap.sender, pswap.note_type)
            .with_tag(tag)
            .with_attachment(pswap.attachment);

        Note::new(pswap.assets, metadata, recipient)
    }
}

impl From<&PswapNote> for Note {
    fn from(pswap: &PswapNote) -> Self {
        Note::from(pswap.clone())
    }
}

impl TryFrom<&Note> for PswapNote {
    type Error = NoteError;

    fn try_from(note: &Note) -> Result<Self, Self::Error> {
        let storage = PswapNoteStorage::try_from(note.recipient().storage().items())?;

        Ok(Self {
            sender: note.metadata().sender(),
            storage,
            serial_number: note.recipient().serial_num(),
            note_type: note.metadata().note_type(),
            assets: note.assets().clone(),
            attachment: note.metadata().attachment().clone(),
        })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
    use miden_protocol::asset::FungibleAsset;

    use super::*;

    #[test]
    fn pswap_note_creation_and_script() {
        let mut offered_faucet_bytes = [0; 15];
        offered_faucet_bytes[0] = 0xaa;

        let mut requested_faucet_bytes = [0; 15];
        requested_faucet_bytes[0] = 0xbb;

        let offered_faucet_id = AccountId::dummy(
            offered_faucet_bytes,
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        );

        let requested_faucet_id = AccountId::dummy(
            requested_faucet_bytes,
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        );

        let creator_id = AccountId::dummy(
            [1; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Public,
        );

        let offered_asset = Asset::Fungible(FungibleAsset::new(offered_faucet_id, 1000).unwrap());
        let requested_asset =
            Asset::Fungible(FungibleAsset::new(requested_faucet_id, 500).unwrap());

        use miden_protocol::crypto::rand::RpoRandomCoin;
        let mut rng = RpoRandomCoin::new(Word::default());

        let script = PswapNote::script();
        assert!(script.root() != Word::default(), "Script root should not be zero");

        let note = PswapNote::create(
            creator_id,
            offered_asset,
            requested_asset,
            NoteType::Public,
            NoteAttachment::default(),
            &mut rng,
        );

        assert!(note.is_ok(), "Note creation should succeed");
        let note = note.unwrap();

        assert_eq!(note.metadata().sender(), creator_id);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.recipient().script().root(), script.root());

        // Verify storage has 18 items
        assert_eq!(
            note.recipient().storage().num_items(),
            PswapNote::NUM_STORAGE_ITEMS as u16,
        );
    }

    #[test]
    fn pswap_note_builder() {
        let mut offered_faucet_bytes = [0; 15];
        offered_faucet_bytes[0] = 0xaa;

        let mut requested_faucet_bytes = [0; 15];
        requested_faucet_bytes[0] = 0xbb;

        let offered_faucet_id = AccountId::dummy(
            offered_faucet_bytes,
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        );

        let requested_faucet_id = AccountId::dummy(
            requested_faucet_bytes,
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        );

        let creator_id = AccountId::dummy(
            [1; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Public,
        );

        let offered_asset = Asset::Fungible(FungibleAsset::new(offered_faucet_id, 1000).unwrap());
        let requested_asset =
            Asset::Fungible(FungibleAsset::new(requested_faucet_id, 500).unwrap());

        use miden_protocol::crypto::rand::{FeltRng, RpoRandomCoin};
        let mut rng = RpoRandomCoin::new(Word::default());

        let storage = PswapNoteStorage::new(requested_asset, creator_id);
        let pswap = PswapNote::builder()
            .sender(creator_id)
            .storage(storage)
            .serial_number(rng.draw_word())
            .note_type(NoteType::Public)
            .assets(NoteAssets::new(vec![offered_asset]).unwrap())
            .build();

        assert_eq!(pswap.sender(), creator_id);
        assert_eq!(pswap.note_type(), NoteType::Public);
        assert_eq!(pswap.assets().num_assets(), 1);

        // Convert to Note
        let note: Note = pswap.into();
        assert_eq!(note.metadata().sender(), creator_id);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(
            note.recipient().storage().num_items(),
            PswapNote::NUM_STORAGE_ITEMS as u16,
        );
    }

    #[test]
    fn pswap_tag() {
        let mut offered_faucet_bytes = [0; 15];
        offered_faucet_bytes[0] = 0xcd;
        offered_faucet_bytes[1] = 0xb1;

        let mut requested_faucet_bytes = [0; 15];
        requested_faucet_bytes[0] = 0xab;
        requested_faucet_bytes[1] = 0xec;

        let offered_asset = Asset::Fungible(
            FungibleAsset::new(
                AccountId::dummy(
                    offered_faucet_bytes,
                    AccountIdVersion::Version0,
                    AccountType::FungibleFaucet,
                    AccountStorageMode::Public,
                ),
                100,
            )
            .unwrap(),
        );
        let requested_asset = Asset::Fungible(
            FungibleAsset::new(
                AccountId::dummy(
                    requested_faucet_bytes,
                    AccountIdVersion::Version0,
                    AccountType::FungibleFaucet,
                    AccountStorageMode::Public,
                ),
                200,
            )
            .unwrap(),
        );

        let tag = PswapNote::build_tag(NoteType::Public, &offered_asset, &requested_asset);
        let tag_u32 = u32::from(tag);

        // Verify note_type bits (top 2 bits should be 10 for Public)
        let note_type_bits = tag_u32 >> 30;
        assert_eq!(note_type_bits, NoteType::Public as u32);
    }

    #[test]
    fn calculate_output_amount() {
        // Equal ratio
        assert_eq!(PswapNote::calculate_output_amount(100, 100, 50), 50);

        // 2:1 ratio
        assert_eq!(PswapNote::calculate_output_amount(200, 100, 50), 100);

        // 1:2 ratio
        assert_eq!(PswapNote::calculate_output_amount(100, 200, 50), 25);

        // Non-integer ratio (100/73)
        let result = PswapNote::calculate_output_amount(100, 73, 7);
        assert!(result > 0, "Should produce non-zero output");
    }

    #[test]
    fn pswap_note_storage_try_from() {
        let creator_id = AccountId::dummy(
            [1; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Public,
        );

        let faucet_id = AccountId::dummy(
            [0xaa; 15],
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        );

        let asset = Asset::Fungible(FungibleAsset::new(faucet_id, 500).unwrap());
        let key_word = asset.to_key_word();
        let value_word = asset.to_value_word();

        let inputs = vec![
            key_word[0],
            key_word[1],
            key_word[2],
            key_word[3],
            value_word[0],
            value_word[1],
            value_word[2],
            value_word[3],
            Felt::new(0xC0000000), // pswap_tag
            Felt::new(0x80000001), // p2id_tag
            ZERO,
            ZERO,
            Felt::new(3), // swap_count
            ZERO,
            ZERO,
            ZERO,
            creator_id.prefix().as_felt(),
            creator_id.suffix(),
        ];

        let parsed = PswapNoteStorage::try_from(inputs.as_slice()).unwrap();
        assert_eq!(parsed.swap_count(), 3);
        assert_eq!(parsed.creator_account_id(), creator_id);
        assert_eq!(
            parsed.requested_key(),
            Word::from([key_word[0], key_word[1], key_word[2], key_word[3]])
        );
        assert_eq!(parsed.requested_amount(), 500);
    }

    #[test]
    fn pswap_note_storage_roundtrip() {
        let creator_id = AccountId::dummy(
            [1; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Public,
        );

        let faucet_id = AccountId::dummy(
            [0xaa; 15],
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        );

        let requested_asset = Asset::Fungible(FungibleAsset::new(faucet_id, 500).unwrap());
        let storage = PswapNoteStorage::new(requested_asset, creator_id);

        // Convert to NoteStorage and back
        let note_storage = NoteStorage::from(storage.clone());
        let parsed = PswapNoteStorage::try_from(note_storage.items()).unwrap();

        assert_eq!(parsed.creator_account_id(), creator_id);
        assert_eq!(parsed.swap_count(), 0);
        assert_eq!(parsed.requested_amount(), 500);
    }
}
