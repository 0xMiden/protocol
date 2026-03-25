use alloc::vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentScheme,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Hasher, Word, ZERO};

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

/// Canonical storage representation for a PSWAP note.
///
/// Maps to the 18-element [`NoteStorage`] layout consumed by the on-chain MASM script:
///
/// | Slot | Field |
/// |---------|-------|
/// | `[0-3]` | Requested asset key (`asset.to_key_word()`) |
/// | `[4-7]` | Requested asset value (`asset.to_value_word()`) |
/// | `[8]` | PSWAP note tag |
/// | `[9]` | Payback note routing tag (targets the creator) |
/// | `[10-11]` | Reserved (zero) |
/// | `[12]` | Swap count (incremented on each partial fill) |
/// | `[13-15]` | Reserved (zero) |
/// | `[16-17]` | Creator account ID (prefix, suffix) |
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct PswapNoteStorage {
    requested_asset_key: Word,
    requested_asset_value: Word,

    #[builder(default)]
    pswap_tag: NoteTag,

    #[builder(default)]
    swap_count: u16,

    creator_account_id: AccountId,
}

impl PswapNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for the PSWAP note.
    pub const NUM_STORAGE_ITEMS: usize = 18;

    /// Consumes the storage and returns a PSWAP [`NoteRecipient`] with the provided serial number.
    pub fn into_recipient(self, serial_num: Word) -> NoteRecipient {
        NoteRecipient::new(serial_num, PswapNote::script(), NoteStorage::from(self))
    }

    /// Overwrites the PSWAP tag. Called during [`Note`] conversion once the tag can be derived
    /// from the offered/requested asset pair.
    pub(crate) fn with_pswap_tag(mut self, tag: NoteTag) -> Self {
        self.pswap_tag = tag;
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    pub fn requested_asset_key(&self) -> Word {
        self.requested_asset_key
    }

    pub fn requested_asset_value(&self) -> Word {
        self.requested_asset_value
    }

    pub fn pswap_tag(&self) -> NoteTag {
        self.pswap_tag
    }

    pub fn payback_note_tag(&self) -> NoteTag {
        NoteTag::with_account_target(self.creator_account_id)
    }

    /// Number of times this note has been partially filled and re-created.
    pub fn swap_count(&self) -> u16 {
        self.swap_count
    }

    pub fn creator_account_id(&self) -> AccountId {
        self.creator_account_id
    }

    /// Reconstructs the requested [`Asset`] from the stored key and value words.
    ///
    /// # Errors
    ///
    /// Returns an error if the faucet ID or amount stored in the key/value words is invalid.
    pub fn requested_asset(&self) -> Result<Asset, NoteError> {
        let faucet_id = self.requested_faucet_id()?;
        let amount = self.requested_asset_amount();
        Ok(Asset::Fungible(FungibleAsset::new(faucet_id, amount).map_err(|e| {
            NoteError::other_with_source("failed to create requested asset", e)
        })?))
    }

    /// Extracts the faucet ID of the requested asset from the key word.
    pub fn requested_faucet_id(&self) -> Result<AccountId, NoteError> {
        AccountId::try_from_elements(self.requested_asset_key[2], self.requested_asset_key[3])
            .map_err(|e| NoteError::other_with_source("failed to parse faucet ID from key", e))
    }

    /// Extracts the requested token amount from the value word.
    pub fn requested_asset_amount(&self) -> u64 {
        self.requested_asset_value[0].as_canonical_u64()
    }
}

/// Serializes [`PswapNoteStorage`] into an 18-element [`NoteStorage`].
impl From<PswapNoteStorage> for NoteStorage {
    fn from(storage: PswapNoteStorage) -> Self {
        let storage_items = vec![
            // ASSET_KEY [0-3]
            storage.requested_asset_key[0],
            storage.requested_asset_key[1],
            storage.requested_asset_key[2],
            storage.requested_asset_key[3],
            // ASSET_VALUE [4-7]
            storage.requested_asset_value[0],
            storage.requested_asset_value[1],
            storage.requested_asset_value[2],
            storage.requested_asset_value[3],
            // Tags [8-9]
            Felt::from(storage.pswap_tag),
            Felt::from(storage.payback_note_tag()),
            // Padding [10-11]
            ZERO,
            ZERO,
            // Swap count [12-15]
            Felt::from(storage.swap_count),
            ZERO,
            ZERO,
            ZERO,
            // Creator ID [16-17]
            storage.creator_account_id.prefix().as_felt(),
            storage.creator_account_id.suffix(),
        ];
        NoteStorage::new(storage_items)
            .expect("number of storage items should not exceed max storage items")
    }
}

/// Deserializes [`PswapNoteStorage`] from a slice of exactly 18 [`Felt`]s.
impl TryFrom<&[Felt]> for PswapNoteStorage {
    type Error = NoteError;

    fn try_from(note_storage: &[Felt]) -> Result<Self, Self::Error> {
        if note_storage.len() != Self::NUM_STORAGE_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: Self::NUM_STORAGE_ITEMS,
                actual: note_storage.len(),
            });
        }

        let requested_asset_key =
            Word::from([note_storage[0], note_storage[1], note_storage[2], note_storage[3]]);
        let requested_asset_value =
            Word::from([note_storage[4], note_storage[5], note_storage[6], note_storage[7]]);
        let pswap_tag = NoteTag::new(note_storage[8].as_canonical_u64() as u32);
        let swap_count: u16 = note_storage[12]
            .as_canonical_u64()
            .try_into()
            .map_err(|_| NoteError::other("swap_count exceeds u16"))?;

        let creator_account_id = AccountId::try_from_elements(note_storage[17], note_storage[16])
            .map_err(|e| {
            NoteError::other_with_source("failed to parse creator account ID", e)
        })?;

        Ok(Self {
            requested_asset_key,
            requested_asset_value,
            pswap_tag,
            swap_count,
            creator_account_id,
        })
    }
}

// PSWAP NOTE
// ================================================================================================

/// A partially-fillable swap note for decentralized asset exchange.
///
/// A PSWAP note allows a creator to offer one fungible asset in exchange for another.
/// Unlike a regular SWAP note, consumers may fill it partially — the unfilled portion
/// is re-created as a remainder note with an incremented swap count, while the creator
/// receives the filled portion via a payback note.
#[derive(Debug, Clone, bon::Builder)]
#[builder(finish_fn(vis = "", name = build_internal))]
pub struct PswapNote {
    sender: AccountId,
    storage: PswapNoteStorage,
    serial_number: Word,

    #[builder(default = NoteType::Private)]
    note_type: NoteType,

    assets: NoteAssets,

    #[builder(default)]
    attachment: NoteAttachment,
}

impl<S: pswap_note_builder::State> PswapNoteBuilder<S>
where
    S: pswap_note_builder::IsComplete,
{
    pub fn build(self) -> Result<PswapNote, NoteError> {
        let note = self.build_internal();

        if note.assets.num_assets() != 1 {
            return Err(NoteError::other("Swap note must have exactly 1 offered asset"));
        }

        let offered_asset = note.assets.iter().next().unwrap();
        let requested_asset = note.storage.requested_asset()?;
        if offered_asset.faucet_id() == requested_asset.faucet_id() {
            return Err(NoteError::other(
                "offered and requested assets must have different faucets",
            ));
        }

        Ok(note)
    }
}

impl PswapNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for the PSWAP note.
    pub const NUM_STORAGE_ITEMS: usize = PswapNoteStorage::NUM_STORAGE_ITEMS;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the compiled PSWAP note script.
    pub fn script() -> NoteScript {
        PSWAP_SCRIPT.clone()
    }

    /// Returns the root hash of the PSWAP note script.
    pub fn script_root() -> Word {
        PSWAP_SCRIPT.root()
    }

    pub fn sender(&self) -> AccountId {
        self.sender
    }

    pub fn storage(&self) -> &PswapNoteStorage {
        &self.storage
    }

    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    pub fn note_type(&self) -> NoteType {
        self.note_type
    }

    pub fn assets(&self) -> &NoteAssets {
        &self.assets
    }

    pub fn attachment(&self) -> &NoteAttachment {
        &self.attachment
    }

    // INSTANCE METHODS
    // --------------------------------------------------------------------------------------------

    /// Executes the swap, producing the output notes for a given fill.
    ///
    /// `input_amount` is debited from the consumer's vault; `inflight_amount` arrives
    /// from another note in the same transaction (cross-swap). Their sum is the total fill.
    ///
    /// Returns `(payback_note, Option<remainder_pswap_note>)`. The remainder is
    /// `None` when the fill equals the total requested amount (full fill).
    pub fn execute(
        &self,
        consumer_account_id: AccountId,
        input_amount: u64,
        inflight_amount: u64,
    ) -> Result<(Note, Option<PswapNote>), NoteError> {
        let fill_amount = input_amount + inflight_amount;

        let requested_faucet_id = self.storage.requested_faucet_id()?;
        let total_requested_amount = self.storage.requested_asset_amount();

        // Ensure offered asset exists and is fungible
        if self.assets.num_assets() != 1 {
            return Err(NoteError::other("Swap note must have exactly 1 offered asset"));
        }
        let total_offered_amount = self.offered_asset_amount()?;
        let offered_faucet_id = match self.assets.iter().next().unwrap() {
            Asset::Fungible(fa) => fa.faucet_id(),
            _ => unreachable!(),
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

        // Build the payback note
        let payback_asset = Asset::Fungible(
            FungibleAsset::new(requested_faucet_id, fill_amount)
                .map_err(|e| NoteError::other_with_source("failed to create payback asset", e))?,
        );

        let payback_note =
            self.create_payback_note(consumer_account_id, payback_asset, fill_amount)?;

        // Create remainder note if partial fill
        let remainder = if fill_amount < total_requested_amount {
            let remaining_offered = total_offered_amount - offered_amount_for_fill;
            let remaining_requested = total_requested_amount - fill_amount;

            let remaining_offered_asset =
                Asset::Fungible(FungibleAsset::new(offered_faucet_id, remaining_offered).map_err(
                    |e| NoteError::other_with_source("failed to create remainder asset", e),
                )?);

            Some(self.create_remainder_pswap_note(
                consumer_account_id,
                remaining_offered_asset,
                remaining_requested,
                offered_amount_for_fill,
            )?)
        } else {
            None
        };

        Ok((payback_note, remainder))
    }

    /// Returns the amount of the offered fungible asset in this note.
    ///
    /// # Errors
    ///
    /// Returns an error if the note has no assets or the asset is non-fungible.
    pub fn offered_asset_amount(&self) -> Result<u64, NoteError> {
        let asset = self.assets.iter().next().ok_or(NoteError::other("No offered asset found"))?;
        match asset {
            Asset::Fungible(fa) => Ok(fa.amount()),
            _ => Err(NoteError::other("Non-fungible offered asset not supported")),
        }
    }

    /// Returns how many offered tokens a consumer receives for `input_amount` of the
    /// requested asset, based on this note's current offered/requested ratio.
    pub fn calculate_offered_for_requested(&self, input_amount: u64) -> Result<u64, NoteError> {
        let total_requested = self.storage.requested_asset_amount();
        let total_offered = self.offered_asset_amount()?;

        Ok(Self::calculate_output_amount(total_offered, total_requested, input_amount))
    }

    // ASSOCIATED FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Builds the 32-bit [`NoteTag`] for a PSWAP note.
    ///
    /// ```text
    /// [31..30] note_type          (2 bits)
    /// [29..16] script_root MSBs   (14 bits)
    /// [15..8]  offered faucet ID  (8 bits, top byte of prefix)
    /// [7..0]   requested faucet ID (8 bits, top byte of prefix)
    /// ```
    pub fn create_tag(
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

    /// Computes `offered_total * input_amount / requested_total` using fixed-point
    /// u64 arithmetic with a precision factor of 10^5, matching the on-chain MASM
    /// calculation. Returns the full `offered_total` when `input_amount == requested_total`.
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

    /// Builds a payback note that delivers the filled assets to the swap creator.
    ///
    /// The note inherits its type (public/private) from this PSWAP note and derives a
    /// deterministic serial number via `hmerge(swap_count + 1, serial_num)`.
    fn create_payback_note(
        &self,
        consumer_account_id: AccountId,
        payback_asset: Asset,
        fill_amount: u64,
    ) -> Result<Note, NoteError> {
        let payback_note_tag = self.storage.payback_note_tag();
        // Derive P2ID serial matching PSWAP.masm
        let swap_count_word =
            Word::from([Felt::from(self.storage.swap_count + 1), ZERO, ZERO, ZERO]);
        let p2id_serial_digest = Hasher::merge(&[swap_count_word, self.serial_number]);
        let p2id_serial_num: Word = p2id_serial_digest;

        // P2ID recipient targets the creator
        let recipient =
            P2idNoteStorage::new(self.storage.creator_account_id).into_recipient(p2id_serial_num);

        let attachment_word = Word::from([Felt::new(fill_amount), ZERO, ZERO, ZERO]);
        let attachment = NoteAttachment::new_word(NoteAttachmentScheme::none(), attachment_word);

        let p2id_assets = NoteAssets::new(vec![payback_asset])?;
        let p2id_metadata = NoteMetadata::new(consumer_account_id, self.note_type)
            .with_tag(payback_note_tag)
            .with_attachment(attachment);

        Ok(Note::new(p2id_assets, p2id_metadata, recipient))
    }

    /// Builds a remainder PSWAP note carrying the unfilled portion of the swap.
    ///
    /// The remainder inherits the original creator, tags, and note type, but has an
    /// incremented swap count and an updated serial number (`serial[0] + 1`).
    fn create_remainder_pswap_note(
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

        let new_storage = PswapNoteStorage::builder()
            .requested_asset_key(key_word)
            .requested_asset_value(value_word)
            .pswap_tag(self.storage.pswap_tag)
            .swap_count(self.storage.swap_count + 1)
            .creator_account_id(self.storage.creator_account_id)
            .build();

        // Remainder serial: increment top element (matching MASM add.1 on Word[0])
        let remainder_serial_num = Word::from([
            Felt::new(self.serial_number[0].as_canonical_u64() + 1),
            self.serial_number[1],
            self.serial_number[2],
            self.serial_number[3],
        ]);

        let attachment_word = Word::from([Felt::new(offered_amount_for_fill), ZERO, ZERO, ZERO]);
        let attachment = NoteAttachment::new_word(NoteAttachmentScheme::none(), attachment_word);

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

/// Converts a [`PswapNote`] into a protocol [`Note`], computing the final PSWAP tag.
impl From<PswapNote> for Note {
    fn from(pswap: PswapNote) -> Self {
        let offered_asset =
            pswap.assets.iter().next().expect("PswapNote must have an offered asset");
        let requested_asset = pswap
            .storage
            .requested_asset()
            .expect("PswapNote must have a valid requested asset");
        let tag = PswapNote::create_tag(pswap.note_type, offered_asset, &requested_asset);

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

/// Parses a protocol [`Note`] back into a [`PswapNote`] by deserializing its storage.
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

        use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
        let mut rng = RandomCoin::new(Word::default());

        let script = PswapNote::script();
        assert!(script.root() != Word::default(), "Script root should not be zero");

        let storage = PswapNoteStorage::builder()
            .requested_asset_key(requested_asset.to_key_word())
            .requested_asset_value(requested_asset.to_value_word())
            .creator_account_id(creator_id)
            .build();
        let pswap = PswapNote::builder()
            .sender(creator_id)
            .storage(storage)
            .serial_number(rng.draw_word())
            .note_type(NoteType::Public)
            .assets(NoteAssets::new(vec![offered_asset]).unwrap())
            .build()
            .unwrap();

        let note: Note = pswap.into();

        assert_eq!(note.metadata().sender(), creator_id);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.recipient().script().root(), script.root());

        // Verify storage has 18 items
        assert_eq!(note.recipient().storage().num_items(), PswapNote::NUM_STORAGE_ITEMS as u16,);
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

        use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
        let mut rng = RandomCoin::new(Word::default());

        let storage = PswapNoteStorage::builder()
            .requested_asset_key(requested_asset.to_key_word())
            .requested_asset_value(requested_asset.to_value_word())
            .creator_account_id(creator_id)
            .build();
        let pswap = PswapNote::builder()
            .sender(creator_id)
            .storage(storage)
            .serial_number(rng.draw_word())
            .note_type(NoteType::Public)
            .assets(NoteAssets::new(vec![offered_asset]).unwrap())
            .build()
            .unwrap();

        assert_eq!(pswap.sender(), creator_id);
        assert_eq!(pswap.note_type(), NoteType::Public);
        assert_eq!(pswap.assets().num_assets(), 1);

        // Convert to Note
        let note: Note = pswap.into();
        assert_eq!(note.metadata().sender(), creator_id);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.recipient().storage().num_items(), PswapNote::NUM_STORAGE_ITEMS as u16,);
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

        let tag = PswapNote::create_tag(NoteType::Public, &offered_asset, &requested_asset);
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

        let storage_items = vec![
            key_word[0],
            key_word[1],
            key_word[2],
            key_word[3],
            value_word[0],
            value_word[1],
            value_word[2],
            value_word[3],
            Felt::from(0xc0000000u32), // pswap_tag
            Felt::from(0x80000001u32), // payback_note_tag
            ZERO,
            ZERO,
            Felt::from(3u16), // swap_count
            ZERO,
            ZERO,
            ZERO,
            creator_id.prefix().as_felt(),
            creator_id.suffix(),
        ];

        let parsed = PswapNoteStorage::try_from(storage_items.as_slice()).unwrap();
        assert_eq!(parsed.swap_count(), 3);
        assert_eq!(parsed.creator_account_id(), creator_id);
        assert_eq!(
            parsed.requested_asset_key(),
            Word::from([key_word[0], key_word[1], key_word[2], key_word[3]])
        );
        assert_eq!(parsed.requested_asset_amount(), 500);
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
        let storage = PswapNoteStorage::builder()
            .requested_asset_key(requested_asset.to_key_word())
            .requested_asset_value(requested_asset.to_value_word())
            .creator_account_id(creator_id)
            .build();

        // Convert to NoteStorage and back
        let note_storage = NoteStorage::from(storage.clone());
        let parsed = PswapNoteStorage::try_from(note_storage.items()).unwrap();

        assert_eq!(parsed.creator_account_id(), creator_id);
        assert_eq!(parsed.swap_count(), 0);
        assert_eq!(parsed.requested_asset_amount(), 500);
    }
}
