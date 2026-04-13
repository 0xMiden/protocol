use alloc::vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::{Asset, AssetCallbackFlag, FungibleAsset};
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteMetadata, NoteRecipient,
    NoteScript, NoteStorage, NoteTag, NoteType,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, ONE, Word, ZERO};

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
/// Maps to the 14-element [`NoteStorage`] layout consumed by the on-chain MASM script:
///
/// | Slot | Field |
/// |---------|-------|
/// | `[0]` | Requested asset enable_callbacks flag |
/// | `[1]` | Requested asset faucet ID suffix |
/// | `[2]` | Requested asset faucet ID prefix |
/// | `[3]` | Requested asset amount |
/// | `[4]` | PSWAP note tag |
/// | `[5]` | Payback note routing tag (targets the creator) |
/// | `[6]` | Payback note type (0 = private, 1 = public) |
/// | `[7]` | Swap count (incremented on each partial fill) |
/// | `[8-9]` | Creator account ID (prefix, suffix) |
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct PswapNoteStorage {
    requested_asset: FungibleAsset,

    #[builder(default)]
    pswap_tag: NoteTag,

    #[builder(default)]
    swap_count: u16,

    creator_account_id: AccountId,

    /// Note type of the payback note produced when the pswap is filled. Defaults to
    /// [`NoteType::Private`] because the payback carries the fill asset and is typically
    /// consumed directly by the creator — a private note is cheaper in fees and bandwidth
    /// and offers the same information (the fill amount is already recorded in the
    /// executed transaction's output).
    #[builder(default = NoteType::Private)]
    payback_note_type: NoteType,
}

impl PswapNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for the PSWAP note.
    pub const NUM_STORAGE_ITEMS: usize = 10;

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

    /// Returns a reference to the requested [`FungibleAsset`].
    pub fn requested_asset(&self) -> &FungibleAsset {
        &self.requested_asset
    }

    /// Returns the PSWAP note tag. This may be the default (zero) tag until the note
    /// is converted into a [`Note`], at which point the tag is derived from the
    /// offered/requested asset pair.
    pub fn pswap_tag(&self) -> NoteTag {
        self.pswap_tag
    }

    /// Returns the payback note routing tag, derived from the creator's account ID.
    pub fn payback_note_tag(&self) -> NoteTag {
        NoteTag::with_account_target(self.creator_account_id)
    }

    /// Number of times this note has been partially filled and re-created.
    pub fn swap_count(&self) -> u16 {
        self.swap_count
    }

    /// Returns the account ID of the note creator.
    pub fn creator_account_id(&self) -> AccountId {
        self.creator_account_id
    }

    /// Returns the [`NoteType`] used when creating the payback note.
    pub fn payback_note_type(&self) -> NoteType {
        self.payback_note_type
    }

    /// Returns the faucet ID of the requested asset.
    pub fn requested_faucet_id(&self) -> AccountId {
        self.requested_asset.faucet_id()
    }

    /// Returns the requested token amount.
    pub fn requested_asset_amount(&self) -> u64 {
        self.requested_asset.amount()
    }
}

/// Serializes [`PswapNoteStorage`] into a 10-element [`NoteStorage`].
impl From<PswapNoteStorage> for NoteStorage {
    fn from(storage: PswapNoteStorage) -> Self {
        let storage_items = vec![
            // Requested asset (individual felts) [0-3]
            Felt::from(storage.requested_asset.callbacks().as_u8()),
            storage.requested_asset.faucet_id().suffix(),
            storage.requested_asset.faucet_id().prefix().as_felt(),
            Felt::try_from(storage.requested_asset.amount())
                .expect("asset amount should fit in a felt"),
            // Tags [4-5]
            Felt::from(storage.pswap_tag),
            Felt::from(storage.payback_note_tag()),
            // Payback note type [6]
            Felt::from(storage.payback_note_type.as_u8()),
            // Swap count [7]
            Felt::from(storage.swap_count),
            // Creator ID [8-9]
            storage.creator_account_id.prefix().as_felt(),
            storage.creator_account_id.suffix(),
        ];
        NoteStorage::new(storage_items)
            .expect("number of storage items should not exceed max storage items")
    }
}

/// Deserializes [`PswapNoteStorage`] from a slice of exactly 10 [`Felt`]s.
impl TryFrom<&[Felt]> for PswapNoteStorage {
    type Error = NoteError;

    fn try_from(note_storage: &[Felt]) -> Result<Self, Self::Error> {
        if note_storage.len() != Self::NUM_STORAGE_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: Self::NUM_STORAGE_ITEMS,
                actual: note_storage.len(),
            });
        }

        // Reconstruct requested asset from individual felts:
        // [0] = enable_callbacks, [1] = faucet_id_suffix, [2] = faucet_id_prefix, [3] = amount
        let callbacks = AssetCallbackFlag::try_from(
            u8::try_from(note_storage[0].as_canonical_u64())
                .map_err(|_| NoteError::other("enable_callbacks exceeds u8"))?,
        )
        .map_err(|e| {
            NoteError::other_with_source("failed to parse asset callback flag", e)
        })?;

        let faucet_id =
            AccountId::try_from_elements(note_storage[1], note_storage[2]).map_err(|e| {
                NoteError::other_with_source("failed to parse requested faucet ID", e)
            })?;

        let amount = note_storage[3].as_canonical_u64();
        let requested_asset = FungibleAsset::new(faucet_id, amount)
            .map_err(|e| {
                NoteError::other_with_source("failed to create requested asset", e)
            })?
            .with_callbacks(callbacks);

        let pswap_tag = NoteTag::new(
            u32::try_from(note_storage[4].as_canonical_u64())
                .map_err(|_| NoteError::other("pswap_tag exceeds u32"))?,
        );

        let payback_note_type = NoteType::try_from(
            u8::try_from(note_storage[6].as_canonical_u64())
                .map_err(|_| NoteError::other("payback_note_type exceeds u8"))?,
        )
        .map_err(|e| NoteError::other_with_source("failed to parse payback note type", e))?;

        let swap_count: u16 = note_storage[7]
            .as_canonical_u64()
            .try_into()
            .map_err(|_| NoteError::other("swap_count exceeds u16"))?;

        let creator_account_id = AccountId::try_from_elements(note_storage[9], note_storage[8])
            .map_err(|e| {
            NoteError::other_with_source("failed to parse creator account ID", e)
        })?;

        Ok(Self {
            requested_asset,
            pswap_tag,
            swap_count,
            creator_account_id,
            payback_note_type,
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
///
/// The note can be consumed both in local transactions (where the consumer provides
/// fill amounts via note_args) and in network transactions (where note_args default to
/// `[0, 0, 0, 0]`, triggering a full fill). To route a PSWAP note to a network account,
/// set the `attachment` to a [`NetworkAccountTarget`](crate::note::NetworkAccountTarget)
/// via the builder.
#[derive(Debug, Clone, bon::Builder)]
#[builder(finish_fn(vis = "", name = build_internal))]
pub struct PswapNote {
    sender: AccountId,
    storage: PswapNoteStorage,
    serial_number: Word,

    #[builder(default = NoteType::Private)]
    note_type: NoteType,

    offered_asset: FungibleAsset,

    #[builder(default)]
    attachment: NoteAttachment,
}

impl<S: pswap_note_builder::State> PswapNoteBuilder<S>
where
    S: pswap_note_builder::IsComplete,
{
    /// Validates and builds the [`PswapNote`].
    ///
    /// # Errors
    ///
    /// Returns an error if the offered and requested assets have the same faucet ID.
    pub fn build(self) -> Result<PswapNote, NoteError> {
        let note = self.build_internal();

        if note.offered_asset.faucet_id() == note.storage.requested_faucet_id() {
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

    /// Returns the account ID of the note sender.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns a reference to the PSWAP note storage.
    pub fn storage(&self) -> &PswapNoteStorage {
        &self.storage
    }

    /// Returns the serial number of this note.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the note type (public or private).
    pub fn note_type(&self) -> NoteType {
        self.note_type
    }

    /// Returns a reference to the offered [`FungibleAsset`].
    pub fn offered_asset(&self) -> &FungibleAsset {
        &self.offered_asset
    }

    /// Returns a reference to the note attachment.
    ///
    /// For notes targeting a network account, this may contain a
    /// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) with scheme = 1.
    /// For local-only notes, this is typically `NoteAttachmentScheme::none()`.
    pub fn attachment(&self) -> &NoteAttachment {
        &self.attachment
    }

    // INSTANCE METHODS
    // --------------------------------------------------------------------------------------------

    /// Executes the swap as a full fill, intended for network transactions.
    ///
    /// In network transactions, note_args are unavailable (the kernel defaults them to
    /// `[0, 0, 0, 0]`), so the MASM script fills the entire requested amount. This method
    /// mirrors that behavior. Returns only the payback note — no remainder is produced.
    ///
    /// # Errors
    ///
    /// Returns an error if the swap count overflows `u16::MAX`.
    pub fn execute_full_fill_network(
        &self,
        network_account_id: AccountId,
    ) -> Result<Note, NoteError> {
        let requested_faucet_id = self.storage.requested_faucet_id();
        let total_requested_amount = self.storage.requested_asset_amount();

        let fill_asset = FungibleAsset::new(requested_faucet_id, total_requested_amount)
            .map_err(|e| NoteError::other_with_source("failed to create full fill asset", e))?;

        self.create_payback_note(network_account_id, fill_asset, total_requested_amount)
    }

    /// Executes the swap, producing the output notes for a given fill.
    ///
    /// `input_asset` is debited from the consumer's vault; `inflight_asset` arrives
    /// from another note in the same transaction (cross-swap). At least one must be
    /// provided.
    ///
    /// Returns `(payback_note, Option<remainder_pswap_note>)`. The remainder is
    /// `None` when the fill equals the total requested amount (full fill).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Both assets are `None`.
    /// - The fill amount is zero.
    /// - The fill amount exceeds the total requested amount.
    /// - The swap count overflows `u16::MAX`.
    pub fn execute(
        &self,
        consumer_account_id: AccountId,
        input_asset: Option<FungibleAsset>,
        inflight_asset: Option<FungibleAsset>,
    ) -> Result<(Note, Option<PswapNote>), NoteError> {
        // Combine input and inflight into a single payback asset
        let input_amount = input_asset.as_ref().map_or(0, |a| a.amount());
        let inflight_amount = inflight_asset.as_ref().map_or(0, |a| a.amount());
        let payback_asset = match (input_asset, inflight_asset) {
            (Some(input), Some(inflight)) => input.add(inflight).map_err(|e| {
                NoteError::other_with_source("failed to combine input and inflight assets", e)
            })?,
            (Some(asset), None) | (None, Some(asset)) => asset,
            (None, None) => {
                return Err(NoteError::other(
                    "at least one of input_asset or inflight_asset must be provided",
                ));
            },
        };
        let fill_amount = payback_asset.amount();

        let total_offered_amount = self.offered_asset.amount();
        let requested_faucet_id = self.storage.requested_faucet_id();
        let total_requested_amount = self.storage.requested_asset_amount();

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
        // which calls calculate_tokens_offered_for_requested twice. This is necessary
        // because the input portion goes to the consumer's vault while the total determines
        // the remainder note's offered amount.
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

        let payback_note =
            self.create_payback_note(consumer_account_id, payback_asset, fill_amount)?;

        // Create remainder note if partial fill
        let remainder = if fill_amount < total_requested_amount {
            let remaining_offered = total_offered_amount - offered_amount_for_fill;
            let remaining_requested = total_requested_amount - fill_amount;

            let remaining_offered_asset =
                FungibleAsset::new(self.offered_asset.faucet_id(), remaining_offered).map_err(
                    |e| NoteError::other_with_source("failed to create remainder asset", e),
                )?;

            let remaining_requested_asset =
                FungibleAsset::new(requested_faucet_id, remaining_requested).map_err(|e| {
                    NoteError::other_with_source("failed to create remaining requested asset", e)
                })?;

            Some(self.create_remainder_pswap_note(
                consumer_account_id,
                remaining_offered_asset,
                remaining_requested_asset,
                offered_amount_for_fill,
            )?)
        } else {
            None
        };

        Ok((payback_note, remainder))
    }

    /// Returns how many offered tokens a consumer receives for `input_amount` of the
    /// requested asset, based on this note's current offered/requested ratio.
    pub fn calculate_offered_for_requested(&self, input_amount: u64) -> u64 {
        let total_requested = self.storage.requested_asset_amount();
        let total_offered = self.offered_asset.amount();

        Self::calculate_output_amount(total_offered, total_requested, input_amount)
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
        offered_asset: &FungibleAsset,
        requested_asset: &FungibleAsset,
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
    ///
    /// The formula is implemented in two branches to maximize precision:
    /// - When `offered > requested`: the ratio `offered/requested` is >= 1, so we compute
    ///   `(offered * FACTOR / requested) * input / FACTOR` to avoid losing the fractional part.
    /// - When `requested >= offered`: the ratio `offered/requested` is < 1, so computing it
    ///   directly would truncate to zero. Instead we compute the inverse ratio
    ///   `(requested * FACTOR / offered)` and divide: `(input * FACTOR) / inverse_ratio`.
    fn calculate_output_amount(offered_total: u64, requested_total: u64, input_amount: u64) -> u64 {
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

    /// Builds a payback note (P2ID) that delivers the filled assets to the swap creator.
    ///
    /// The note inherits its type (public/private) from this PSWAP note and derives a
    /// deterministic serial number by incrementing the least significant element of the
    /// serial number (`serial[0] + 1`).
    ///
    /// The attachment carries the fill amount as auxiliary data with
    /// `NoteAttachmentScheme::none()`, matching the on-chain MASM behavior.
    fn create_payback_note(
        &self,
        consumer_account_id: AccountId,
        payback_asset: FungibleAsset,
        fill_amount: u64,
    ) -> Result<Note, NoteError> {
        let payback_note_tag = self.storage.payback_note_tag();
        // Derive P2ID serial: increment least significant element (matching MASM add.1)
        let p2id_serial_num = Word::from([
            self.serial_number[0] + ONE,
            self.serial_number[1],
            self.serial_number[2],
            self.serial_number[3],
        ]);

        // P2ID recipient targets the creator
        let recipient =
            P2idNoteStorage::new(self.storage.creator_account_id).into_recipient(p2id_serial_num);

        let attachment_word = Word::from([
            Felt::try_from(fill_amount).expect("fill amount should fit in a felt"),
            ZERO,
            ZERO,
            ZERO,
        ]);
        let attachment = NoteAttachment::new_word(NoteAttachmentScheme::none(), attachment_word);

        let p2id_assets = NoteAssets::new(vec![Asset::Fungible(payback_asset)])?;
        let p2id_metadata =
            NoteMetadata::new(consumer_account_id, self.storage.payback_note_type)
                .with_tag(payback_note_tag)
                .with_attachment(attachment);

        Ok(Note::new(p2id_assets, p2id_metadata, recipient))
    }

    /// Builds a remainder PSWAP note carrying the unfilled portion of the swap.
    ///
    /// The remainder inherits the original creator, tags, and note type, but has an
    /// incremented swap count and an updated serial number (`serial[3] + 1`).
    ///
    /// The attachment carries the total offered amount for the fill as auxiliary data
    /// with `NoteAttachmentScheme::none()`, matching the on-chain MASM behavior.
    fn create_remainder_pswap_note(
        &self,
        consumer_account_id: AccountId,
        remaining_offered_asset: FungibleAsset,
        remaining_requested_asset: FungibleAsset,
        offered_amount_for_fill: u64,
    ) -> Result<PswapNote, NoteError> {
        let next_swap_count = self
            .storage
            .swap_count
            .checked_add(1)
            .ok_or_else(|| NoteError::other("swap count overflow"))?;
        let new_storage = PswapNoteStorage::builder()
            .requested_asset(remaining_requested_asset)
            .pswap_tag(self.storage.pswap_tag)
            .swap_count(next_swap_count)
            .creator_account_id(self.storage.creator_account_id)
            .payback_note_type(self.storage.payback_note_type)
            .build();

        // Remainder serial: increment most significant element (matching MASM movup.3 add.1 movdn.3)
        let remainder_serial_num = Word::from([
            self.serial_number[0],
            self.serial_number[1],
            self.serial_number[2],
            self.serial_number[3] + ONE,
        ]);

        let attachment_word = Word::from([
            Felt::try_from(offered_amount_for_fill)
                .expect("offered amount for fill should fit in a felt"),
            ZERO,
            ZERO,
            ZERO,
        ]);
        let attachment = NoteAttachment::new_word(NoteAttachmentScheme::none(), attachment_word);

        Ok(PswapNote {
            sender: consumer_account_id,
            storage: new_storage,
            serial_number: remainder_serial_num,
            note_type: self.note_type,
            offered_asset: remaining_offered_asset,
            attachment,
        })
    }
}

// CONVERSIONS
// ================================================================================================

/// Converts a [`PswapNote`] into a protocol [`Note`], computing the final PSWAP tag.
impl From<PswapNote> for Note {
    fn from(pswap: PswapNote) -> Self {
        let tag = PswapNote::create_tag(
            pswap.note_type,
            &pswap.offered_asset,
            pswap.storage.requested_asset(),
        );

        let storage = pswap.storage.with_pswap_tag(tag);
        let recipient = storage.into_recipient(pswap.serial_number);

        let assets = NoteAssets::new(vec![Asset::Fungible(pswap.offered_asset)])
            .expect("single fungible asset should be valid");

        let metadata = NoteMetadata::new(pswap.sender, pswap.note_type)
            .with_tag(tag)
            .with_attachment(pswap.attachment);

        Note::new(assets, metadata, recipient)
    }
}

/// Parses a protocol [`Note`] back into a [`PswapNote`] by deserializing its storage.
impl TryFrom<&Note> for PswapNote {
    type Error = NoteError;

    fn try_from(note: &Note) -> Result<Self, Self::Error> {
        if note.recipient().script().root() != PswapNote::script_root() {
            return Err(NoteError::other("note script root does not match PSWAP script root"));
        }

        let storage = PswapNoteStorage::try_from(note.recipient().storage().items())?;

        if note.assets().num_assets() != 1 {
            return Err(NoteError::other("PSWAP note must have exactly one asset"));
        }
        let offered_asset = match note.assets().iter().next().unwrap() {
            Asset::Fungible(fa) => *fa,
            Asset::NonFungible(_) => {
                return Err(NoteError::other("PSWAP note asset must be fungible"));
            },
        };

        Ok(Self {
            sender: note.metadata().sender(),
            storage,
            serial_number: note.recipient().serial_num(),
            note_type: note.metadata().note_type(),
            offered_asset,
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
    use miden_protocol::crypto::rand::{FeltRng, RandomCoin};

    use super::*;

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    fn dummy_faucet_id(byte: u8) -> AccountId {
        let mut bytes = [0; 15];
        bytes[0] = byte;
        AccountId::dummy(
            bytes,
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        )
    }

    fn dummy_creator_id() -> AccountId {
        AccountId::dummy(
            [1; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Public,
        )
    }

    fn build_pswap_note(
        offered_asset: FungibleAsset,
        requested_asset: FungibleAsset,
        creator_id: AccountId,
    ) -> (PswapNote, Note) {
        let mut rng = RandomCoin::new(Word::default());
        let storage = PswapNoteStorage::builder()
            .requested_asset(requested_asset)
            .creator_account_id(creator_id)
            .build();
        let pswap = PswapNote::builder()
            .sender(creator_id)
            .storage(storage)
            .serial_number(rng.draw_word())
            .note_type(NoteType::Public)
            .offered_asset(offered_asset)
            .build()
            .unwrap();
        let note: Note = pswap.clone().into();
        (pswap, note)
    }

    // TESTS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn pswap_note_creation_and_script() {
        let creator_id = dummy_creator_id();
        let offered_asset = FungibleAsset::new(dummy_faucet_id(0xaa), 1000).unwrap();
        let requested_asset = FungibleAsset::new(dummy_faucet_id(0xbb), 500).unwrap();

        let (pswap, note) = build_pswap_note(offered_asset, requested_asset, creator_id);

        assert_eq!(pswap.sender(), creator_id);
        assert_eq!(pswap.note_type(), NoteType::Public);

        let script = PswapNote::script();
        assert!(script.root() != Word::default(), "Script root should not be zero");
        assert_eq!(note.metadata().sender(), creator_id);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.recipient().script().root(), script.root());
        assert_eq!(
            note.recipient().storage().num_items(),
            PswapNoteStorage::NUM_STORAGE_ITEMS as u16,
        );
    }

    #[test]
    fn pswap_note_builder() {
        let creator_id = dummy_creator_id();
        let offered_asset = FungibleAsset::new(dummy_faucet_id(0xaa), 1000).unwrap();
        let requested_asset = FungibleAsset::new(dummy_faucet_id(0xbb), 500).unwrap();

        let (pswap, note) = build_pswap_note(offered_asset, requested_asset, creator_id);

        assert_eq!(pswap.sender(), creator_id);
        assert_eq!(pswap.note_type(), NoteType::Public);
        assert_eq!(note.metadata().sender(), creator_id);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(
            note.recipient().storage().num_items(),
            PswapNoteStorage::NUM_STORAGE_ITEMS as u16,
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

        let offered_asset = FungibleAsset::new(
            AccountId::dummy(
                offered_faucet_bytes,
                AccountIdVersion::Version0,
                AccountType::FungibleFaucet,
                AccountStorageMode::Public,
            ),
            100,
        )
        .unwrap();
        let requested_asset = FungibleAsset::new(
            AccountId::dummy(
                requested_faucet_bytes,
                AccountIdVersion::Version0,
                AccountType::FungibleFaucet,
                AccountStorageMode::Public,
            ),
            200,
        )
        .unwrap();

        let tag = PswapNote::create_tag(NoteType::Public, &offered_asset, &requested_asset);
        let tag_u32 = u32::from(tag);

        // Verify note_type bits (top 2 bits should be 10 for Public)
        let note_type_bits = tag_u32 >> 30;
        assert_eq!(note_type_bits, NoteType::Public as u32);
    }

    #[test]
    fn calculate_output_amount() {
        assert_eq!(PswapNote::calculate_output_amount(100, 100, 50), 50); // Equal ratio
        assert_eq!(PswapNote::calculate_output_amount(200, 100, 50), 100); // 2:1 ratio
        assert_eq!(PswapNote::calculate_output_amount(100, 200, 50), 25); // 1:2 ratio

        // Non-integer ratio (100/73)
        let result = PswapNote::calculate_output_amount(100, 73, 7);
        assert!(result > 0, "Should produce non-zero output");
    }

    #[test]
    fn pswap_note_storage_try_from() {
        let creator_id = dummy_creator_id();
        let requested_asset = FungibleAsset::new(dummy_faucet_id(0xaa), 500).unwrap();

        let storage_items = vec![
            Felt::from(requested_asset.callbacks().as_u8()),
            requested_asset.faucet_id().suffix(),
            requested_asset.faucet_id().prefix().as_felt(),
            Felt::try_from(requested_asset.amount()).unwrap(),
            Felt::from(0xc0000000u32), // pswap_tag
            Felt::from(0x80000001u32), // payback_note_tag
            Felt::from(NoteType::Private.as_u8()), // payback_note_type
            Felt::from(3u16), // swap_count
            creator_id.prefix().as_felt(),
            creator_id.suffix(),
        ];

        let parsed = PswapNoteStorage::try_from(storage_items.as_slice()).unwrap();
        assert_eq!(parsed.swap_count(), 3);
        assert_eq!(parsed.creator_account_id(), creator_id);
        assert_eq!(parsed.requested_asset_amount(), 500);
    }

    #[test]
    fn pswap_note_storage_roundtrip() {
        let creator_id = dummy_creator_id();
        let requested_asset = FungibleAsset::new(dummy_faucet_id(0xaa), 500).unwrap();

        let storage = PswapNoteStorage::builder()
            .requested_asset(requested_asset)
            .creator_account_id(creator_id)
            .build();

        let note_storage = NoteStorage::from(storage.clone());
        let parsed = PswapNoteStorage::try_from(note_storage.items()).unwrap();

        assert_eq!(parsed.creator_account_id(), creator_id);
        assert_eq!(parsed.swap_count(), 0);
        assert_eq!(parsed.requested_asset_amount(), 500);
    }
}
