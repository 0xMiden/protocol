use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentScheme,
    NoteAttachments,
    NoteRecipient,
    NoteScript,
    NoteScriptRoot,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNote,
    PartialNoteMetadata,
};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Hasher, ONE, Word, ZERO};

use crate::StandardsLib;
use crate::note::costs::{NoteConsumptionCost, PSWAP_CONSUMPTION_CYCLES};
use crate::note::{P2idNote, P2idNoteStorage, StandardNoteAttachment};

// NOTE SCRIPT
// ================================================================================================

/// Path to the PSWAP note script procedure in the standards library.
const PSWAP_SCRIPT_PATH: &str = "::miden::standards::notes::pswap::main";

// Initialize the PSWAP note script only once
static PSWAP_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(PSWAP_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains PSWAP note script procedure")
});

// PSWAP NOTE STORAGE
// ================================================================================================

/// Fixed P2ID payback configuration for an entire PSWAP order.
///
/// Private paybacks disclose only a recipient digest. The owner must retain its opening separately.
/// Public paybacks disclose the independent payback serial and canonical P2ID storage.
/// Sample a fresh payback serial for each independent order, separately from the PSWAP serial.
/// Reuse this configuration only within that order's remainder chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PswapPayback {
    Private {
        recipient: Word,
    },
    Public {
        serial_number: Word,
        storage: P2idNoteStorage,
    },
}

impl PswapPayback {
    /// Returns the visibility of every payback in this order.
    pub fn note_type(&self) -> NoteType {
        match self {
            Self::Private { .. } => NoteType::Private,
            Self::Public { .. } => NoteType::Public,
        }
    }

    /// Returns the fixed recipient digest used for every fill and for cancellation verification.
    pub fn recipient_digest(&self) -> Word {
        match self {
            Self::Private { recipient } => *recipient,
            Self::Public { serial_number, storage } => {
                storage.into_recipient(*serial_number).digest()
            },
        }
    }
}

/// Canonical storage for a PSWAP note, selected by payback visibility:
///
/// | Offset | Private payback | Public payback |
/// |--------|-----------------|----------------|
/// | 0..3 | Requested faucet suffix, prefix, amount | Same |
/// | 3 | Minimum fill step | Same |
/// | 4..8 | Complete payback recipient digest | Payback serial |
/// | 8 | Private note type | Public note type |
/// | 9 | Payback discovery tag | Same |
/// | 10..14 | Absent | Target suffix, prefix, salt[0], salt[1] |
///
/// PSWAP visibility is independent of payback visibility. Every remainder preserves the payback
/// configuration. The PSWAP's own discovery tag lives in its metadata.
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct PswapNoteStorage {
    min_requested_asset: FungibleAsset,
    payback: PswapPayback,

    /// Explicit payback discovery tag. Avoid account-derived tags when target privacy is required.
    payback_note_tag: NoteTag,

    /// Minimum amount of the requested asset a single fill may deliver, denominated in the
    /// requested asset and checked against `total_fill = account_fill + note_fill`. Prevents
    /// griefing a swap with tiny partial fills that mint dust payback notes.
    ///
    /// Defaults to [`AssetAmount::ZERO`], which disables the floor. The on-chain script clamps the
    /// effective floor to `min(min_fill_step, min_requested_amount)`, so a remainder note whose
    /// requested amount has shrunk below `min_fill_step` can still be filled in full rather than
    /// becoming stuck. Any higher-level default (e.g. a percentage of the offered amount) is a
    /// wallet-layer concern and is intentionally not baked in here.
    ///
    /// Typed as [`AssetAmount`] so the value is validated (`<= AssetAmount::MAX`) by construction,
    /// making serialization to a [`Felt`] infallible.
    #[builder(default = AssetAmount::ZERO)]
    min_fill_step: AssetAmount,
}

impl PswapNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Exact storage length for orders producing private paybacks.
    pub const PRIVATE_NUM_STORAGE_ITEMS: usize = 10;
    /// Exact storage length for orders producing public paybacks.
    pub const PUBLIC_NUM_STORAGE_ITEMS: usize = 10 + P2idNoteStorage::NUM_ITEMS;

    /// Consumes the storage and returns a PSWAP [`NoteRecipient`] with the provided serial number.
    pub fn into_recipient(self, serial_num: Word) -> NoteRecipient {
        NoteRecipient::new(serial_num, PswapNote::script(), NoteStorage::from(self))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the requested [`FungibleAsset`].
    pub fn min_requested_asset(&self) -> &FungibleAsset {
        &self.min_requested_asset
    }

    /// Returns the fixed payback configuration for this order.
    pub fn payback(&self) -> &PswapPayback {
        &self.payback
    }

    /// Returns the explicit discovery tag used by every payback.
    pub fn payback_note_tag(&self) -> NoteTag {
        self.payback_note_tag
    }

    /// Returns the [`NoteType`] used when creating the payback note.
    pub fn payback_note_type(&self) -> NoteType {
        self.payback.note_type()
    }

    /// Returns the faucet ID of the requested asset.
    pub fn requested_faucet_id(&self) -> AccountId {
        self.min_requested_asset.faucet_id()
    }

    /// Returns the requested token amount.
    pub fn min_requested_amount(&self) -> u64 {
        self.min_requested_asset.amount().as_u64()
    }

    /// Returns the minimum fill step ([`AssetAmount::ZERO`] if no floor is enforced).
    pub fn min_fill_step(&self) -> AssetAmount {
        self.min_fill_step
    }
}

impl From<PswapNoteStorage> for NoteStorage {
    fn from(storage: PswapNoteStorage) -> Self {
        let mut items = vec![
            storage.min_requested_asset.faucet_id().suffix(),
            storage.min_requested_asset.faucet_id().prefix().as_felt(),
            Felt::from(storage.min_requested_asset.amount()),
            Felt::from(storage.min_fill_step),
        ];
        let payback_word = match storage.payback {
            PswapPayback::Private { recipient } => recipient,
            PswapPayback::Public { serial_number, .. } => serial_number,
        };
        items.extend_from_slice(payback_word.as_elements());
        items.push(Felt::from(storage.payback_note_type().as_u8()));
        items.push(Felt::from(storage.payback_note_tag));
        if let PswapPayback::Public { storage, .. } = storage.payback {
            items.extend_from_slice(NoteStorage::from(storage).items());
        }
        NoteStorage::new(items).expect("PSWAP storage fits within the storage limit")
    }
}

impl TryFrom<&[Felt]> for PswapNoteStorage {
    type Error = NoteError;

    fn try_from(items: &[Felt]) -> Result<Self, Self::Error> {
        if items.len() < Self::PRIVATE_NUM_STORAGE_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: Self::PRIVATE_NUM_STORAGE_ITEMS,
                actual: items.len(),
            });
        }

        let note_type = NoteType::try_from(
            u8::try_from(items[8].as_canonical_u64())
                .map_err(|_| NoteError::other("payback note type exceeds u8"))?,
        )?;
        let expected = match note_type {
            NoteType::Private => Self::PRIVATE_NUM_STORAGE_ITEMS,
            NoteType::Public => Self::PUBLIC_NUM_STORAGE_ITEMS,
        };
        if items.len() != expected {
            return Err(NoteError::InvalidNoteStorageLength { expected, actual: items.len() });
        }

        let faucet_id = AccountId::try_from_elements(items[0], items[1])
            .map_err(|e| NoteError::other_with_source("invalid requested faucet ID", e))?;
        let min_requested_asset = FungibleAsset::new(faucet_id, items[2].as_canonical_u64())
            .map_err(|e| NoteError::other_with_source("invalid requested asset", e))?;
        let min_fill_step = AssetAmount::new(items[3].as_canonical_u64())
            .map_err(|e| NoteError::other_with_source("invalid minimum fill step", e))?;
        let payback_word = Word::new(items[4..8].try_into().expect("length already checked"));
        let payback = match note_type {
            NoteType::Private => PswapPayback::Private { recipient: payback_word },
            NoteType::Public => PswapPayback::Public {
                serial_number: payback_word,
                storage: P2idNoteStorage::try_from(&items[10..])?,
            },
        };
        let payback_note_tag = NoteTag::new(
            u32::try_from(items[9].as_canonical_u64())
                .map_err(|_| NoteError::other("payback tag exceeds u32"))?,
        );
        Ok(Self {
            min_requested_asset,
            payback,
            payback_note_tag,
            min_fill_step,
        })
    }
}

// PSWAP NOTE ATTACHMENT
// ================================================================================================

/// Typed attachment carried by both PSWAP output notes, encoded as
/// `[amount, order_id, depth, 0]` under [`PswapNote::PSWAP_ATTACHMENT_SCHEME`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PswapNoteAttachment {
    amount: AssetAmount,
    order_id: Felt,
    depth: u32,
}

impl PswapNoteAttachment {
    /// Creates a new [`PswapNoteAttachment`].
    pub fn new(amount: AssetAmount, order_id: Felt, depth: u32) -> Self {
        Self { amount, order_id, depth }
    }

    pub fn amount(&self) -> AssetAmount {
        self.amount
    }

    pub fn order_id(&self) -> Felt {
        self.order_id
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }
}

impl From<PswapNoteAttachment> for NoteAttachment {
    fn from(attachment: PswapNoteAttachment) -> Self {
        let word = Word::from([
            Felt::from(attachment.amount),
            attachment.order_id,
            Felt::from(attachment.depth),
            ZERO,
        ]);
        NoteAttachment::with_word(PswapNote::PSWAP_ATTACHMENT_SCHEME, word)
    }
}

/// Parses a [`NoteAttachment`] carrying [`PswapNote::PSWAP_ATTACHMENT_SCHEME`] into its typed
/// form.
impl TryFrom<&NoteAttachment> for PswapNoteAttachment {
    type Error = NoteError;

    fn try_from(attachment: &NoteAttachment) -> Result<Self, Self::Error> {
        if attachment.attachment_scheme() != PswapNote::PSWAP_ATTACHMENT_SCHEME {
            return Err(NoteError::other("attachment scheme is not the PSWAP attachment scheme"));
        }

        let [word] = attachment.content().as_words() else {
            return Err(NoteError::other("PSWAP attachment must carry exactly one word"));
        };

        let amount = AssetAmount::new(word[0].as_canonical_u64())
            .map_err(|e| NoteError::other_with_source("invalid PSWAP attachment amount", e))?;
        let order_id = word[1];
        let depth =
            u32::try_from(word[PswapNote::PARENT_ATTACHMENT_DEPTH_OFFSET].as_canonical_u64())
                .map_err(|_| NoteError::other("PSWAP depth does not fit in u32"))?;

        if word[3] != ZERO {
            return Err(NoteError::other("PSWAP attachment must be zero-padded"));
        }

        Ok(Self::new(amount, order_id, depth))
    }
}

// PSWAP NOTE
// ================================================================================================

/// A partially-fillable swap note for decentralized asset exchange.
///
/// A PSWAP note allows a creator to offer one fungible asset in exchange for another.
/// Unlike a regular SWAP note, consumers may fill it partially — the unfilled portion
/// is re-created as a remainder note with an updated serial number. Every fill sends a P2ID
/// payback to the order's fixed recipient, which may target a different account from the creator.
/// Only that P2ID target can cancel, using [`Self::create_cancel_args`] and
/// [`Self::cancellation_advice`].
///
/// # Private paybacks
///
/// The owner must retain the payback [`NoteRecipient`] to reconstruct outputs with
/// [`Self::payback_note`]. Use an independent random serial and a discovery tag that does not
/// encode the target account. Consume reconstructed private paybacks with inclusion proofs;
/// unauthenticated consumption exposes their headers and links them to the consuming account.
/// Cancellation links the target account to the order. This design does not hide private data
/// from parties given the full transaction witness, including remote provers.
///
/// The note can be consumed both in local transactions (where the consumer provides
/// fill amounts via note_args) and in network transactions (where note_args default to
/// `[0, 0, 0, 0]`, triggering a full fill). To route a PSWAP note to a network account,
/// set the `attachment` to a [`NetworkAccountTarget`](crate::note::NetworkAccountTarget)
/// via the builder.
///
/// Fills are priced against the note's initial offered asset.
#[derive(Debug, Clone, bon::Builder)]
#[builder(finish_fn(vis = "", name = build_internal))]
pub struct PswapNote {
    sender: AccountId,
    storage: PswapNoteStorage,
    serial_number: Word,

    #[builder(default = NoteType::Private)]
    note_type: NoteType,

    offered_asset: FungibleAsset,

    attachment: Option<NoteAttachment>,
}

impl<S: pswap_note_builder::State> PswapNoteBuilder<S>
where
    S: pswap_note_builder::IsComplete,
{
    /// Validates and builds the [`PswapNote`].
    ///
    /// # Errors
    ///
    /// Returns an error if the offered and requested assets have the same faucet ID, or if the
    /// note carries a malformed [`PswapNote::PSWAP_ATTACHMENT_SCHEME`] attachment.
    pub fn build(self) -> Result<PswapNote, NoteError> {
        let note = self.build_internal();

        if note.offered_asset.faucet_id() == note.storage.requested_faucet_id() {
            return Err(NoteError::other(
                "offered and requested assets must have different faucets",
            ));
        }

        if let Some(attachment) = note.attachment.as_ref()
            && attachment.attachment_scheme() == PswapNote::PSWAP_ATTACHMENT_SCHEME
        {
            PswapNoteAttachment::try_from(attachment)?;
        }

        Ok(note)
    }
}

impl PswapNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Domain separator for cancellation advice; ASCII "PSWAPCAN".
    const CANCEL_ADVICE_DOMAIN: Word =
        Word::new([Felt::new_unchecked(0x505357415043414e), ZERO, ZERO, ZERO]);

    /// Attachment scheme stamped on both PSWAP output notes (the payback P2ID and the
    /// remainder PSWAP).
    pub const PSWAP_ATTACHMENT_SCHEME: NoteAttachmentScheme =
        StandardNoteAttachment::PswapAttachment.attachment_scheme();

    /// Offset of the `depth` field within the [`Self::PSWAP_ATTACHMENT_SCHEME`] word.
    const PARENT_ATTACHMENT_DEPTH_OFFSET: usize = 2;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the compiled PSWAP note script.
    pub fn script() -> NoteScript {
        PSWAP_SCRIPT.clone()
    }

    /// Returns the root hash of the PSWAP note script.
    pub fn script_root() -> NoteScriptRoot {
        PSWAP_SCRIPT.root()
    }

    /// Builds the `NOTE_ARGS` word that the PSWAP script expects when a
    /// consumer wants to fill part of the swap:
    ///
    /// `[account_fill, note_fill, 0, 0]`
    ///
    /// - `account_fill` is the portion of the requested asset the consumer pays out of their own
    ///   vault.
    /// - `note_fill` is the portion sourced from another note in the same transaction (cross-swap /
    ///   net-zero flow).
    ///
    /// Both values are in the requested asset's base units. In a network
    /// transaction the kernel defaults `NOTE_ARGS` to `[0, 0, 0, 0]` and the
    /// script falls back to a full fill, so this helper is only needed for
    /// local transactions where the consumer is choosing the fill split.
    ///
    /// # Errors
    ///
    /// Returns an error if either value exceeds the Goldilocks field size
    /// (i.e. cannot be represented as a [`Felt`]). In practice this cannot
    /// happen for any amount that fits in a [`FungibleAsset`] —
    /// `FungibleAsset::MAX_AMOUNT` is comfortably below `2^63` — but the
    /// conversion is surfaced explicitly rather than hidden behind a panic.
    pub fn create_args(account_fill: u64, note_fill: u64) -> Result<Word, NoteError> {
        let account_fill = Felt::try_from(account_fill)
            .map_err(|e| NoteError::other_with_source("account_fill is not a valid felt", e))?;
        let note_fill = Felt::try_from(note_fill)
            .map_err(|e| NoteError::other_with_source("note_fill is not a valid felt", e))?;
        Ok(Word::from([account_fill, note_fill, ZERO, ZERO]))
    }

    /// Selects cancellation explicitly. Zero arguments always select a full fill.
    pub fn create_cancel_args() -> Word {
        Word::new([ZERO, ZERO, ONE, ZERO])
    }

    /// Returns a domain-separated advice entry containing the four-element payback serial,
    /// followed by the two salt elements only when the salt is nonzero. Supply it when consuming
    /// the PSWAP with [`Self::create_cancel_args`].
    ///
    /// The opening is verified here and again on chain. Cancellation additionally requires the
    /// authenticated executing account to be the P2ID target; knowledge of this advice is not
    /// authorization. Do not publish the opening of a private payback.
    pub fn cancellation_advice(
        &self,
        recipient: &NoteRecipient,
    ) -> Result<(Word, Vec<Felt>), NoteError> {
        let storage = self.validate_payback_recipient(recipient)?;
        let key = Hasher::merge(&[recipient.digest(), Self::CANCEL_ADVICE_DOMAIN]);
        let mut values = recipient.serial_num().as_elements().to_vec();
        if storage.salt() != [ZERO; 2] {
            values.extend_from_slice(&storage.salt());
        }
        Ok((key, values))
    }

    fn validate_payback_recipient(
        &self,
        recipient: &NoteRecipient,
    ) -> Result<P2idNoteStorage, NoteError> {
        if recipient.script().root() != P2idNote::script_root() {
            return Err(NoteError::other("payback recipient must use the P2ID script"));
        }
        let storage = P2idNoteStorage::try_from(recipient.storage().items())?;
        if recipient.digest() != self.storage.payback.recipient_digest() {
            return Err(NoteError::other("payback recipient does not match the order"));
        }
        Ok(storage)
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

    /// Returns a reference to the note attachments.
    ///
    /// For notes targeting a network account, this may contain a
    /// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) with scheme = 2. For a
    /// remainder PSWAP this contains the [`Self::PSWAP_ATTACHMENT_SCHEME`] word
    /// `[amt_payout, order_id, depth, 0]`. For an original PSWAP (no prior fill),
    /// this is typically empty.
    pub fn attachments(&self) -> Option<&NoteAttachment> {
        self.attachment.as_ref()
    }

    /// Returns the order_id of this lineage, equal to `serial_number()[1]`.
    pub fn order_id(&self) -> Felt {
        self.serial_number[1]
    }

    /// Returns the depth carried in this note's [`Self::PSWAP_ATTACHMENT_SCHEME`] attachment,
    /// or 0 if the note has no such attachment (i.e., it is the original PSWAP, not a
    /// remainder produced by an earlier fill).
    ///
    /// The next round's `current_depth` is computed as `parent_depth() + 1`, matching the
    /// on-chain `get_current_depth` MASM procedure.
    pub fn parent_depth(&self) -> u32 {
        self.attachment
            .as_ref()
            .and_then(|attachment| PswapNoteAttachment::try_from(attachment).ok())
            .map_or(0, |attachment| attachment.depth())
    }

    // INSTANCE METHODS
    // --------------------------------------------------------------------------------------------

    /// Executes the swap as a full fill, producing only the payback note (no remainder).
    ///
    /// Equivalent to calling [`Self::execute`] with `account_fill_asset` set to the full
    /// requested amount and `note_fill_asset = None`. It also matches the on-chain
    /// behavior when a note is consumed without explicit `note_args` (e.g. in a network
    /// transaction, where the kernel defaults `note_args` to `[0, 0, 0, 0]` and the MASM
    /// script falls back to a full fill).
    pub fn execute_full_fill(
        &self,
        consumer_account_id: AccountId,
    ) -> Result<RawOutputNote, NoteError> {
        self.create_payback_note(consumer_account_id, self.storage.min_requested_asset)
    }

    /// Executes the swap, producing the output notes for a given fill.
    ///
    /// `account_fill_asset` is debited from the consumer's vault; `note_fill_asset` arrives
    /// from another note in the same transaction (cross-swap). At least one must be
    /// provided.
    ///
    /// Returns `(payback_note, Option<remainder_pswap_note>)`. The remainder is
    /// `None` when the fill is at least `min_requested_amount` (full fill or over-fill).
    /// The payback is [`RawOutputNote::Partial`] for private outputs and [`RawOutputNote::Full`]
    /// for public outputs. Private fill simulation does not require the recipient opening.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Both assets are `None`.
    /// - The fill amount is zero.
    /// - The combined fill amount overflows or exceeds the maximum fungible asset amount.
    pub fn execute(
        &self,
        consumer_account_id: AccountId,
        account_fill_asset: Option<FungibleAsset>,
        note_fill_asset: Option<FungibleAsset>,
    ) -> Result<(RawOutputNote, Option<PswapNote>), NoteError> {
        // Combine account fill and note fill into a single payback asset.
        let payback_asset = match (account_fill_asset, note_fill_asset) {
            (Some(account_fill), Some(note_fill)) => account_fill.add(note_fill).map_err(|e| {
                NoteError::other_with_source(
                    "failed to combine account fill and note fill assets",
                    e,
                )
            })?,
            (Some(asset), None) | (None, Some(asset)) => asset,
            (None, None) => {
                return Err(NoteError::other(
                    "at least one of account_fill_asset or note_fill_asset must be provided",
                ));
            },
        };
        let fill_amount = payback_asset.amount().as_u64();

        let total_offered_amount = self.offered_asset.amount().as_u64();
        let requested_faucet_id = self.storage.requested_faucet_id();
        let min_requested_amount = self.storage.min_requested_amount();

        // Validate fill amount
        if fill_amount == 0 {
            return Err(NoteError::other("Fill amount must be greater than 0"));
        }

        let account_fill_amount = account_fill_asset.as_ref().map_or(0, |a| a.amount().as_u64());
        let note_fill_amount = note_fill_asset.as_ref().map_or(0, |a| a.amount().as_u64());

        // Enforce the per-fill floor, mirroring the MASM `execute_pswap` guard. The effective floor
        // is clamped to `min(min_fill_step, min_requested_amount)` so a remainder whose requested
        // amount has shrunk below `min_fill_step` stays fillable in full. `min_fill_step == 0`
        // disables the floor.
        let effective_floor = self.storage.min_fill_step().as_u64().min(min_requested_amount);
        if fill_amount < effective_floor {
            return Err(NoteError::other("PSWAP fill amount is below the minimum fill step"));
        }

        // `min_requested_amount` is a floor, not an exact target: each fill's share is computed
        // against `fill_reference = max(fill_amount, min_requested_amount)`. At or below the
        // minimum this is `min_requested_amount` (proportional, leaving a remainder); for an
        // over-fill it is the fill itself, so the whole offered side is paid out and no remainder
        // is created.
        let fill_reference = fill_amount.max(min_requested_amount);

        // Calculate payout amounts separately for account fill and note fill, matching the MASM
        // which calls calculate_output_amount twice: the account fill portion is credited to the
        // consumer's vault while the total determines the remainder note's offered amount.
        let payout_for_account_fill = Self::calculate_output_amount(
            total_offered_amount,
            fill_reference,
            account_fill_amount,
        )?;
        let payout_for_note_fill =
            Self::calculate_output_amount(total_offered_amount, fill_reference, note_fill_amount)?;
        let offered_amount_for_fill = payout_for_account_fill + payout_for_note_fill;

        let payback_note = self.create_payback_note(consumer_account_id, payback_asset)?;

        // Create remainder note if partial fill
        let remainder = if fill_amount < min_requested_amount {
            let remaining_offered = total_offered_amount - offered_amount_for_fill;
            let remaining_requested = min_requested_amount - fill_amount;

            let remaining_offered_asset =
                FungibleAsset::new(self.offered_asset.faucet_id(), remaining_offered).map_err(
                    |e| NoteError::other_with_source("failed to create remainder asset", e),
                )?;

            let remaining_min_requested_asset =
                FungibleAsset::new(requested_faucet_id, remaining_requested).map_err(|e| {
                    NoteError::other_with_source("failed to create remaining requested asset", e)
                })?;

            Some(self.create_remainder_pswap_note(
                consumer_account_id,
                remaining_offered_asset,
                remaining_min_requested_asset,
                offered_amount_for_fill,
            )?)
        } else {
            None
        };

        Ok((payback_note, remainder))
    }

    /// Returns how many offered tokens a consumer receives for `fill_amount` of the
    /// requested asset, based on this note's current offered/requested ratio.
    ///
    /// `min_requested_amount` is a floor, not an exact price: a `fill_amount` at or above it
    /// returns the entire offered amount. (The divisor is `max(fill_amount, min_requested)`, so
    /// the payout ratio never exceeds 1 — see [`Self::execute`].)
    ///
    /// # Errors
    ///
    /// Returns an error if the calculated payout is not a valid asset amount.
    pub fn calculate_offered_for_requested(&self, fill_amount: u64) -> Result<u64, NoteError> {
        let min_requested = self.storage.min_requested_amount();
        let total_offered = self.offered_asset.amount().as_u64();

        let fill_reference = fill_amount.max(min_requested);
        Self::calculate_output_amount(total_offered, fill_reference, fill_amount)
    }

    // LINEAGE DISCOVERY
    // --------------------------------------------------------------------------------------------

    /// Returns the number of fill rounds between this note and the round `attachment` was
    /// stamped in.
    ///
    /// # Errors
    ///
    /// Returns an error if the attachment was not stamped in a round after this note.
    fn rounds_since(&self, attachment: &PswapNoteAttachment) -> Result<u32, NoteError> {
        if attachment.order_id() != self.order_id() {
            return Err(NoteError::other("attachment order ID does not match this order"));
        }
        attachment
            .depth()
            .checked_sub(self.parent_depth())
            .filter(|rounds| *rounds > 0)
            .ok_or_else(|| {
                NoteError::other("attachment depth must be greater than this note's depth")
            })
    }

    /// Reconstructs a payback from the owner's retained recipient opening and a fill attachment.
    ///
    /// The sender is the account that filled the order. Verify the reconstructed note ID against
    /// the observed output, obtain its inclusion proof, and consume it as an authenticated input
    /// to avoid linking the private payback to the consuming account.
    ///
    /// Returns an error for an incorrect recipient, order ID, or attachment depth.
    pub fn payback_note(
        &self,
        consumer_account_id: AccountId,
        attachment: &PswapNoteAttachment,
        recipient: &NoteRecipient,
    ) -> Result<Note, NoteError> {
        self.rounds_since(attachment)?;
        self.validate_payback_recipient(recipient)?;

        let fill_asset =
            FungibleAsset::new(self.storage.requested_faucet_id(), u64::from(attachment.amount()))
                .map_err(|e| NoteError::other_with_source("invalid fill amount", e))?;
        let assets = NoteAssets::new(vec![fill_asset.into()])?;

        let metadata =
            PartialNoteMetadata::new(consumer_account_id, self.storage.payback_note_type())
                .with_tag(self.storage.payback_note_tag());

        Ok(Note::with_attachments(
            assets,
            metadata,
            recipient.clone(),
            NoteAttachments::from(NoteAttachment::from(*attachment)),
        ))
    }

    /// Reconstructs the depth-`d` remainder PSWAP [`Note`] in this lineage.
    ///
    /// Called on the original PSWAP, this returns the full Note for the remainder produced
    /// in round `depth`. The returned Note matches the created note exactly.
    ///
    /// - `consumer_account_id` — the account that consumed the parent PSWAP in round `depth`, used
    ///   as the remainder's sender.
    /// - `attachment` — the on-chain `[amount, order_id, depth, 0]` attachment for this round,
    ///   where `amount` is the offered-asset units paid out.
    /// - `remaining_offered` / `remaining_requested` — the leftover amounts that survive into this
    ///   remainder. Both are required because the price formula uses floor division, so one isn't
    ///   derivable from the other across rounds in general.
    ///
    /// # Errors
    ///
    /// Returns an error if `attachment` was not stamped in a round after this note, or if any
    /// amount is not a valid asset amount.
    pub fn remainder_note(
        &self,
        consumer_account_id: AccountId,
        attachment: &PswapNoteAttachment,
        remaining_offered: AssetAmount,
        remaining_requested: AssetAmount,
    ) -> Result<Note, NoteError> {
        // Every round bumps the remainder's serial once, so the offset is the round distance.
        let rounds = self.rounds_since(attachment)?;
        let remainder_serial = Word::from([
            self.serial_number[0],
            self.serial_number[1],
            self.serial_number[2],
            self.serial_number[3] + Felt::from(rounds),
        ]);

        let min_requested_asset =
            FungibleAsset::new(self.storage.requested_faucet_id(), u64::from(remaining_requested))
                .map_err(|e| {
                    NoteError::other_with_source("invalid remaining_requested amount", e)
                })?;
        let offered_asset =
            FungibleAsset::new(self.offered_asset.faucet_id(), u64::from(remaining_offered))
                .map_err(|e| NoteError::other_with_source("invalid remaining_offered amount", e))?;

        let new_storage = PswapNoteStorage {
            min_requested_asset,
            ..self.storage.clone()
        };
        let recipient = new_storage.into_recipient(remainder_serial);

        let assets = NoteAssets::new(vec![offered_asset.into()])?;

        let tag = Self::create_tag(self.note_type, &offered_asset, &min_requested_asset);
        let metadata = PartialNoteMetadata::new(consumer_account_id, self.note_type).with_tag(tag);

        Ok(Note::with_attachments(
            assets,
            metadata,
            recipient,
            NoteAttachments::from(NoteAttachment::from(*attachment)),
        ))
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
        min_requested_asset: &FungibleAsset,
    ) -> NoteTag {
        let pswap_root_bytes = Self::script().root().as_bytes();

        // Construct the pswap use case ID from the 14 most significant bits of the script root.
        // This leaves the two most significant bits zero.
        let mut pswap_use_case_id = (pswap_root_bytes[0] as u16) << 6;
        pswap_use_case_id |= (pswap_root_bytes[1] >> 2) as u16;

        // Get bits 0..8 from the faucet IDs of both assets which will form the tag payload.
        let offered_asset_id: u64 = offered_asset.faucet_id().prefix().into();
        let offered_asset_tag = (offered_asset_id >> 56) as u8;

        let min_requested_asset_id: u64 = min_requested_asset.faucet_id().prefix().into();
        let min_requested_asset_tag = (min_requested_asset_id >> 56) as u8;

        let asset_pair = ((offered_asset_tag as u16) << 8) | (min_requested_asset_tag as u16);

        let tag = ((note_type as u8 as u32) << 30)
            | ((pswap_use_case_id as u32) << 16)
            | asset_pair as u32;

        NoteTag::new(tag)
    }

    /// Computes a fill's proportional share of the offered tokens:
    /// `floor((offered_total * fill_amount) / fill_reference)`, computed via a u128 intermediate.
    ///
    /// The caller passes `fill_reference = max(total_fill, min_requested_amount)`, so for an
    /// over-fill the shares scale by the actual fill rather than `min_requested_amount` (see
    /// [`Self::execute`]).
    ///
    /// # Errors
    ///
    /// Returns an error if the result does not fit in a valid [`AssetAmount`].
    fn calculate_output_amount(
        offered_total: u64,
        fill_reference: u64,
        fill_amount: u64,
    ) -> Result<u64, NoteError> {
        let product = (offered_total as u128) * (fill_amount as u128);
        let quotient = product / (fill_reference as u128);
        let amount = u64::try_from(quotient)
            .map_err(|_| NoteError::other("payout quotient does not fit in u64"))?;
        // Validate the result is a valid fungible asset amount.
        AssetAmount::new(amount).map_err(|e| {
            NoteError::other_with_source("payout amount exceeds max fungible asset amount", e)
        })?;
        Ok(amount)
    }

    /// Builds the [`NoteAttachment`] carried by both PSWAP output notes (payback and
    /// remainder).
    ///
    /// `amount` is the round's transferred amount on the relevant side of the trade —
    /// requested-asset units for the payback, offered-asset units for the remainder.
    fn pswap_output_attachment(
        amount: u64,
        order_id: Felt,
        depth: u64,
    ) -> Result<NoteAttachment, NoteError> {
        let amount = AssetAmount::new(amount)
            .map_err(|e| NoteError::other_with_source("amount is not a valid asset amount", e))?;
        let depth = u32::try_from(depth)
            .map_err(|_| NoteError::other("PSWAP depth does not fit in u32"))?;
        Ok(PswapNoteAttachment::new(amount, order_id, depth).into())
    }

    /// Builds an output without disclosing private recipient details to the filler.
    fn create_payback_note(
        &self,
        consumer_account_id: AccountId,
        payback_asset: FungibleAsset,
    ) -> Result<RawOutputNote, NoteError> {
        let current_depth = u64::from(self.parent_depth()) + 1;
        let attachment = Self::pswap_output_attachment(
            payback_asset.amount().as_u64(),
            self.order_id(),
            current_depth,
        )?;
        let assets = NoteAssets::new(vec![payback_asset.into()])?;
        let metadata =
            PartialNoteMetadata::new(consumer_account_id, self.storage.payback_note_type())
                .with_tag(self.storage.payback_note_tag());
        let attachments = NoteAttachments::from(attachment);
        Ok(match self.storage.payback {
            PswapPayback::Private { recipient } => {
                RawOutputNote::Partial(PartialNote::new(metadata, recipient, assets, attachments))
            },
            PswapPayback::Public { serial_number, storage } => {
                RawOutputNote::Full(Note::with_attachments(
                    assets,
                    metadata,
                    storage.into_recipient(serial_number),
                    attachments,
                ))
            },
        })
    }

    /// Builds a remainder PSWAP note carrying the unfilled portion of the swap.
    ///
    /// The remainder inherits the payback configuration and note type, with an updated
    /// serial number (`serial[3] + 1`). Its sender is the account executing the fill.
    ///
    /// The attachment carries `[offered_amount_for_fill, order_id, current_depth, 0]` under
    /// [`Self::PSWAP_ATTACHMENT_SCHEME`]. The remainder must carry this attachment so that
    /// when *it* is later consumed as a parent, `get_current_depth` reads the right scheme
    /// and increments depth correctly.
    fn create_remainder_pswap_note(
        &self,
        consumer_account_id: AccountId,
        remaining_offered_asset: FungibleAsset,
        remaining_min_requested_asset: FungibleAsset,
        offered_amount_for_fill: u64,
    ) -> Result<PswapNote, NoteError> {
        let new_storage = PswapNoteStorage {
            min_requested_asset: remaining_min_requested_asset,
            ..self.storage.clone()
        };

        // Remainder serial: increment most significant element (matching MASM movup.3 add.1
        // movdn.3)
        let remainder_serial_num = Word::from([
            self.serial_number[0],
            self.serial_number[1],
            self.serial_number[2],
            self.serial_number[3] + ONE,
        ]);

        let current_depth = u64::from(self.parent_depth()) + 1;
        let attachment =
            Self::pswap_output_attachment(offered_amount_for_fill, self.order_id(), current_depth)?;

        PswapNote::builder()
            .sender(consumer_account_id)
            .storage(new_storage)
            .serial_number(remainder_serial_num)
            .note_type(self.note_type)
            .offered_asset(remaining_offered_asset)
            .attachment(attachment)
            .build()
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
            pswap.storage.min_requested_asset(),
        );

        let recipient = pswap.storage.into_recipient(pswap.serial_number);

        let assets = NoteAssets::new(vec![pswap.offered_asset.into()])
            .expect("single fungible asset should be valid");

        let metadata = PartialNoteMetadata::new(pswap.sender, pswap.note_type).with_tag(tag);

        let attachments = pswap.attachment.map(NoteAttachments::from).unwrap_or_default();

        Note::with_attachments(assets, metadata, recipient, attachments)
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
        let offered_asset = note
            .assets()
            .iter()
            .next()
            .expect("number of assets should have been validated")
            .as_fungible()
            .ok_or_else(|| NoteError::other("PSWAP note asset must be fungible"))?;

        let attachment = match note.attachments().num_attachments() {
            0 => None,
            1 => {
                Some(note.attachments().get(0).expect("length should have been validated").clone())
            },
            _ => return Err(NoteError::other("pswap note supports only one attachment")),
        };

        PswapNote::builder()
            .sender(note.metadata().sender())
            .storage(storage)
            .serial_number(note.recipient().serial_num())
            .note_type(note.metadata().note_type())
            .offered_asset(offered_asset)
            .maybe_attachment(attachment)
            .build()
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for PswapNote {
    fn consumption_cycles() -> u32 {
        PSWAP_CONSUMPTION_CYCLES
    }

    /// Filling a PSWAP note creates the P2ID payback for the fixed recipient and, on a
    /// partial fill, the residual PSWAP note carrying the unfilled remainder.
    fn created_notes() -> Vec<NoteScriptRoot> {
        vec![P2idNote::script_root(), PswapNote::script_root()]
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
    use rstest::rstest;

    use super::*;

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    fn dummy_faucet_id(byte: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([byte; 32])
    }

    fn dummy_creator_id() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([1; 32])
    }

    fn dummy_consumer_id() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([2; 32])
    }

    fn public_payback(target: AccountId) -> PswapPayback {
        PswapPayback::Public {
            serial_number: Word::new([Felt::from(42u32), ZERO, ONE, ZERO]),
            storage: P2idNoteStorage::new(target).with_salt([ONE, Felt::from(7u32)]),
        }
    }

    fn public_recipient(note: &PswapNote) -> NoteRecipient {
        let PswapPayback::Public { serial_number, storage } = *note.storage().payback() else {
            panic!("expected a public payback")
        };
        storage.into_recipient(serial_number)
    }

    fn build_pswap_note(
        offered_asset: FungibleAsset,
        min_requested_asset: FungibleAsset,
        creator_id: AccountId,
    ) -> (PswapNote, Note) {
        let mut rng = RandomCoin::new(Word::default());
        let storage = PswapNoteStorage::builder()
            .min_requested_asset(min_requested_asset)
            .payback(public_payback(creator_id))
            .payback_note_tag(NoteTag::new(0))
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
        let min_requested_asset = FungibleAsset::new(dummy_faucet_id(0xbb), 500).unwrap();

        let (pswap, note) = build_pswap_note(offered_asset, min_requested_asset, creator_id);

        assert_eq!(pswap.sender(), creator_id);
        assert_eq!(pswap.note_type(), NoteType::Public);

        let script = PswapNote::script();
        assert!(Word::from(script.root()) != Word::default(), "Script root should not be zero");
        assert_eq!(note.metadata().sender(), creator_id);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.recipient().script().root(), script.root());
        assert_eq!(
            note.recipient().storage().num_items(),
            PswapNoteStorage::PUBLIC_NUM_STORAGE_ITEMS as u16,
        );
    }

    #[test]
    fn pswap_note_builder() {
        let creator_id = dummy_creator_id();
        let offered_asset = FungibleAsset::new(dummy_faucet_id(0xaa), 1000).unwrap();
        let min_requested_asset = FungibleAsset::new(dummy_faucet_id(0xbb), 500).unwrap();

        let (pswap, note) = build_pswap_note(offered_asset, min_requested_asset, creator_id);

        assert_eq!(pswap.sender(), creator_id);
        assert_eq!(pswap.note_type(), NoteType::Public);
        assert_eq!(note.metadata().sender(), creator_id);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(
            note.recipient().storage().num_items(),
            PswapNoteStorage::PUBLIC_NUM_STORAGE_ITEMS as u16,
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
                AccountIdVersion::Version1,
                AccountType::Public,
                AssetCallbackFlag::Disabled,
            ),
            100,
        )
        .unwrap();
        let min_requested_asset = FungibleAsset::new(
            AccountId::dummy(
                requested_faucet_bytes,
                AccountIdVersion::Version1,
                AccountType::Public,
                AssetCallbackFlag::Disabled,
            ),
            200,
        )
        .unwrap();

        let tag = PswapNote::create_tag(NoteType::Public, &offered_asset, &min_requested_asset);
        let tag_u32 = u32::from(tag);

        // Verify note_type bits (top 2 bits should be 10 for Public)
        let note_type_bits = tag_u32 >> 30;
        assert_eq!(note_type_bits, NoteType::Public as u32);
    }

    #[test]
    fn calculate_output_amount() {
        assert_eq!(PswapNote::calculate_output_amount(100, 100, 50).unwrap(), 50); // Equal ratio
        assert_eq!(PswapNote::calculate_output_amount(200, 100, 50).unwrap(), 100); // 2:1 ratio
        assert_eq!(PswapNote::calculate_output_amount(100, 200, 50).unwrap(), 25); // 1:2 ratio

        // Non-integer ratio (100/73)
        let result = PswapNote::calculate_output_amount(100, 73, 7).unwrap();
        assert!(result > 0, "Should produce non-zero output");
    }

    #[test]
    fn pswap_rejects_legacy_storage() {
        let target = dummy_creator_id();
        let faucet = dummy_faucet_id(0xaa);
        let legacy = [
            faucet.suffix(),
            faucet.prefix().as_felt(),
            Felt::from(500u32),
            ZERO,
            ZERO,
            target.suffix(),
            target.prefix().as_felt(),
        ];
        assert!(PswapNoteStorage::try_from(legacy.as_slice()).is_err());
    }

    #[test]
    fn pswap_note_storage_roundtrip() {
        let creator_id = dummy_creator_id();
        let min_requested_asset = FungibleAsset::new(dummy_faucet_id(0xaa), 500).unwrap();

        let storage = PswapNoteStorage::builder()
            .min_requested_asset(min_requested_asset)
            .payback(public_payback(creator_id))
            .payback_note_tag(NoteTag::new(0))
            .min_fill_step(AssetAmount::new(42).unwrap())
            .build();

        let note_storage = NoteStorage::from(storage.clone());
        assert_eq!(note_storage.num_items(), PswapNoteStorage::PUBLIC_NUM_STORAGE_ITEMS as u16);

        let parsed = PswapNoteStorage::try_from(note_storage.items()).unwrap();

        assert_eq!(parsed.payback(), &public_payback(creator_id));
        assert_eq!(parsed.min_requested_amount(), 500);
        assert_eq!(parsed.min_fill_step().as_u64(), 42);
    }

    #[test]
    fn pswap_note_storage_defaults_min_fill_step_to_zero() {
        let creator_id = dummy_creator_id();
        let min_requested_asset = FungibleAsset::new(dummy_faucet_id(0xaa), 500).unwrap();

        let storage = PswapNoteStorage::builder()
            .min_requested_asset(min_requested_asset)
            .payback(public_payback(creator_id))
            .payback_note_tag(NoteTag::new(0))
            .build();

        assert_eq!(
            storage.min_fill_step(),
            AssetAmount::ZERO,
            "min_fill_step must default to zero (no floor)",
        );
    }

    /// `execute` mirrors the MASM floor: it rejects `total_fill = account_fill + note_fill` below
    /// `min(min_fill_step, min_requested_amount)` and accepts anything at or above it, with any
    /// remainder inheriting the floor. Cases are `(min_requested, min_fill_step, account_fill,
    /// note_fill, expect_ok)`; offered is 200 throughout.
    #[rstest]
    // Binding floor (min_fill_step <= min_requested): below / equal / above.
    #[case::below_floor(100, 30, 29, 0, false)]
    #[case::equal_floor(100, 30, 30, 0, true)]
    #[case::above_floor(100, 30, 50, 0, true)]
    // Clamp (min_requested < min_fill_step): a full fill at min_requested is accepted, below it
    // isn't.
    #[case::clamped_full_fill(20, 50, 20, 0, true)]
    #[case::clamped_below_both(20, 50, 10, 0, false)]
    // total_fill = account_fill + note_fill, checked as a sum: neither leg alone reaches the floor.
    #[case::two_legs_meet_floor(100, 30, 20, 20, true)]
    #[case::two_legs_below_floor(100, 30, 10, 10, false)]
    fn pswap_execute_enforces_min_fill_step(
        #[case] min_requested: u64,
        #[case] min_fill_step: u64,
        #[case] account_fill: u64,
        #[case] note_fill: u64,
        #[case] expect_ok: bool,
    ) {
        let creator_id = dummy_creator_id();
        let consumer_id = dummy_consumer_id();
        let offered_faucet = dummy_faucet_id(0xaa);
        let requested_faucet = dummy_faucet_id(0xbb);

        let offered_asset = FungibleAsset::new(offered_faucet, 200).unwrap();
        let min_requested_asset = FungibleAsset::new(requested_faucet, min_requested).unwrap();
        let storage = PswapNoteStorage::builder()
            .min_requested_asset(min_requested_asset)
            .payback(public_payback(creator_id))
            .payback_note_tag(NoteTag::new(0))
            .min_fill_step(AssetAmount::new(min_fill_step).unwrap())
            .build();
        let mut rng = RandomCoin::new(Word::default());
        let pswap = PswapNote::builder()
            .sender(creator_id)
            .storage(storage)
            .serial_number(rng.draw_word())
            .note_type(NoteType::Public)
            .offered_asset(offered_asset)
            .build()
            .unwrap();

        let leg = |amt: u64| (amt > 0).then(|| FungibleAsset::new(requested_faucet, amt).unwrap());
        let result = pswap.execute(consumer_id, leg(account_fill), leg(note_fill));

        assert_eq!(result.is_ok(), expect_ok, "unexpected accept/reject for this fill");

        if let Ok((_, remainder)) = result {
            // A partial fill (total below the requested minimum) leaves a remainder that must carry
            // the same floor; a full or over fill leaves none.
            if account_fill + note_fill < min_requested {
                let rem = remainder.expect("partial fill should produce a remainder");
                assert_eq!(
                    rem.storage().min_fill_step().as_u64(),
                    min_fill_step,
                    "remainder must inherit min_fill_step",
                );
            } else {
                assert!(remainder.is_none(), "full fill must complete the swap with no remainder");
            }
        }
    }

    /// Consumer supplies both an account fill and a note fill, and the sum is below
    /// the requested amount → `execute` must combine them into a single payback note
    /// carrying account_fill+note_fill of the requested asset and emit a remainder
    /// pswap note for the unfilled portion.
    #[test]
    fn pswap_execute_combined_account_fill_and_note_fill_partial_fill() {
        let creator_id = dummy_creator_id();
        let consumer_id = dummy_consumer_id();
        let offered_faucet = dummy_faucet_id(0xaa);
        let requested_faucet = dummy_faucet_id(0xbb);

        // Offer 100 offered, request 50 requested → 2:1 ratio.
        let offered_asset = FungibleAsset::new(offered_faucet, 100).unwrap();
        let min_requested_asset = FungibleAsset::new(requested_faucet, 50).unwrap();
        let (pswap, _) = build_pswap_note(offered_asset, min_requested_asset, creator_id);

        // Account fill = 10, note fill = 20 → total fill = 30 (< 50, so partial).
        let account_fill = FungibleAsset::new(requested_faucet, 10).unwrap();
        let note_fill = FungibleAsset::new(requested_faucet, 20).unwrap();

        let (payback, remainder) =
            pswap.execute(consumer_id, Some(account_fill), Some(note_fill)).unwrap();

        // Payback note must carry the combined 30 of requested asset.
        assert_eq!(payback.assets().num_assets(), 1);
        let payback_asset = payback.assets().iter().next().unwrap();
        let fa = payback_asset.unwrap_fungible();
        assert_eq!(fa.faucet_id(), requested_faucet);
        assert_eq!(fa.amount().as_u64(), 30);

        // Remainder must exist with the unfilled 50 - 30 = 20 of requested, and the
        // offered amount reduced proportionally (100 - 30*2 = 40).
        let remainder = remainder.expect("partial fill should produce remainder");
        assert_eq!(remainder.storage().min_requested_amount(), 20);
        assert_eq!(remainder.offered_asset().amount().as_u64(), 40);
        assert_eq!(remainder.storage().payback(), pswap.storage().payback());
    }

    /// Consumer supplies both an account fill and a note fill, and the sum exactly
    /// matches the requested amount → `execute` must produce a single payback note for
    /// the full amount and no remainder.
    #[test]
    fn pswap_execute_combined_account_fill_and_note_fill_full_fill() {
        let creator_id = dummy_creator_id();
        let consumer_id = dummy_consumer_id();
        let offered_faucet = dummy_faucet_id(0xaa);
        let requested_faucet = dummy_faucet_id(0xbb);

        let offered_asset = FungibleAsset::new(offered_faucet, 100).unwrap();
        let min_requested_asset = FungibleAsset::new(requested_faucet, 50).unwrap();
        let (pswap, _) = build_pswap_note(offered_asset, min_requested_asset, creator_id);

        // Account fill = 30, note fill = 20 → total fill = 50 (exactly requested).
        let account_fill = FungibleAsset::new(requested_faucet, 30).unwrap();
        let note_fill = FungibleAsset::new(requested_faucet, 20).unwrap();

        let (payback, remainder) =
            pswap.execute(consumer_id, Some(account_fill), Some(note_fill)).unwrap();

        // Payback note must carry the full 50 of requested asset.
        assert_eq!(payback.assets().num_assets(), 1);
        let payback_asset = payback.assets().iter().next().unwrap();
        let fa = payback_asset.unwrap_fungible();
        assert_eq!(fa.faucet_id(), requested_faucet);
        assert_eq!(fa.amount().as_u64(), 50);

        // Full fill → no remainder note.
        assert!(remainder.is_none(), "full fill must not produce a remainder");
    }

    /// A depth outside the u32 range the on-chain script enforces must be rejected when the
    /// note is built, and therefore also when a protocol note is decoded back into a
    /// [`PswapNote`].
    #[rstest]
    #[case::above_u32(Felt::new_unchecked(u64::from(u32::MAX) + 1))]
    #[case::wraps_the_field(Felt::MAX)]
    fn pswap_rejects_out_of_range_attachment_depth(#[case] depth: Felt) {
        let creator_id = dummy_creator_id();
        let offered_asset = FungibleAsset::new(dummy_faucet_id(0xaa), 100).unwrap();
        let min_requested_asset = FungibleAsset::new(dummy_faucet_id(0xbb), 50).unwrap();

        let storage = PswapNoteStorage::builder()
            .min_requested_asset(min_requested_asset)
            .payback(public_payback(creator_id))
            .payback_note_tag(NoteTag::new(0))
            .build();
        let attachment = NoteAttachment::with_word(
            PswapNote::PSWAP_ATTACHMENT_SCHEME,
            Word::from([ONE, ONE, depth, ZERO]),
        );

        let result = PswapNote::builder()
            .sender(creator_id)
            .storage(storage)
            .serial_number(RandomCoin::new(Word::default()).draw_word())
            .note_type(NoteType::Public)
            .offered_asset(offered_asset)
            .attachment(attachment)
            .build();

        assert!(result.is_err(), "an out-of-range depth must not build a PswapNote");
    }

    /// The lineage helpers offset the serial number by the distance between the note they are
    /// called on and the attachment's round, so a note that itself sits at a non-zero depth
    /// reconstructs the same round as the original does.
    #[test]
    fn pswap_lineage_helpers_are_relative_to_the_parent_depth() {
        let creator_id = dummy_creator_id();
        let consumer_id = dummy_consumer_id();
        let offered_faucet = dummy_faucet_id(0xaa);
        let requested_faucet = dummy_faucet_id(0xbb);

        let offered_asset = FungibleAsset::new(offered_faucet, 100).unwrap();
        let min_requested_asset = FungibleAsset::new(requested_faucet, 50).unwrap();
        let (original, _) = build_pswap_note(offered_asset, min_requested_asset, creator_id);

        // Round 1 leaves a remainder sitting at depth 1, which round 2 then consumes.
        let fill = FungibleAsset::new(requested_faucet, 20).unwrap();
        let (_, remainder) = original.execute(consumer_id, Some(fill), None).unwrap();
        let remainder = remainder.expect("partial fill should produce a remainder");
        assert_eq!(remainder.parent_depth(), 1);

        let (round_two_payback, _) = remainder.execute(consumer_id, Some(fill), None).unwrap();
        let round_one_attachment = PswapNoteAttachment::try_from(
            remainder.attachments().expect("remainder carries an attachment"),
        )
        .unwrap();
        let round_two_attachment = PswapNoteAttachment::new(
            AssetAmount::new(20).unwrap(),
            round_one_attachment.order_id(),
            2,
        );

        assert_eq!(
            original
                .payback_note(consumer_id, &round_two_attachment, &public_recipient(&original))
                .unwrap()
                .id(),
            round_two_payback.id(),
            "the original must reconstruct round 2 from its absolute depth",
        );
        assert_eq!(
            remainder
                .payback_note(consumer_id, &round_two_attachment, &public_recipient(&original))
                .unwrap()
                .id(),
            round_two_payback.id(),
            "the round's own parent must reconstruct it as well",
        );
        assert!(
            remainder
                .payback_note(consumer_id, &round_one_attachment, &public_recipient(&original))
                .is_err(),
            "an attachment from the parent's own round is not a later round",
        );
    }
}
