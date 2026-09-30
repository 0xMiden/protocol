//! `XReserveBurnNote`: the Circle-facing public burn-event note.
//!
//! A withdrawing xUSDC holder creates this note carrying the burned xUSDC; Circle's off-chain
//! withdrawal attester discovers it by its FIXED full-32-bit tag (`SyncNotes` exact-match) and
//! reads its withdrawal-payload attachment `(destDomain, destRecipient)` to release
//! USDC on the source chain.
//!
//! It is built as a standalone note factory. What it does reuse is the standard burn consume
//! script, so consuming one of these notes runs `faucet::receive_and_burn` and the faucet's active
//! burn policy exactly as any other burn would. The stock script reserves all eight `NoteStorage`
//! items for the asset and asserts the stored asset equals the carried one, so this note keeps the
//! stock 8-felt asset storage and carries its withdrawal payload in a scheme-tagged note
//! ATTACHMENT instead. The note is forced public, carries the fixed xUSDC burn tag, and packs the
//! payload with the shared codec so the listener decodes precisely what was encoded.
//!
//! The burn policy requires exactly two attachments: the routing target and a withdrawal payload
//! of three words. It checks the withdrawal content against the commitment in the note.
//! The off-chain withdrawal attester validates the destination fields.

use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteRecipient,
    NoteScript, NoteScriptRoot, NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::{Felt, Word, WORD_SIZE};
use miden_standards::note::BurnNote;

use crate::xreserve::encoding::{XReserveBurnItems, BURN_NOTE_ITEMS_FELTS};

/// The fixed tag every xUSDC burn note carries — ASCII `"BURN"`.
///
/// The off-chain listener discovers burn notes by asking the node for this exact 32-bit value, so
/// it has to be a constant shared by every burn note rather than anything per-account. Its low 18
/// bits are non-zero, which means it can never be mistaken for an account-target tag: those are
/// built with the low 18 bits zeroed. It identifies a use case, not a destination.
///
/// The specific value is provisional and awaits Circle's confirmation — it is not a value Circle
/// has assigned.
pub const FIXED_XUSDC_BURN_TAG: u32 = 0x4255_524E;

/// The withdrawal-payload attachment scheme (u16, project-chosen). It carries the 9-felt Circle
/// withdrawal payload, mirroring how the mint transport carries its own payload as a scheme-tagged
/// attachment.
///
/// The value is chosen clear of everything already in use: the protocol reserves `0` (absent) and
/// `1` (none); the standards use `2` (`NetworkAccountTarget`) and `3` (`Pswap`); the xUSDC mint
/// transport holds `4`; and `5` is left burned because the parked validation crate historically
/// used it for a now-retired attestation attachment. `6` is the first value not associated with any
/// other payload, so it does not resurrect a retired scheme.
pub const XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME: u16 = 6;

/// Word count of the withdrawal-payload attachment: the 9 payload felts zero-padded to a word
/// boundary (3 words, 3 pad felts). Fixed, because [`BURN_NOTE_ITEMS_FELTS`] is fixed.
pub const XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_WORDS: usize = 3;

/// The withdrawal payload a burn note carries — the [`XReserveBurnItems`] the off-chain attester
/// decodes.
///
/// This is the scheme-6 withdrawal attachment in domain form. It converts into the
/// [`NoteAttachment`] the note id commits to, the way [`XUsdcDeposit`] converts into the mint
/// note's scheme-4 transport one.
///
/// [`XUsdcDeposit`]: crate::note::xreserve_mint::XUsdcDeposit
pub struct XUsdcBurnAttachment {
    items: XReserveBurnItems,
}

impl XUsdcBurnAttachment {
    /// Wraps the withdrawal payload the burn note carries.
    pub fn new(items: XReserveBurnItems) -> Self {
        Self { items }
    }

    /// The carried withdrawal payload.
    pub fn items(&self) -> &XReserveBurnItems {
        &self.items
    }
}

impl From<&XUsdcBurnAttachment> for NoteAttachment {
    /// Builds the withdrawal attachment: the payload felts, zero-padded to the word boundary.
    ///
    /// The encoding is the shared codec the off-chain attester decodes with, so the write and the
    /// read side cannot drift apart.
    fn from(attachment: &XUsdcBurnAttachment) -> Self {
        let mut elements = attachment.items.encode();
        while !elements.len().is_multiple_of(Word::NUM_ELEMENTS) {
            elements.push(Felt::ZERO);
        }

        let words: Vec<Word> = elements
            .as_chunks::<{ Word::NUM_ELEMENTS }>()
            .0
            .iter()
            .map(|chunk| Word::new(*chunk))
            .collect();
        NoteAttachment::with_words(
            NoteAttachmentScheme::new(XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME)
                .expect("the withdrawal scheme is neither reserved nor past the protocol maximum"),
            words,
        )
        // the payload is fixed-width, so the word count is the constant asserted below
        .expect("the withdrawal payload is within the per-attachment word cap")
    }
}

// the padded payload is what fixes the attachment's word count, so the two cannot drift apart — and
// that fixed count is what makes the conversion above infallible.
const _: () = assert!(
    BURN_NOTE_ITEMS_FELTS.div_ceil(WORD_SIZE) == XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_WORDS
        && XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_WORDS <= NoteAttachment::MAX_NUM_WORDS as usize,
    "the padded withdrawal payload must occupy the declared number of words, within the cap"
);

/// The public burn-event note. A standalone unit-struct note factory.
pub struct XReserveBurnNote;

impl XReserveBurnNote {
    /// Number of withdrawal-payload felts (9), owned by the shared-encoding codec.
    pub const NUM_PAYLOAD_ITEMS: usize = BURN_NOTE_ITEMS_FELTS;

    /// Returns the (reused) stock burn note consume script — targets `faucet::receive_and_burn`.
    pub fn script() -> NoteScript {
        BurnNote::script()
    }

    /// Returns the (reused) stock burn note script root.
    pub fn script_root() -> NoteScriptRoot {
        BurnNote::script_root()
    }

    /// Convenience constructor over the [`XReserveBurnItems`] payload (a thin delegator to the
    /// [`builder`](Self::builder)); retained because the frozen conformance suites pin this signature.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        amount: AssetAmount,
        items: XReserveBurnItems,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        Self::builder()
            .sender(sender)
            .faucet_id(faucet_id)
            .amount(amount)
            .items(items)
            .rng(rng)
            .build()
    }
}

#[bon::bon]
impl XReserveBurnNote {
    /// Builds an `XReserveBurnNote` via a `bon` builder
    /// (`XReserveBurnNote::builder().sender(..).faucet_id(..).amount(..).items(..).rng(..).build()`):
    /// `NoteType::Public`, the fixed xUSDC burn tag, `metadata.sender = sender` (the depositor),
    /// `NoteAssets` = the burned xUSDC `FungibleAsset` (`amount` issued by `faucet_id`), and
    /// `NoteStorage.items` = the stock 8-felt asset layout the stock burn script asserts against. The
    /// `(destDomain, destRecipient)` withdrawal payload rides in a scheme-tagged
    /// [`XUsdcBurnAttachment`]. The amount is supplied separately for the burned asset.
    #[builder]
    pub fn new<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        amount: AssetAmount,
        items: XReserveBurnItems,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let serial_num = rng.draw_word();

        let asset = FungibleAsset::new(faucet_id, u64::from(amount))
            .map_err(|err| NoteError::other_with_source("invalid burned xUSDC asset", err))?;

        // NoteStorage carries the STOCK 8-felt asset layout (ASSET_ID(4) + ASSET_VALUE(4)); the stock
        // consume script requires exactly that and asserts the stored asset equals the carried one.
        // The withdrawal payload no longer lives here — it rides in the attachment below.
        let storage = NoteStorage::new(Asset::from(asset).as_elements().to_vec())?;
        let recipient = NoteRecipient::new(serial_num, BurnNote::script(), storage);

        // the burn note is always Public — there is no note_type parameter.
        let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
            .with_tag(NoteTag::new(FIXED_XUSDC_BURN_TAG));

        let vault = NoteAssets::new(vec![asset.into()])?;

        // two attachments: the scheme-2 NetworkAccountTarget routing bind (routing only, as any
        // faucet-targeted note carries), and the scheme-tagged withdrawal payload the off-chain
        // attester decodes. The stock consume script ignores attachments, so the burn stays gated by
        // receive_and_burn and the burn policy.
        let attachments = NoteAttachments::new(vec![
            super::network_routing_attachment(faucet_id)?,
            NoteAttachment::from(&XUsdcBurnAttachment::new(items)),
        ])?;

        Ok(Note::with_attachments(
            vault,
            metadata,
            recipient,
            attachments,
        ))
    }
}
