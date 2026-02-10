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
    NoteDetails,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, FieldElement, Word};

use super::P2idNote;
use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the SWAPE note script procedure in the standards library.
const SWAPE_SCRIPT_PATH: &str = "::miden::standards::notes::swape::main";

// Initialize the SWAPE note script only once
static SWAPE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(SWAPE_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains SWAPE note script procedure")
});

// SWAPE NOTE
// ================================================================================================

/// SWAPE (Swap with Expiry) note: extends SWAP with a sender reclaim mechanism.
///
/// The SWAPE note functions identically to a SWAP note when consumed by a non-sender account:
/// it adds the offered asset to the consumer's account and creates a payback P2ID note with the
/// requested asset for the original sender.
///
/// Additionally, the SWAPE note allows the sender to reclaim the offered asset after a specified
/// block height (the reclaim block height). This prevents tokens from being locked indefinitely
/// if the swap offer is never accepted.
pub struct SwapeNote;

impl SwapeNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the SWAPE note.
    ///
    /// Layout: 16 items from SWAP + reclaim_block_height + sender_id_prefix + sender_id_suffix
    /// + padding = 20.
    pub const NUM_STORAGE_ITEMS: usize = 20;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the SWAPE note.
    pub fn script() -> NoteScript {
        SWAPE_SCRIPT.clone()
    }

    /// Returns the SWAPE note script root.
    pub fn script_root() -> Word {
        SWAPE_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Generates a SWAPE note - swap of assets with sender reclaim after a deadline.
    ///
    /// This script enables a swap of 2 assets between the `sender` account and any other account
    /// that is willing to consume the note. The consumer will receive the `offered_asset` and
    /// will create a new P2ID note with `sender` as target, containing the `requested_asset`.
    ///
    /// If the swap is not consumed before `reclaim_height`, the sender can reclaim the offered
    /// asset by consuming the note themselves.
    ///
    /// # Errors
    /// Returns an error if the requested asset is the same as the offered asset, or if note
    /// creation fails.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        offered_asset: Asset,
        requested_asset: Asset,
        swap_note_type: NoteType,
        swap_note_attachment: NoteAttachment,
        payback_note_type: NoteType,
        payback_note_attachment: NoteAttachment,
        reclaim_height: BlockNumber,
        rng: &mut R,
    ) -> Result<(Note, NoteDetails), NoteError> {
        if requested_asset == offered_asset {
            return Err(NoteError::other("requested asset same as offered asset"));
        }

        let note_script = Self::script();

        let payback_serial_num = rng.draw_word();
        let payback_recipient = P2idNote::build_recipient(sender, payback_serial_num)?;

        let requested_asset_word: Word = requested_asset.into();
        let payback_tag = NoteTag::with_account_target(sender);

        let attachment_scheme = Felt::from(payback_note_attachment.attachment_scheme().as_u32());
        let attachment_kind = Felt::from(payback_note_attachment.attachment_kind().as_u8());
        let attachment = payback_note_attachment.content().to_word();

        // Build the 20-item storage:
        // [0-15] Same as SWAP: payback_note_type, payback_note_tag, attachment_scheme,
        //        attachment_kind, ATTACHMENT(4), REQUESTED_ASSET(4), PAYBACK_RECIPIENT(4)
        // [16]   reclaim_block_height
        // [17]   sender_id_prefix
        // [18]   sender_id_suffix
        // [19]   padding (zero)
        let mut inputs = Vec::with_capacity(Self::NUM_STORAGE_ITEMS);
        inputs.extend_from_slice(&[
            payback_note_type.into(),
            payback_tag.into(),
            attachment_scheme,
            attachment_kind,
        ]);
        inputs.extend_from_slice(attachment.as_elements());
        inputs.extend_from_slice(requested_asset_word.as_elements());
        inputs.extend_from_slice(payback_recipient.digest().as_elements());
        inputs.push(Felt::new(reclaim_height.as_u32() as u64));
        inputs.push(sender.prefix().as_felt());
        inputs.push(sender.suffix());
        inputs.push(Felt::ZERO); // padding
        let inputs = NoteStorage::new(inputs)?;

        // Use the same tag as SWAP so notes are discoverable through the same mechanism
        let tag = super::SwapNote::build_tag(swap_note_type, &offered_asset, &requested_asset);
        let serial_num = rng.draw_word();

        // build the outgoing note
        let metadata = NoteMetadata::new(sender, swap_note_type)
            .with_tag(tag)
            .with_attachment(swap_note_attachment);
        let assets = NoteAssets::new(vec![offered_asset])?;
        let recipient = NoteRecipient::new(serial_num, note_script, inputs);
        let note = Note::new(assets, metadata, recipient);

        // build the payback note details
        let payback_assets = NoteAssets::new(vec![requested_asset])?;
        let payback_note = NoteDetails::new(payback_assets, payback_recipient);

        Ok((note, payback_note))
    }
}
