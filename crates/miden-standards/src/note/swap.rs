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
    NoteDetails,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use super::P2idNote;
use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the SWAP note script procedure in the standards library.
const SWAP_SCRIPT_PATH: &str = "::miden::standards::notes::swap::main";

// Initialize the SWAP note script only once
static SWAP_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(SWAP_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains SWAP note script procedure")
});

// SWAP NOTE
// ================================================================================================

/// TODO: add docs
pub struct SwapNote;

impl SwapNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the SWAP note.
    pub const NUM_STORAGE_ITEMS: usize = 16;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the SWAP note.
    pub fn script() -> NoteScript {
        SWAP_SCRIPT.clone()
    }

    /// Returns the SWAP note script root.
    pub fn script_root() -> Word {
        SWAP_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Generates a SWAP note - swap of assets between two accounts - and returns the note as well
    /// as [`NoteDetails`] for the payback note.
    ///
    /// This script enables a swap of 2 assets between the `sender` account and any other account
    /// that is willing to consume the note. The consumer will receive the `offered_asset` and
    /// will create a new P2ID note with `sender` as target, containing the `requested_asset`.
    ///
    /// # Errors
    /// Returns an error if deserialization or compilation of the `SWAP` script fails.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        offered_asset: Asset,
        requested_asset: Asset,
        swap_note_type: NoteType,
        swap_note_attachment: NoteAttachment,
        payback_note_type: NoteType,
        payback_note_attachment: NoteAttachment,
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

        let mut inputs = Vec::with_capacity(16);
        inputs.extend_from_slice(&[
            payback_note_type.into(),
            payback_tag.into(),
            attachment_scheme,
            attachment_kind,
        ]);
        inputs.extend_from_slice(attachment.as_elements());
        inputs.extend_from_slice(requested_asset_word.as_elements());
        inputs.extend_from_slice(payback_recipient.digest().as_elements());
        let inputs = NoteStorage::new(inputs)?;

        // build the tag for the SWAP use case
        let tag = Self::build_tag(swap_note_type, &offered_asset, &requested_asset);
        let serial_num = rng.draw_word();

        // build the outgoing note
        let metadata =
            NoteMetadata::new(sender, swap_note_type, tag).with_attachment(swap_note_attachment);
        let assets = NoteAssets::new(vec![offered_asset])?;
        let recipient = NoteRecipient::new(serial_num, note_script, inputs);
        let note = Note::new(assets, metadata, recipient);

        // build the payback note details
        let payback_assets = NoteAssets::new(vec![requested_asset])?;
        let payback_note = NoteDetails::new(payback_assets, payback_recipient);

        Ok((note, payback_note))
    }

    /// Returns a note tag for a swap note with the specified parameters.
    ///
    /// The tag is laid out as follows:
    ///
    /// ```text
    /// [
    ///   note_type (2 bits) | script_root (14 bits)
    ///   | offered_asset_faucet_id (8 bits) | requested_asset_faucet_id (8 bits)
    /// ]
    /// ```
    ///
    /// The script root serves as the use case identifier of the SWAP tag.
    pub fn build_tag(
        note_type: NoteType,
        offered_asset: &Asset,
        requested_asset: &Asset,
    ) -> NoteTag {
        let swap_root_bytes = Self::script().root().as_bytes();
        // Construct the swap use case ID from the 14 most significant bits of the script root. This
        // leaves the two most significant bits zero.
        let mut swap_use_case_id = (swap_root_bytes[0] as u16) << 6;
        swap_use_case_id |= (swap_root_bytes[1] >> 2) as u16;

        // Get bits 0..8 from the faucet IDs of both assets which will form the tag payload.
        let offered_asset_id: u64 = offered_asset.faucet_id_prefix().into();
        let offered_asset_tag = (offered_asset_id >> 56) as u8;

        let requested_asset_id: u64 = requested_asset.faucet_id_prefix().into();
        let requested_asset_tag = (requested_asset_id >> 56) as u8;

        let asset_pair = ((offered_asset_tag as u16) << 8) | (requested_asset_tag as u16);

        let tag = ((note_type as u8 as u32) << 30)
            | ((swap_use_case_id as u32) << 16)
            | asset_pair as u32;

        NoteTag::new(tag)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
    use miden_protocol::asset::{FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
    use miden_protocol::{self};

    use super::*;

    #[test]
    fn swap_tag() {
        // Construct an ID that starts with 0xcdb1.
        let mut fungible_faucet_id_bytes = [0; 15];
        fungible_faucet_id_bytes[0] = 0xcd;
        fungible_faucet_id_bytes[1] = 0xb1;

        // Construct an ID that starts with 0xabec.
        let mut non_fungible_faucet_id_bytes = [0; 15];
        non_fungible_faucet_id_bytes[0] = 0xab;
        non_fungible_faucet_id_bytes[1] = 0xec;

        let offered_asset = Asset::Fungible(
            FungibleAsset::new(
                AccountId::dummy(
                    fungible_faucet_id_bytes,
                    AccountIdVersion::Version0,
                    AccountType::FungibleFaucet,
                    AccountStorageMode::Public,
                ),
                2500,
            )
            .unwrap(),
        );

        let requested_asset = Asset::NonFungible(
            NonFungibleAsset::new(
                &NonFungibleAssetDetails::new(
                    AccountId::dummy(
                        non_fungible_faucet_id_bytes,
                        AccountIdVersion::Version0,
                        AccountType::NonFungibleFaucet,
                        AccountStorageMode::Public,
                    )
                    .prefix(),
                    vec![0xaa, 0xbb, 0xcc, 0xdd],
                )
                .unwrap(),
            )
            .unwrap(),
        );

        // The fungible ID starts with 0xcdb1.
        // The non fungible ID starts with 0xabec.
        // The expected tag payload is thus 0xcdab.
        let expected_asset_pair = 0xcdab;

        let note_type = NoteType::Public;
        let actual_tag = SwapNote::build_tag(note_type, &offered_asset, &requested_asset);

        assert_eq!(actual_tag.as_u32() as u16, expected_asset_pair, "asset pair should match");
        assert_eq!((actual_tag.as_u32() >> 30) as u8, note_type as u8, "note type should match");
        // Check the 8 bits of the first script root byte.
        assert_eq!(
            (actual_tag.as_u32() >> 22) as u8,
            SwapNote::script_root().as_bytes()[0],
            "swap script root byte 0 should match"
        );
        // Extract the 6 bits of the second script root byte and shift for comparison.
        assert_eq!(
            ((actual_tag.as_u32() & 0b00000000_00111111_00000000_00000000) >> 16) as u8,
            SwapNote::script_root().as_bytes()[1] >> 2,
            "swap script root byte 1 should match with the lower two bits set to zero"
        );
    }
}
