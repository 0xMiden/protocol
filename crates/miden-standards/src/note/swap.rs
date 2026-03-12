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
    NoteAttachmentContent,
    NoteAttachmentKind,
    NoteAttachmentScheme,
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

use crate::StandardsLib;
use crate::note::P2idNoteStorage;

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
    pub const NUM_STORAGE_ITEMS: usize = 20;

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
        let payback_recipient = P2idNoteStorage::new(sender).into_recipient(payback_serial_num);

        let payback_tag = NoteTag::with_account_target(sender);

        let attachment_scheme = Felt::from(payback_note_attachment.attachment_scheme().as_u32());
        let attachment_kind = Felt::from(payback_note_attachment.attachment_kind().as_u8());
        let attachment = payback_note_attachment.content().to_word();

        let mut storage = Vec::with_capacity(SwapNote::NUM_STORAGE_ITEMS);
        storage.extend_from_slice(&[
            payback_note_type.into(),
            payback_tag.into(),
            attachment_scheme,
            attachment_kind,
        ]);
        storage.extend_from_slice(attachment.as_elements());
        storage.extend_from_slice(&requested_asset.as_elements());
        storage.extend_from_slice(payback_recipient.digest().as_elements());
        let inputs = NoteStorage::new(storage)?;

        // build the tag for the SWAP use case
        let tag = Self::build_tag(swap_note_type, &offered_asset, &requested_asset);
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
        let offered_asset_id: u64 = offered_asset.faucet_id().prefix().into();
        let offered_asset_tag = (offered_asset_id >> 56) as u8;

        let requested_asset_id: u64 = requested_asset.faucet_id().prefix().into();
        let requested_asset_tag = (requested_asset_id >> 56) as u8;

        let asset_pair = ((offered_asset_tag as u16) << 8) | (requested_asset_tag as u16);

        let tag = ((note_type as u8 as u32) << 30)
            | ((swap_use_case_id as u32) << 16)
            | asset_pair as u32;

        NoteTag::new(tag)
    }
}

// SWAP NOTE STORAGE
// ================================================================================================

/// Canonical storage representation for a SWAP note.
///
/// Contains the payback note configuration and the requested asset that the
/// swap creator wants to receive in exchange for the offered asset contained
/// in the note's vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapNoteStorage {
    payback_note_type: NoteType,
    payback_tag: NoteTag,
    payback_attachment: NoteAttachment,
    requested_asset: Asset,
    payback_recipient_digest: Word,
}

impl SwapNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the SWAP note.
    pub const NUM_ITEMS: usize = 20;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates new SWAP note storage with the specified parameters.
    pub fn new(
        payback_note_type: NoteType,
        payback_tag: NoteTag,
        payback_attachment: NoteAttachment,
        requested_asset: Asset,
        payback_recipient_digest: Word,
    ) -> Self {
        Self {
            payback_note_type,
            payback_tag,
            payback_attachment,
            requested_asset,
            payback_recipient_digest,
        }
    }

    /// Returns the payback note type.
    pub fn payback_note_type(&self) -> NoteType {
        self.payback_note_type
    }

    /// Returns the payback note tag.
    pub fn payback_tag(&self) -> NoteTag {
        self.payback_tag
    }

    /// Returns the payback note attachment.
    pub fn payback_attachment(&self) -> &NoteAttachment {
        &self.payback_attachment
    }

    /// Returns the requested asset.
    pub fn requested_asset(&self) -> Asset {
        self.requested_asset
    }

    /// Returns the payback recipient digest.
    pub fn payback_recipient_digest(&self) -> Word {
        self.payback_recipient_digest
    }

    pub fn into_recipient(self, serial_num: Word) -> NoteRecipient {
        NoteRecipient::new(serial_num, SwapNote::script(), NoteStorage::from(self))
    }
}

impl From<SwapNoteStorage> for NoteStorage {
    fn from(storage: SwapNoteStorage) -> Self {
        let attachment_scheme = Felt::from(storage.payback_attachment.attachment_scheme().as_u32());
        let attachment_kind = Felt::from(storage.payback_attachment.attachment_kind().as_u8());
        let attachment = storage.payback_attachment.content().to_word();

        let mut storage_values = Vec::with_capacity(SwapNoteStorage::NUM_ITEMS);
        storage_values.extend_from_slice(&[
            storage.payback_note_type.into(),
            storage.payback_tag.into(),
            attachment_scheme,
            attachment_kind,
        ]);
        storage_values.extend_from_slice(attachment.as_elements());
        storage_values.extend_from_slice(&storage.requested_asset.as_elements());
        storage_values.extend_from_slice(storage.payback_recipient_digest.as_elements());

        NoteStorage::new(storage_values)
            .expect("number of storage items should not exceed max storage items")
    }
}

impl TryFrom<&[Felt]> for SwapNoteStorage {
    type Error = NoteError;

    fn try_from(note_storage: &[Felt]) -> Result<Self, Self::Error> {
        if note_storage.len() != SwapNote::NUM_STORAGE_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: SwapNote::NUM_STORAGE_ITEMS,
                actual: note_storage.len(),
            });
        }

        let payback_note_type = NoteType::try_from(note_storage[0])
            .map_err(|err| NoteError::other_with_source("invalid payback note type", err))?;

        let payback_tag = NoteTag::new(
            note_storage[1]
                .as_canonical_u64()
                .try_into()
                .map_err(|e| NoteError::other_with_source("invalid payback tag value", e))?,
        );

        let attachment_scheme_u32: u32 = note_storage[2]
            .as_canonical_u64()
            .try_into()
            .map_err(|e| NoteError::other_with_source("invalid attachment scheme value", e))?;
        let attachment_scheme = NoteAttachmentScheme::new(attachment_scheme_u32);

        let attachment_kind_u8: u8 = note_storage[3]
            .as_canonical_u64()
            .try_into()
            .map_err(|e| NoteError::other_with_source("invalid attachment kind value", e))?;
        let attachment_kind = NoteAttachmentKind::try_from(attachment_kind_u8)
            .map_err(|e| NoteError::other_with_source("invalid attachment kind", e))?;

        let attachment_content_word =
            Word::new([note_storage[4], note_storage[5], note_storage[6], note_storage[7]]);

        let attachment_content = match attachment_kind {
            NoteAttachmentKind::None => NoteAttachmentContent::None,
            NoteAttachmentKind::Word => NoteAttachmentContent::new_word(attachment_content_word),
            NoteAttachmentKind::Array => NoteAttachmentContent::new_word(attachment_content_word),
        };

        let payback_attachment = NoteAttachment::new(attachment_scheme, attachment_content)
            .map_err(|e| NoteError::other_with_source("invalid note attachment", e))?;

        let asset_key =
            Word::new([note_storage[8], note_storage[9], note_storage[10], note_storage[11]]);
        let asset_value =
            Word::new([note_storage[12], note_storage[13], note_storage[14], note_storage[15]]);
        let requested_asset = Asset::from_key_value_words(asset_key, asset_value)
            .map_err(|err| NoteError::other_with_source("invalid requested asset", err))?;

        let payback_recipient_digest =
            Word::new([note_storage[16], note_storage[17], note_storage[18], note_storage[19]]);

        Ok(Self {
            payback_note_type,
            payback_tag,
            payback_attachment,
            requested_asset,
            payback_recipient_digest,
        })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Felt;
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
    use miden_protocol::asset::{FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
    use miden_protocol::errors::NoteError;
    use miden_protocol::note::{NoteAttachment, NoteStorage, NoteTag, NoteType};

    use super::*;

    fn dummy_fungible_faucet() -> AccountId {
        AccountId::dummy(
            [1u8; 15],
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        )
    }

    fn dummy_non_fungible_faucet() -> AccountId {
        AccountId::dummy(
            [2u8; 15],
            AccountIdVersion::Version0,
            AccountType::NonFungibleFaucet,
            AccountStorageMode::Public,
        )
    }

    fn dummy_fungible_asset() -> Asset {
        Asset::Fungible(FungibleAsset::new(dummy_fungible_faucet(), 1000).unwrap())
    }

    fn dummy_non_fungible_asset() -> Asset {
        let details =
            NonFungibleAssetDetails::new(dummy_non_fungible_faucet(), vec![0xaa, 0xbb]).unwrap();
        Asset::NonFungible(NonFungibleAsset::new(&details).unwrap())
    }

    #[test]
    fn swap_note_storage() {
        let payback_note_type = NoteType::Private;
        let payback_tag = NoteTag::new(0x12345678);
        let payback_attachment = NoteAttachment::default();
        let requested_asset = dummy_fungible_asset();
        let payback_recipient_digest =
            Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);

        let storage = SwapNoteStorage::new(
            payback_note_type,
            payback_tag,
            payback_attachment.clone(),
            requested_asset,
            payback_recipient_digest,
        );

        // Convert to NoteStorage
        let note_storage = NoteStorage::from(storage.clone());
        assert_eq!(note_storage.num_items() as usize, SwapNoteStorage::NUM_ITEMS);

        // Convert back from storage items
        let decoded = SwapNoteStorage::try_from(note_storage.items())
            .expect("valid SWAP storage should decode");

        assert_eq!(decoded.payback_note_type(), payback_note_type);
        assert_eq!(decoded.payback_tag(), payback_tag);
        assert_eq!(decoded.payback_attachment(), &payback_attachment);
        assert_eq!(decoded.requested_asset(), requested_asset);
        assert_eq!(decoded.payback_recipient_digest(), payback_recipient_digest);
    }

    #[test]
    fn swap_note_storage_with_non_fungible_asset() {
        let payback_note_type = NoteType::Public;
        let payback_tag = NoteTag::new(0xaabbccdd);
        let payback_attachment = NoteAttachment::default();
        let requested_asset = dummy_non_fungible_asset();
        let payback_recipient_digest =
            Word::new([Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]);

        let storage = SwapNoteStorage::new(
            payback_note_type,
            payback_tag,
            payback_attachment.clone(),
            requested_asset,
            payback_recipient_digest,
        );

        let note_storage = NoteStorage::from(storage);
        let decoded = SwapNoteStorage::try_from(note_storage.items())
            .expect("valid SWAP storage should decode");

        assert_eq!(decoded.payback_note_type(), payback_note_type);
        assert_eq!(decoded.requested_asset(), requested_asset);
    }

    #[test]
    fn try_from_invalid_length_fails() {
        let storage = vec![Felt::ZERO; 10];

        let err =
            SwapNoteStorage::try_from(storage.as_slice()).expect_err("wrong length must fail");

        assert!(matches!(
            err,
            NoteError::InvalidNoteStorageLength {
                expected: SwapNote::NUM_STORAGE_ITEMS,
                actual: 10
            }
        ));
    }

    #[test]
    fn try_from_invalid_note_type_fails() {
        let mut storage = vec![Felt::ZERO; SwapNoteStorage::NUM_ITEMS];
        // Set invalid note type (value > 2)
        storage[0] = Felt::new(99);

        let err =
            SwapNoteStorage::try_from(storage.as_slice()).expect_err("invalid note type must fail");

        assert!(matches!(err, NoteError::Other { source: Some(_), .. }));
    }

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
                    ),
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
