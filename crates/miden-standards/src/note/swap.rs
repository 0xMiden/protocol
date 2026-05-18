use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::Asset;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachments,
    NoteDetails,
    NoteRecipient,
    NoteScript,
    NoteScriptRoot,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, ONE, Word};

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
    pub const NUM_STORAGE_ITEMS: usize = SwapNoteStorage::NUM_ITEMS;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the SWAP note.
    pub fn script() -> NoteScript {
        SWAP_SCRIPT.clone()
    }

    /// Returns the SWAP note script root.
    pub fn script_root() -> NoteScriptRoot {
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
        swap_note_attachments: NoteAttachments,
        payback_note_type: NoteType,
        rng: &mut R,
    ) -> Result<(Note, NoteDetails), NoteError> {
        if requested_asset == offered_asset {
            return Err(NoteError::other("requested asset same as offered asset"));
        }

        let swap_storage = SwapNoteStorage::new(requested_asset, payback_note_type, sender);

        let serial_num = rng.draw_word();
        let recipient = swap_storage.into_recipient(serial_num);

        // build the tag for the SWAP use case
        let tag = Self::build_tag(swap_note_type, &offered_asset, &requested_asset);

        // build the outgoing note
        let metadata = PartialNoteMetadata::new(sender, swap_note_type).with_tag(tag);
        let assets = NoteAssets::new(vec![offered_asset])?;
        let note = Note::with_attachments(assets, metadata, recipient, swap_note_attachments);

        // build the payback note details
        let payback_serial_num = payback_serial_from_swap(serial_num);
        let payback_recipient = P2idNoteStorage::new(sender).into_recipient(payback_serial_num);
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
    ///   note_type (1 bit) | script_root (15 bits)
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
        // Construct the swap use case ID from the 15 most significant bits of the script root. This
        // leaves the most significant bit zero.
        let mut swap_use_case_id = (swap_root_bytes[0] as u16) << 7;
        swap_use_case_id |= (swap_root_bytes[1] >> 1) as u16;

        // Get bits 0..8 from the faucet IDs of both assets which will form the tag payload.
        let offered_asset_id: u64 = offered_asset.faucet_id().prefix().into();
        let offered_asset_tag = (offered_asset_id >> 56) as u8;

        let requested_asset_id: u64 = requested_asset.faucet_id().prefix().into();
        let requested_asset_tag = (requested_asset_id >> 56) as u8;

        let asset_pair = ((offered_asset_tag as u16) << 8) | (requested_asset_tag as u16);

        let tag = ((note_type as u8 as u32) << 31)
            | ((swap_use_case_id as u32) << 16)
            | asset_pair as u32;

        NoteTag::new(tag)
    }
}

// SWAP NOTE STORAGE
// ================================================================================================

/// Canonical storage representation for a SWAP note.
///
/// Maps to the 11-element [`NoteStorage`] layout consumed by the on-chain MASM script:
///
/// | Slot     | Field |
/// |----------|-------|
/// | `[0-7]`  | Requested asset (key + value) |
/// | `[8]`    | Payback note type (0 = private, 1 = public) |
/// | `[9-10]` | Creator account ID (prefix, suffix) |
///
/// The payback note tag is derived at runtime from the creator account ID
/// (via `note_tag::create_account_target` in MASM).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapNoteStorage {
    payback_note_type: NoteType,
    requested_asset: Asset,
    creator_account_id: AccountId,
}

impl SwapNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the SWAP note.
    pub const NUM_ITEMS: usize = 11;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates new SWAP note storage with the specified parameters.
    pub fn new(
        requested_asset: Asset,
        payback_note_type: NoteType,
        creator_account_id: AccountId,
    ) -> Self {
        Self {
            payback_note_type,
            requested_asset,
            creator_account_id,
        }
    }

    /// Returns the payback note type.
    pub fn payback_note_type(&self) -> NoteType {
        self.payback_note_type
    }

    /// Returns the requested asset.
    pub fn requested_asset(&self) -> Asset {
        self.requested_asset
    }

    /// Returns the creator account ID embedded in the SWAP storage.
    pub fn creator_account_id(&self) -> AccountId {
        self.creator_account_id
    }

    /// Consumes the storage and returns a SWAP [`NoteRecipient`] with the provided serial number.
    ///
    /// Notes created with this recipient will be SWAP notes whose storage encodes the payback
    /// configuration and the requested asset stored in this [`SwapNoteStorage`].
    pub fn into_recipient(self, serial_num: Word) -> NoteRecipient {
        NoteRecipient::new(serial_num, SwapNote::script(), NoteStorage::from(self))
    }
}

impl From<SwapNoteStorage> for NoteStorage {
    fn from(storage: SwapNoteStorage) -> Self {
        let mut storage_values = Vec::with_capacity(SwapNoteStorage::NUM_ITEMS);
        storage_values.extend_from_slice(&storage.requested_asset.as_elements());
        storage_values.push(Felt::from(storage.payback_note_type.as_u8()));
        storage_values.push(storage.creator_account_id.prefix().as_felt());
        storage_values.push(storage.creator_account_id.suffix());

        NoteStorage::new(storage_values)
            .expect("number of storage items should not exceed max storage items")
    }
}

/// Deserializes [`SwapNoteStorage`] from a slice of exactly 11 [`Felt`]s.
impl TryFrom<&[Felt]> for SwapNoteStorage {
    type Error = NoteError;

    fn try_from(note_storage: &[Felt]) -> Result<Self, Self::Error> {
        if note_storage.len() != Self::NUM_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: Self::NUM_ITEMS,
                actual: note_storage.len(),
            });
        }

        // [0..7] = requested asset (key + value)
        let key = Word::new([note_storage[0], note_storage[1], note_storage[2], note_storage[3]]);
        let value = Word::new([note_storage[4], note_storage[5], note_storage[6], note_storage[7]]);
        let requested_asset = Asset::from_key_value_words(key, value)
            .map_err(|e| NoteError::other_with_source("failed to parse requested asset", e))?;

        // [8] = payback_note_type
        let payback_note_type = NoteType::try_from(
            u8::try_from(note_storage[8].as_canonical_u64())
                .map_err(|_| NoteError::other("payback_note_type exceeds u8"))?,
        )
        .map_err(|e| NoteError::other_with_source("failed to parse payback note type", e))?;

        // [9..10] = creator account ID (prefix, suffix)
        let creator_account_id = AccountId::try_from_elements(note_storage[10], note_storage[9])
            .map_err(|e| NoteError::other_with_source("failed to parse creator account ID", e))?;

        Ok(Self {
            payback_note_type,
            requested_asset,
            creator_account_id,
        })
    }
}

/// Returns the P2ID payback serial derived from a SWAP note's own serial number.
///
/// The SWAP MASM script computes the payback's serial by incrementing the least significant
/// element of the SWAP serial. Creators can recompute this offline to track or consume the
/// payback note after the SWAP is filled.
pub fn payback_serial_from_swap(swap_serial: Word) -> Word {
    let elements = swap_serial.as_elements();
    Word::new([elements[0] + ONE, elements[1], elements[2], elements[3]])
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use miden_protocol::account::{AccountIdVersion, AccountStorageMode, AccountType};
    use miden_protocol::asset::{FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
    use miden_protocol::note::{NoteStorage, NoteType};
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    };

    use super::*;

    fn fungible_faucet() -> AccountId {
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap()
    }

    fn non_fungible_faucet() -> AccountId {
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into().unwrap()
    }

    fn fungible_asset() -> Asset {
        Asset::Fungible(FungibleAsset::new(fungible_faucet(), 1000).unwrap())
    }

    fn non_fungible_asset() -> Asset {
        let details =
            NonFungibleAssetDetails::new(non_fungible_faucet(), vec![0xaa, 0xbb]).unwrap();
        Asset::NonFungible(NonFungibleAsset::new(&details).unwrap())
    }

    fn dummy_creator_id() -> AccountId {
        AccountId::dummy(
            [1; 15],
            AccountIdVersion::Version1,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Public,
        )
    }

    #[test]
    fn swap_note_storage_round_trip_fungible() {
        let creator = dummy_creator_id();
        let storage = SwapNoteStorage::new(fungible_asset(), NoteType::Private, creator);

        let note_storage = NoteStorage::from(storage.clone());
        assert_eq!(note_storage.num_items() as usize, SwapNoteStorage::NUM_ITEMS);
        assert_eq!(storage.payback_note_type(), NoteType::Private);
        assert_eq!(storage.requested_asset(), fungible_asset());
        assert_eq!(storage.creator_account_id(), creator);
    }

    #[test]
    fn swap_note_storage_round_trip_non_fungible_public() {
        let creator = dummy_creator_id();
        let storage = SwapNoteStorage::new(non_fungible_asset(), NoteType::Public, creator);

        let note_storage = NoteStorage::from(storage.clone());
        assert_eq!(note_storage.num_items() as usize, SwapNoteStorage::NUM_ITEMS);
        assert_eq!(storage.payback_note_type(), NoteType::Public);
        assert_eq!(storage.requested_asset(), non_fungible_asset());
        assert_eq!(storage.creator_account_id(), creator);
    }

    #[test]
    fn swap_note_storage_try_from_round_trip() {
        let original = SwapNoteStorage::new(fungible_asset(), NoteType::Public, dummy_creator_id());
        let note_storage = NoteStorage::from(original.clone());

        let parsed =
            SwapNoteStorage::try_from(note_storage.items()).expect("round trip should succeed");

        assert_eq!(parsed, original);
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
                    AccountIdVersion::Version1,
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
                        AccountIdVersion::Version1,
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
        assert_eq!((actual_tag.as_u32() >> 31) as u8, note_type as u8, "note type should match");
        // Check the 8 bits of the first script root byte.
        assert_eq!(
            (actual_tag.as_u32() >> 23) as u8,
            SwapNote::script_root().as_bytes()[0],
            "swap script root byte 0 should match"
        );
        // Extract the 7 bits of the second script root byte and shift for comparison.
        assert_eq!(
            ((actual_tag.as_u32() & 0b00000000_01111111_00000000_00000000) >> 16) as u8,
            SwapNote::script_root().as_bytes()[1] >> 1,
            "swap script root byte 1 should match with the highest bit set to zero"
        );
    }
}
