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
    /// See [`SwapPayback`] for how the two payback modes shape the SWAP note storage.
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

        let serial_num = rng.draw_word();

        // The payback recipient is P2ID(sender) with serial = swap_serial + 1, in both modes.
        // `create` defaults the payback target to the sender; the storage and script support
        // any target (see https://github.com/0xMiden/protocol/issues/2950).
        let payback_serial_num = payback_serial_from_swap(serial_num);
        let payback_recipient = P2idNoteStorage::new(sender).into_recipient(payback_serial_num);
        let payback_assets = NoteAssets::new(vec![requested_asset])?;
        let payback_note = NoteDetails::new(payback_assets, payback_recipient.clone());

        let payback_tag = NoteTag::with_account_target(sender);
        let swap_storage = match payback_note_type {
            NoteType::Private => SwapNoteStorage::new_private(
                requested_asset,
                payback_recipient.digest(),
                payback_tag,
            ),
            NoteType::Public => SwapNoteStorage::new_public(requested_asset, sender, payback_tag),
        };

        let recipient = swap_storage.into_recipient(serial_num);

        // build the tag for the SWAP use case
        let tag = Self::build_tag(swap_note_type, &offered_asset, &requested_asset);

        // build the outgoing note
        let metadata = PartialNoteMetadata::new(sender, swap_note_type).with_tag(tag);
        let assets = NoteAssets::new(vec![offered_asset])?;
        let note = Note::with_attachments(assets, metadata, recipient, swap_note_attachments);

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
/// Maps to the 16-element [`NoteStorage`] layout consumed by the on-chain MASM script:
///
/// | Slot      | Field |
/// |-----------|-------|
/// | `[0..7]`  | Requested asset (key + value) |
/// | `[8..11]` | Payback recipient digest (private mode; zero in public mode) |
/// | `[12]`    | Payback note type |
/// | `[13]`    | Payback note tag |
/// | `[14]`    | Payback target account ID prefix (public mode; zero in private mode) |
/// | `[15]`    | Payback target account ID suffix (public mode; zero in private mode) |
///
/// See [`SwapPayback`] for the rationale behind the per-mode shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapNoteStorage {
    requested_asset: Asset,
    payback_tag: NoteTag,
    payback: SwapPayback,
}

/// Mode-specific payback data embedded in [`SwapNoteStorage`].
///
/// The variant determines how the payback recipient is materialized at consume time:
/// - [`SwapPayback::Private`] embeds the precomputed P2ID recipient digest as an opaque value, so
///   the SWAP storage alone does not reveal who the payback targets.
/// - [`SwapPayback::Public`] embeds the payback target account id in plaintext, so any consumer can
///   reconstruct the payback recipient at consume time via `p2id::new`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapPayback {
    Private {
        /// Precomputed P2ID recipient digest for the payback note.
        recipient: Word,
    },
    Public {
        /// Account ID that will receive the payback note.
        payback_target_id: AccountId,
    },
}

impl SwapNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the SWAP note.
    pub const NUM_ITEMS: usize = 16;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new SWAP note storage for a private payback.
    pub fn new_private(
        requested_asset: Asset,
        payback_recipient: Word,
        payback_tag: NoteTag,
    ) -> Self {
        Self {
            requested_asset,
            payback_tag,
            payback: SwapPayback::Private { recipient: payback_recipient },
        }
    }

    /// Creates a new SWAP note storage for a public payback.
    pub fn new_public(
        requested_asset: Asset,
        payback_target_id: AccountId,
        payback_tag: NoteTag,
    ) -> Self {
        Self {
            requested_asset,
            payback_tag,
            payback: SwapPayback::Public { payback_target_id },
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the payback note type implied by the payback variant.
    pub fn payback_note_type(&self) -> NoteType {
        match self.payback {
            SwapPayback::Private { .. } => NoteType::Private,
            SwapPayback::Public { .. } => NoteType::Public,
        }
    }

    /// Returns the requested asset.
    pub fn requested_asset(&self) -> Asset {
        self.requested_asset
    }

    /// Returns the tag attached to the payback note.
    pub fn payback_tag(&self) -> NoteTag {
        self.payback_tag
    }

    /// Returns the payback variant of this storage.
    pub fn payback(&self) -> &SwapPayback {
        &self.payback
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

        // [0..7] requested asset
        storage_values.extend_from_slice(&storage.requested_asset.as_elements());

        match storage.payback {
            SwapPayback::Private { recipient } => {
                // [8..11] payback recipient digest
                storage_values.extend_from_slice(recipient.as_elements());
                // [12] payback note type
                storage_values.push(Felt::from(NoteType::Private.as_u8()));
                // [13] payback tag
                storage_values.push(Felt::from(storage.payback_tag.as_u32()));
                // [14..15] payback target id (zero in private mode)
                storage_values.extend_from_slice(&[Felt::ZERO; 2]);
            },
            SwapPayback::Public { payback_target_id } => {
                // [8..11] payback recipient (zero in public mode)
                storage_values.extend_from_slice(&[Felt::ZERO; 4]);
                // [12] payback note type
                storage_values.push(Felt::from(NoteType::Public.as_u8()));
                // [13] payback tag
                storage_values.push(Felt::from(storage.payback_tag.as_u32()));
                // [14..15] payback target id (prefix, suffix)
                storage_values.push(payback_target_id.prefix().as_felt());
                storage_values.push(payback_target_id.suffix());
            },
        }

        NoteStorage::new(storage_values)
            .expect("number of storage items should not exceed max storage items")
    }
}

/// Deserializes [`SwapNoteStorage`] from a slice of exactly 16 [`Felt`]s.
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

        // [12] = payback_note_type
        let payback_note_type = NoteType::try_from(
            u8::try_from(note_storage[12].as_canonical_u64())
                .map_err(|_| NoteError::other("payback_note_type exceeds u8"))?,
        )
        .map_err(|e| NoteError::other_with_source("failed to parse payback note type", e))?;

        // [13] = payback tag
        let payback_tag_u32 = u32::try_from(note_storage[13].as_canonical_u64())
            .map_err(|_| NoteError::other("SWAP payback_tag exceeds u32"))?;
        let payback_tag = NoteTag::new(payback_tag_u32);

        let payback = match payback_note_type {
            NoteType::Private => {
                // [14..15] must be zero so a private SWAP cannot leak a payback target id.
                if note_storage[14].as_canonical_u64() != 0
                    || note_storage[15].as_canonical_u64() != 0
                {
                    return Err(NoteError::other(
                        "SWAP private payback must have payback target id slots cleared",
                    ));
                }

                // [8..11] payback recipient digest
                let recipient = Word::new([
                    note_storage[8],
                    note_storage[9],
                    note_storage[10],
                    note_storage[11],
                ]);

                SwapPayback::Private { recipient }
            },
            NoteType::Public => {
                // [8..11] must be zero so the storage shape is unambiguous.
                if note_storage[8..=11].iter().any(|f| f.as_canonical_u64() != 0) {
                    return Err(NoteError::other(
                        "SWAP public payback must have recipient slots cleared",
                    ));
                }

                let payback_target_id = AccountId::try_from_elements(
                    note_storage[15],
                    note_storage[14],
                )
                .map_err(|e| {
                    NoteError::other_with_source("failed to parse payback target account ID", e)
                })?;

                SwapPayback::Public { payback_target_id }
            },
        };

        Ok(Self { requested_asset, payback_tag, payback })
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

    use miden_protocol::account::{AccountIdVersion, AccountType};
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
        let details = NonFungibleAssetDetails::new(non_fungible_faucet(), vec![0xaa, 0xbb]);
        Asset::NonFungible(NonFungibleAsset::new(&details))
    }

    fn dummy_target_id() -> AccountId {
        AccountId::dummy([1; 15], AccountIdVersion::Version1, AccountType::Public)
    }

    fn dummy_recipient_digest() -> Word {
        Word::new([Felt::from(7u32), Felt::from(11u32), Felt::from(13u32), Felt::from(17u32)])
    }

    fn dummy_payback_tag() -> NoteTag {
        NoteTag::new(0xabcd1234)
    }

    #[test]
    fn swap_note_storage_round_trip_fungible_private() {
        let storage = SwapNoteStorage::new_private(
            fungible_asset(),
            dummy_recipient_digest(),
            dummy_payback_tag(),
        );

        let note_storage = NoteStorage::from(storage.clone());
        assert_eq!(note_storage.num_items() as usize, SwapNoteStorage::NUM_ITEMS);
        assert_eq!(storage.payback_note_type(), NoteType::Private);
        assert_eq!(storage.requested_asset(), fungible_asset());
        assert_eq!(storage.payback_tag(), dummy_payback_tag());
        match storage.payback() {
            SwapPayback::Private { recipient } => {
                assert_eq!(*recipient, dummy_recipient_digest());
            },
            SwapPayback::Public { .. } => panic!("expected private payback"),
        }
    }

    #[test]
    fn swap_note_storage_round_trip_non_fungible_public() {
        let target = dummy_target_id();
        let storage =
            SwapNoteStorage::new_public(non_fungible_asset(), target, dummy_payback_tag());

        let note_storage = NoteStorage::from(storage.clone());
        assert_eq!(note_storage.num_items() as usize, SwapNoteStorage::NUM_ITEMS);
        assert_eq!(storage.payback_note_type(), NoteType::Public);
        assert_eq!(storage.requested_asset(), non_fungible_asset());
        assert_eq!(storage.payback_tag(), dummy_payback_tag());
        match storage.payback() {
            SwapPayback::Public { payback_target_id } => {
                assert_eq!(*payback_target_id, target);
            },
            SwapPayback::Private { .. } => panic!("expected public payback"),
        }
    }

    #[test]
    fn swap_note_storage_try_from_round_trip_public() {
        let original =
            SwapNoteStorage::new_public(fungible_asset(), dummy_target_id(), dummy_payback_tag());
        let note_storage = NoteStorage::from(original.clone());

        let parsed =
            SwapNoteStorage::try_from(note_storage.items()).expect("round trip should succeed");

        assert_eq!(parsed, original);
    }

    #[test]
    fn swap_note_storage_try_from_round_trip_private() {
        let original = SwapNoteStorage::new_private(
            fungible_asset(),
            dummy_recipient_digest(),
            dummy_payback_tag(),
        );
        let note_storage = NoteStorage::from(original.clone());

        let parsed =
            SwapNoteStorage::try_from(note_storage.items()).expect("round trip should succeed");

        assert_eq!(parsed, original);
    }

    #[test]
    fn swap_note_storage_private_rejects_dirty_target_slots() {
        let mut items: Vec<Felt> = NoteStorage::from(SwapNoteStorage::new_private(
            fungible_asset(),
            dummy_recipient_digest(),
            dummy_payback_tag(),
        ))
        .items()
        .to_vec();

        // Inject a non-zero target prefix in the slot that must stay clear for private payback.
        items[14] = Felt::from(1u32);
        assert!(SwapNoteStorage::try_from(items.as_slice()).is_err());
    }

    #[test]
    fn swap_note_storage_public_rejects_dirty_private_slots() {
        let mut items: Vec<Felt> = NoteStorage::from(SwapNoteStorage::new_public(
            fungible_asset(),
            dummy_target_id(),
            dummy_payback_tag(),
        ))
        .items()
        .to_vec();

        // Inject a non-zero recipient felt in the slot that must stay clear for public payback.
        items[8] = Felt::from(1u32);
        assert!(SwapNoteStorage::try_from(items.as_slice()).is_err());
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
                    AccountType::Public,
                ),
                2500,
            )
            .unwrap(),
        );

        let requested_asset =
            Asset::NonFungible(NonFungibleAsset::new(&NonFungibleAssetDetails::new(
                AccountId::dummy(
                    non_fungible_faucet_id_bytes,
                    AccountIdVersion::Version1,
                    AccountType::Public,
                ),
                vec![0xaa, 0xbb, 0xcc, 0xdd],
            )));

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
