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
use crate::note::costs::{NoteConsumptionCost, SWAP_CONSUMPTION_CYCLES};
use crate::note::{P2idNote, P2idNoteStorage};

// NOTE SCRIPT
// ================================================================================================

/// Path to the SWAP note script procedure in the standards library.
const SWAP_SCRIPT_PATH: &str = "::miden::standards::notes::swap::main";

// Initialize the SWAP note script only once
static SWAP_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(SWAP_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains SWAP note script procedure")
});

// SWAP NOTE
// ================================================================================================

/// A SWAP note: offers `offered_asset` in exchange for `requested_asset`.
///
/// Any account willing to pay the requested asset can consume the note: the consumer receives the
/// offered asset and, in the same transaction, the script creates a P2ID payback note carrying the
/// requested asset back to the swap creator. [`SwapNote::payback_note_details`] returns that
/// payback note's [`NoteDetails`], which the creator needs to track and consume it once the swap is
/// filled.
///
/// Construct one with the [builder](SwapNote::builder), which defaults both the note type and the
/// payback note type to [`NoteType::Private`] and adds no attachments; convert it into a protocol
/// [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapNote {
    sender: AccountId,
    offered_asset: Asset,
    serial_number: Word,
    note_type: NoteType,
    storage: SwapNoteStorage,
    attachments: NoteAttachments,
}

#[bon::bon]
impl SwapNote {
    /// Builds a new [`SwapNote`].
    ///
    /// The payback note targets the `sender`; the storage and script support any target. See
    /// [`SwapPayback`] for how `payback_note_type` shapes the SWAP note storage.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The requested asset is the same as the offered asset.
    /// - The attachments exceed their protocol limit (see [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        #[builder(into)] offered_asset: Asset,
        #[builder(into)] requested_asset: Asset,
        /// Must be drawn from a cryptographically secure RNG, e.g. via the builder's
        /// `generate_serial_number`: two SWAP notes sharing a serial number derive the same
        /// payback note, of which only one can be created.
        serial_number: Word,
        /// Defaults to [`NoteType::Private`], which only the counterparties the creator shares
        /// the note with can fill. A SWAP note offered to the network at large must be set to
        /// [`NoteType::Public`] explicitly.
        #[builder(default)]
        note_type: NoteType,
        /// Defaults to [`NoteType::Private`], so the payback note's details are known only to the
        /// creator, who needs the [`NoteDetails`] returned by [`SwapNote::payback_note_details`]
        /// to consume it. Set to [`NoteType::Public`] to have the network store those
        /// details instead.
        #[builder(default)]
        payback_note_type: NoteType,
    ) -> Result<Self, NoteError> {
        if requested_asset == offered_asset {
            return Err(NoteError::other("requested asset same as offered asset"));
        }

        let attachments = NoteAttachments::new(attachments)?;

        let payback_tag = NoteTag::with_account_target(sender);

        let storage = match payback_note_type {
            NoteType::Private => SwapNoteStorage::new_private(
                requested_asset,
                Self::payback_recipient(sender, serial_number).digest(),
                payback_tag,
            ),
            NoteType::Public => SwapNoteStorage::new_public(requested_asset, sender, payback_tag),
        };

        Ok(Self {
            sender,
            offered_asset,
            serial_number,
            note_type,
            storage,
            attachments,
        })
    }
}

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

    /// Returns the account ID of the note's sender, which is also the payback note's target.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the asset offered by the note's sender.
    pub fn offered_asset(&self) -> Asset {
        self.offered_asset
    }

    /// Returns the asset the consumer must pay to claim the offered asset.
    pub fn requested_asset(&self) -> Asset {
        self.storage().requested_asset()
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the note's type.
    pub fn note_type(&self) -> NoteType {
        self.note_type
    }

    /// Returns the type of the payback note created when the swap is filled.
    pub fn payback_note_type(&self) -> NoteType {
        self.storage().payback_note_type()
    }

    /// Returns the attachments carried by the note.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }

    /// Returns the note's storage.
    pub fn storage(&self) -> &SwapNoteStorage {
        &self.storage
    }

    /// Returns the [`NoteDetails`] of the payback note that the SWAP script creates when the note
    /// is consumed.
    pub fn payback_note_details(&self) -> NoteDetails {
        let assets = NoteAssets::new(vec![self.requested_asset()])
            .expect("a single asset never exceeds the note asset limit");

        NoteDetails::new(assets, Self::payback_recipient(self.sender, self.serial_number))
    }

    // ASSOCIATED FUNCTIONS
    // --------------------------------------------------------------------------------------------

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
    pub fn create_tag(
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

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the payback note's recipient, which is P2ID(sender) in both payback modes.
    fn payback_recipient(sender: AccountId, serial_number: Word) -> NoteRecipient {
        P2idNoteStorage::new(sender).into_recipient(payback_serial_from_swap(serial_number))
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: swap_note_builder::State> SwapNoteBuilder<S> {
    /// Adds a single attachment to the note.
    pub fn attachment(mut self, attachment: impl Into<NoteAttachment>) -> Self {
        self.attachments.push(attachment.into());
        self
    }

    /// Adds multiple attachments to the note.
    pub fn attachments(
        mut self,
        attachments: impl IntoIterator<Item = impl Into<NoteAttachment>>,
    ) -> Self {
        self.attachments.extend(attachments.into_iter().map(Into::into));
        self
    }
}

impl<S: swap_note_builder::State> SwapNoteBuilder<S>
where
    S::SerialNumber: swap_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> SwapNoteBuilder<swap_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<SwapNote> for Note {
    fn from(note: SwapNote) -> Self {
        let SwapNote {
            sender,
            offered_asset,
            serial_number,
            note_type,
            storage,
            attachments,
        } = note;

        let tag = SwapNote::create_tag(note_type, &offered_asset, &storage.requested_asset());
        let metadata = PartialNoteMetadata::new(sender, note_type).with_tag(tag);
        let recipient = storage.into_recipient(serial_number);

        let assets = NoteAssets::new(vec![offered_asset])
            .expect("a single asset never exceeds the note asset limit");

        Note::with_attachments(assets, metadata, recipient, attachments)
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
/// | `[14]`    | Payback target account ID suffix (public mode; zero in private mode) |
/// | `[15]`    | Payback target account ID prefix (public mode; zero in private mode) |
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
///   reconstruct the payback recipient at consume time via `p2id::prepare_note`.
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
                // [14..15] payback target id (suffix, prefix)
                storage_values.push(payback_target_id.suffix());
                storage_values.push(payback_target_id.prefix().as_felt());
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
        let requested_asset = Asset::from_id_and_value_words(key, value)
            .map_err(|err| NoteError::other_with_source("failed to parse requested asset", err))?;

        // [12] = payback_note_type
        let payback_note_type = NoteType::try_from(
            u8::try_from(note_storage[12].as_canonical_u64())
                .map_err(|_| NoteError::other("payback_note_type exceeds u8"))?,
        )
        .map_err(|err| NoteError::other_with_source("failed to parse payback note type", err))?;

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
                if note_storage[8..=11].iter().any(|felt| felt.as_canonical_u64() != 0) {
                    return Err(NoteError::other(
                        "SWAP public payback must have recipient slots cleared",
                    ));
                }

                let payback_target_id = AccountId::try_from_elements(
                    note_storage[14],
                    note_storage[15],
                )
                .map_err(|err| {
                    NoteError::other_with_source("failed to parse payback target account ID", err)
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

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for SwapNote {
    fn consumption_cycles() -> u32 {
        SWAP_CONSUMPTION_CYCLES
    }

    /// Filling a SWAP note creates the P2ID payback note for the swap creator.
    fn created_notes() -> Vec<NoteScriptRoot> {
        vec![P2idNote::script_root()]
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use assert_matches::assert_matches;
    use miden_protocol::account::{AccountIdVersion, AccountType, AssetCallbackFlag};
    use miden_protocol::asset::{FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::note::{NoteStorage, NoteType};
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    };
    use rstest::rstest;

    use super::*;
    use crate::note::{NetworkAccountTarget, P2idNote};

    fn fungible_faucet() -> AccountId {
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap()
    }

    fn non_fungible_faucet() -> AccountId {
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into().unwrap()
    }

    fn fungible_asset() -> Asset {
        Asset::from(FungibleAsset::new(fungible_faucet(), 1000).unwrap())
    }

    fn non_fungible_asset() -> Asset {
        let details = NonFungibleAssetDetails::new(non_fungible_faucet(), vec![0xaa, 0xbb]);
        Asset::from(NonFungibleAsset::new(&details))
    }

    fn dummy_target_id() -> AccountId {
        AccountId::builder().account_type(AccountType::Private).build_with_seed([1; 32])
    }

    fn dummy_recipient_digest() -> Word {
        Word::new([Felt::from(7u32), Felt::from(11u32), Felt::from(13u32), Felt::from(17u32)])
    }

    fn dummy_payback_tag() -> NoteTag {
        NoteTag::new(0xabcd1234)
    }

    /// The built note must carry the offered asset and a storage that encodes the payback
    /// configuration, while the payback note details target the sender with the serial number the
    /// MASM script derives.
    #[rstest]
    #[case::private_payback(NoteType::Private)]
    #[case::public_payback(NoteType::Public)]
    fn swap_note_builder(#[case] payback_note_type: NoteType) -> anyhow::Result<()> {
        let sender = dummy_target_id();
        let attachment = NoteAttachment::with_word(
            NetworkAccountTarget::ATTACHMENT_SCHEME,
            dummy_recipient_digest(),
        );
        let swap_note_type = NoteType::Public;
        let swap_note = SwapNote::builder()
            .sender(sender)
            .offered_asset(fungible_asset())
            .requested_asset(non_fungible_asset())
            .note_type(swap_note_type)
            .payback_note_type(payback_note_type)
            .attachment(attachment.clone())
            .generate_serial_number(&mut RandomCoin::new(Word::from([1, 2, 3, 4u32])))
            .build()?;

        let serial_number = swap_note.serial_number();
        let storage = swap_note.storage().clone();
        let payback_note = swap_note.payback_note_details();
        let note = Note::from(swap_note);

        assert_eq!(note.metadata().sender(), sender);
        assert_eq!(note.metadata().note_type(), swap_note_type);
        assert_eq!(
            note.metadata().tag(),
            SwapNote::create_tag(swap_note_type, &fungible_asset(), &non_fungible_asset())
        );
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.assets().iter().next(), Some(&fungible_asset()));
        assert_eq!(note.attachments().get(0), Some(&attachment));
        assert_eq!(note.recipient().script().root(), SwapNote::script_root());
        assert_eq!(
            SwapNoteStorage::try_from(note.recipient().storage().items())?,
            storage,
            "the note's storage must match the one derived from the SWAP note"
        );
        assert_eq!(storage.payback_tag(), NoteTag::with_account_target(sender));

        assert_eq!(payback_note.assets().iter().next(), Some(&non_fungible_asset()));
        assert_eq!(payback_note.recipient().serial_num(), payback_serial_from_swap(serial_number));
        assert_eq!(payback_note.recipient().script().root(), P2idNote::script_root());

        // Both payback modes must resolve to the payback note the creator was handed: privately
        // through the embedded recipient digest, publicly by reconstructing it from the target ID.
        match (payback_note_type, storage.payback()) {
            (NoteType::Private, SwapPayback::Private { recipient }) => {
                assert_eq!(*recipient, payback_note.recipient().digest());
            },
            (NoteType::Public, SwapPayback::Public { payback_target_id }) => {
                assert_eq!(*payback_target_id, sender);
            },
            (note_type, payback) => panic!("payback {payback:?} does not match {note_type:?}"),
        }

        Ok(())
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

        let parsed =
            SwapNoteStorage::try_from(note_storage.items()).expect("round trip should succeed");
        assert_eq!(parsed, storage);
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

        let parsed =
            SwapNoteStorage::try_from(note_storage.items()).expect("round trip should succeed");
        assert_eq!(parsed, storage);
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

        // Inject a non-zero target suffix in the slot that must stay clear for private payback.
        items[14] = Felt::from(1u32);
        let err = SwapNoteStorage::try_from(items.as_slice())
            .expect_err("private payback with a dirty target slot must be rejected");
        assert_matches!(
            err,
            NoteError::Other { error_msg, .. }
                if error_msg == "SWAP private payback must have payback target id slots cleared".into()
        );
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
        let err = SwapNoteStorage::try_from(items.as_slice())
            .expect_err("public payback with a dirty recipient slot must be rejected");
        assert_matches!(
            err,
            NoteError::Other { error_msg, .. }
                if error_msg == "SWAP public payback must have recipient slots cleared".into()
        );
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

        let offered_asset = Asset::from(
            FungibleAsset::new(
                AccountId::dummy(
                    fungible_faucet_id_bytes,
                    AccountIdVersion::Version1,
                    AccountType::Public,
                    AssetCallbackFlag::Disabled,
                ),
                2500,
            )
            .unwrap(),
        );

        let requested_asset = Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(
            AccountId::dummy(
                non_fungible_faucet_id_bytes,
                AccountIdVersion::Version1,
                AccountType::Public,
                AssetCallbackFlag::Disabled,
            ),
            vec![0xaa, 0xbb, 0xcc, 0xdd],
        )));

        // The fungible ID starts with 0xcdb1.
        // The non fungible ID starts with 0xabec.
        // The expected tag payload is thus 0xcdab.
        let expected_asset_pair = 0xcdab;

        let note_type = NoteType::Public;
        let actual_tag = SwapNote::create_tag(note_type, &offered_asset, &requested_asset);

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
