use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::{Asset, AssetAmount};
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentScheme,
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
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS, ONE, Word};
use rand::{Rng, RngExt};

use crate::StandardsLib;
use crate::note::costs::{NoteConsumptionCost, SWAP_CONSUMPTION_CYCLES};
use crate::note::{NumStorageItems, P2idNote, P2idNoteStorage};

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
/// offered asset and, in the same transaction, the script creates a payback note carrying the
/// requested asset. [`SwapNote::payback_note_details`] returns that payback note's
/// [`NoteDetails`], which its receiver needs to track and consume it once the swap is filled.
///
/// Construct one with the [builder](SwapNote::builder), which defaults both the note type and the
/// payback note type to [`NoteType::Private`], the payback to a P2ID note for the sender and adds
/// no attachments; convert it into a protocol [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapNote {
    sender: AccountId,
    offered_asset: Asset,
    serial_number: Word,
    note_type: NoteType,
    payback_recipient: NoteRecipient,
    storage: SwapNoteStorage,
    attachments: NoteAttachments,
}

#[bon::bon]
impl SwapNote {
    /// Builds a new [`SwapNote`].
    ///
    /// See [`SwapPayback`] for how `payback_note_type` shapes the SWAP note storage.
    ///
    /// When the payback note is sealed, the `on_before_note_sealed` callback of the requested
    /// asset's faucet can append attachments after the payback attachments, which take the payback
    /// note's remaining attachment slots.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The requested asset is the same as the offered asset.
    /// - Either the offered or the requested asset is a zero-amount fungible asset.
    /// - The attachments or payback attachments exceed their protocol limit (see
    ///   [`NoteAttachments::new`]).
    /// - The payback configuration does not fit into the note storage.
    #[builder]
    pub fn new(
        #[builder(field)] attachments: Vec<NoteAttachment>,
        #[builder(field)] payback_attachments: Vec<NoteAttachment>,
        sender: AccountId,
        #[builder(into)] offered_asset: Asset,
        #[builder(into)] requested_asset: Asset,
        /// Must be drawn from a cryptographically secure RNG, e.g. via the builder's
        /// `generate_serial_number`: two SWAP notes sharing a serial number derive the same
        /// default payback note, of which only one can be created.
        serial_number: Word,
        /// Defaults to [`NoteType::Private`], which only the counterparties the creator shares
        /// the note with can fill. A SWAP note offered to the network at large must be set to
        /// [`NoteType::Public`] explicitly.
        #[builder(default)]
        note_type: NoteType,
        /// Defaults to [`NoteType::Private`], so the payback note's details are known only to the
        /// parties that hold the [`NoteDetails`] returned by [`SwapNote::payback_note_details`].
        /// Set to [`NoteType::Public`] to have the network store those details instead.
        #[builder(default)]
        payback_note_type: NoteType,
        /// Defaults to a P2ID note for the `sender`, with the serial number derived by
        /// [`payback_serial_from_swap`].
        payback_recipient: Option<NoteRecipient>,
        /// Defaults to a tag targeting the `sender`.
        payback_tag: Option<NoteTag>,
    ) -> Result<Self, NoteError> {
        if requested_asset == offered_asset {
            return Err(NoteError::other("requested asset same as offered asset"));
        }

        let is_zero =
            |asset: &Asset| asset.as_fungible().is_some_and(|a| a.amount() == AssetAmount::ZERO);
        if is_zero(&offered_asset) {
            return Err(NoteError::other("offered asset must be non-zero"));
        }
        if is_zero(&requested_asset) {
            return Err(NoteError::other("requested asset must be non-zero"));
        }

        let attachments = NoteAttachments::new(attachments)?;
        let payback_attachments = NoteAttachments::new(payback_attachments)?;

        let payback_recipient = payback_recipient.unwrap_or_else(|| {
            P2idNoteStorage::new(sender).into_recipient(payback_serial_from_swap(serial_number))
        });
        let payback_tag = payback_tag.unwrap_or_else(|| NoteTag::with_account_target(sender));

        let storage = match payback_note_type {
            NoteType::Private => SwapNoteStorage::new_private(
                requested_asset,
                payback_recipient.digest(),
                payback_tag,
                payback_attachments,
            )?,
            NoteType::Public => SwapNoteStorage::new_public(
                requested_asset,
                payback_recipient.clone(),
                payback_tag,
                payback_attachments,
            )?,
        };

        Ok(Self {
            sender,
            offered_asset,
            serial_number,
            note_type,
            payback_recipient,
            storage,
            attachments,
        })
    }
}

impl SwapNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The numbers of storage items the SWAP note script accepts.
    ///
    /// The storage holds at least [`SwapNoteStorage::MIN_NUM_ITEMS`] and grows with the payback
    /// storage and attachments.
    pub const NUM_STORAGE_ITEMS: NumStorageItems = NumStorageItems::Range {
        min: SwapNoteStorage::MIN_NUM_ITEMS,
        max: MAX_NOTE_STORAGE_ITEMS,
    };

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

    /// Returns the account ID of the note's sender.
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

    /// Returns the attachments of the payback note created when the swap is filled.
    pub fn payback_attachments(&self) -> &NoteAttachments {
        self.storage().payback_attachments()
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

        NoteDetails::new(assets, self.payback_recipient.clone())
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

    /// Adds a single attachment to the payback note.
    pub fn payback_attachment(mut self, attachment: impl Into<NoteAttachment>) -> Self {
        self.payback_attachments.push(attachment.into());
        self
    }

    /// Adds multiple attachments to the payback note.
    pub fn payback_attachments(
        mut self,
        attachments: impl IntoIterator<Item = impl Into<NoteAttachment>>,
    ) -> Self {
        self.payback_attachments.extend(attachments.into_iter().map(Into::into));
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
        rng: &mut impl Rng,
    ) -> SwapNoteBuilder<swap_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.random())
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
            payback_recipient: _,
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
/// Maps to the variable-length [`NoteStorage`] layout consumed by the on-chain MASM script:
///
/// | Slot       | Field |
/// |------------|-------|
/// | `[0..8]`   | Requested asset (key + value) |
/// | `[8..12]`  | Payback recipient digest (private) or payback script root (public) |
/// | `[12..16]` | Payback serial number (public; zero in private mode) |
/// | `[16]`     | Payback note type |
/// | `[17]`     | Payback note tag |
/// | `[18]`     | Number of payback storage items (public; zero in private mode) |
/// | `[19]`     | Number of payback attachments |
/// | `[20..20+num_payback_storage_items]` | Payback storage (public; empty in private mode) |
/// | up to `ATTACHMENTS_START` | Zero padding to the next word boundary |
/// | `[ATTACHMENTS_START..]` | Attachments: a `[scheme, num_words, 0, 0]` header, then the words |
///
/// Every region is word-aligned, so the script passes the payback storage and attachments to the
/// APIs straight from the loaded storage. See [`SwapPayback`] for the per-mode shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapNoteStorage {
    requested_asset: Asset,
    payback_tag: NoteTag,
    payback_attachments: NoteAttachments,
    payback: SwapPayback,
}

/// Mode-specific payback data embedded in [`SwapNoteStorage`].
///
/// The variant determines how the payback recipient is materialized at consume time:
/// - [`SwapPayback::Private`] embeds the precomputed recipient digest as an opaque value, so the
///   SWAP storage alone does not reveal the payback note.
/// - [`SwapPayback::Public`] embeds the recipient's script root, serial number and storage in
///   plaintext, so any consumer can build the payback recipient at consume time without further
///   advice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapPayback {
    Private {
        /// Precomputed recipient digest of the payback note.
        recipient: Word,
    },
    Public {
        /// Recipient of the payback note.
        ///
        /// When parsed from note storage, its script only references the script root (see
        /// [`NoteScript::from_root`]).
        recipient: NoteRecipient,
    },
}

impl SwapNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Minimum number of storage items of a SWAP note, i.e. the fixed header before the payback
    /// storage and attachments.
    pub const MIN_NUM_ITEMS: usize = 20;

    /// Offset of the requested asset.
    const REQUESTED_ASSET_OFFSET: usize = 0;
    /// Offset of the payback recipient digest (private) or script root (public).
    const PAYBACK_RECIPIENT_OFFSET: usize = 8;
    /// Offset of the payback serial number (public).
    const PAYBACK_SERIAL_NUM_OFFSET: usize = 12;
    const PAYBACK_NOTE_TYPE_OFFSET: usize = 16;
    const PAYBACK_TAG_OFFSET: usize = 17;
    const NUM_PAYBACK_STORAGE_ITEMS_OFFSET: usize = 18;
    const NUM_PAYBACK_ATTACHMENTS_OFFSET: usize = 19;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new SWAP note storage for a private payback.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage exceeds [`MAX_NOTE_STORAGE_ITEMS`].
    pub fn new_private(
        requested_asset: Asset,
        payback_recipient: Word,
        payback_tag: NoteTag,
        payback_attachments: NoteAttachments,
    ) -> Result<Self, NoteError> {
        Self::new(
            requested_asset,
            payback_tag,
            payback_attachments,
            SwapPayback::Private { recipient: payback_recipient },
        )
    }

    /// Creates a new SWAP note storage for a public payback.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage exceeds [`MAX_NOTE_STORAGE_ITEMS`].
    pub fn new_public(
        requested_asset: Asset,
        payback_recipient: NoteRecipient,
        payback_tag: NoteTag,
        payback_attachments: NoteAttachments,
    ) -> Result<Self, NoteError> {
        Self::new(
            requested_asset,
            payback_tag,
            payback_attachments,
            SwapPayback::Public { recipient: payback_recipient },
        )
    }

    fn new(
        requested_asset: Asset,
        payback_tag: NoteTag,
        payback_attachments: NoteAttachments,
        payback: SwapPayback,
    ) -> Result<Self, NoteError> {
        let storage = Self {
            requested_asset,
            payback_tag,
            payback_attachments,
            payback,
        };

        let num_items = storage.num_items();
        if num_items > MAX_NOTE_STORAGE_ITEMS {
            return Err(NoteError::TooManyStorageItems(num_items));
        }

        Ok(storage)
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

    /// Returns the attachments of the payback note.
    pub fn payback_attachments(&self) -> &NoteAttachments {
        &self.payback_attachments
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

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of storage items this storage encodes into.
    fn num_items(&self) -> usize {
        let payback_storage_len = match &self.payback {
            SwapPayback::Private { .. } => 0,
            SwapPayback::Public { recipient } => {
                usize::from(recipient.storage().num_items()).next_multiple_of(Word::NUM_ELEMENTS)
            },
        };
        let attachments_len: usize = self
            .payback_attachments
            .iter()
            .map(|attachment| {
                Word::NUM_ELEMENTS + usize::from(attachment.num_words()) * Word::NUM_ELEMENTS
            })
            .sum();

        Self::MIN_NUM_ITEMS + payback_storage_len + attachments_len
    }
}

impl From<SwapNoteStorage> for NoteStorage {
    fn from(storage: SwapNoteStorage) -> Self {
        let mut storage_values = Vec::with_capacity(storage.num_items());

        storage_values.extend_from_slice(&storage.requested_asset.as_elements());

        let payback_storage = match &storage.payback {
            SwapPayback::Private { recipient } => {
                storage_values.extend_from_slice(recipient.as_elements());
                storage_values.extend_from_slice(&[Felt::ZERO; Word::NUM_ELEMENTS]);
                [].as_slice()
            },
            SwapPayback::Public { recipient } => {
                storage_values.extend_from_slice(recipient.script().root().as_elements());
                storage_values.extend_from_slice(recipient.serial_num().as_elements());
                recipient.storage().items()
            },
        };

        storage_values.push(Felt::from(storage.payback_note_type().as_u8()));
        storage_values.push(Felt::from(storage.payback_tag.as_u32()));
        storage_values.push(Felt::from(payback_storage.len() as u32));
        storage_values.push(Felt::from(storage.payback_attachments.num_attachments()));

        storage_values.extend_from_slice(payback_storage);
        storage_values
            .resize(storage_values.len().next_multiple_of(Word::NUM_ELEMENTS), Felt::ZERO);

        for attachment in storage.payback_attachments.iter() {
            storage_values.extend_from_slice(&[
                Felt::from(attachment.attachment_scheme().as_u16()),
                Felt::from(attachment.num_words()),
                Felt::ZERO,
                Felt::ZERO,
            ]);
            storage_values.extend_from_slice(attachment.as_elements());
        }

        NoteStorage::new(storage_values)
            .expect("constructor should ensure the storage does not exceed max storage items")
    }
}

/// Deserializes [`SwapNoteStorage`] from its [`NoteStorage`] items.
impl TryFrom<&[Felt]> for SwapNoteStorage {
    type Error = NoteError;

    fn try_from(note_storage: &[Felt]) -> Result<Self, Self::Error> {
        if note_storage.len() < Self::MIN_NUM_ITEMS {
            return Err(NoteError::other("SWAP note storage is shorter than its header"));
        }

        let word_at = |offset: usize| -> Result<Word, NoteError> {
            let elements = note_storage
                .get(offset..offset + Word::NUM_ELEMENTS)
                .ok_or_else(|| NoteError::other("SWAP note storage is truncated"))?;
            Ok(Word::new(
                elements.try_into().expect("four elements should have been sliced off"),
            ))
        };
        let usize_at = |offset: usize, field: &str| -> Result<usize, NoteError> {
            usize::try_from(note_storage[offset].as_canonical_u64())
                .map_err(|_| NoteError::other(format!("SWAP {field} exceeds usize")))
        };

        let requested_asset = Asset::from_id_and_value_words(
            word_at(Self::REQUESTED_ASSET_OFFSET)?,
            word_at(Self::REQUESTED_ASSET_OFFSET + Word::NUM_ELEMENTS)?,
        )
        .map_err(|err| NoteError::other_with_source("failed to parse requested asset", err))?;

        let payback_note_type = NoteType::try_from(
            u8::try_from(note_storage[Self::PAYBACK_NOTE_TYPE_OFFSET].as_canonical_u64())
                .map_err(|_| NoteError::other("payback_note_type exceeds u8"))?,
        )
        .map_err(|err| NoteError::other_with_source("failed to parse payback note type", err))?;

        let payback_tag = u32::try_from(note_storage[Self::PAYBACK_TAG_OFFSET].as_canonical_u64())
            .map(NoteTag::new)
            .map_err(|_| NoteError::other("SWAP payback_tag exceeds u32"))?;

        let num_payback_storage_items =
            usize_at(Self::NUM_PAYBACK_STORAGE_ITEMS_OFFSET, "number of payback storage items")?;
        let num_payback_attachments =
            usize_at(Self::NUM_PAYBACK_ATTACHMENTS_OFFSET, "number of payback attachments")?;

        let payback_storage_end = Self::MIN_NUM_ITEMS
            .checked_add(num_payback_storage_items)
            .ok_or_else(|| NoteError::other("SWAP payback storage length overflows"))?;
        let padded_payback_storage = note_storage
            .get(Self::MIN_NUM_ITEMS..payback_storage_end.next_multiple_of(Word::NUM_ELEMENTS))
            .ok_or_else(|| NoteError::other("SWAP note storage is truncated"))?;
        let (payback_storage, payback_storage_padding) =
            padded_payback_storage.split_at(num_payback_storage_items);
        if payback_storage_padding.iter().any(|felt| *felt != Felt::ZERO) {
            return Err(NoteError::other("SWAP payback storage padding must be zero"));
        }

        let payback = match payback_note_type {
            NoteType::Private => {
                // The public-only slots must be clear so the storage shape is unambiguous.
                if word_at(Self::PAYBACK_SERIAL_NUM_OFFSET)? != Word::empty()
                    || num_payback_storage_items != 0
                {
                    return Err(NoteError::other(
                        "SWAP private payback must have the public payback slots cleared",
                    ));
                }

                SwapPayback::Private {
                    recipient: word_at(Self::PAYBACK_RECIPIENT_OFFSET)?,
                }
            },
            NoteType::Public => {
                let script_root =
                    NoteScriptRoot::from_raw(word_at(Self::PAYBACK_RECIPIENT_OFFSET)?);
                let storage = NoteStorage::new(payback_storage.to_vec())?;

                SwapPayback::Public {
                    recipient: NoteRecipient::new(
                        word_at(Self::PAYBACK_SERIAL_NUM_OFFSET)?,
                        NoteScript::from_root(script_root),
                        storage,
                    ),
                }
            },
        };

        let mut attachment_offset = padded_payback_storage.len() + Self::MIN_NUM_ITEMS;
        let mut payback_attachments = Vec::with_capacity(num_payback_attachments);
        for _ in 0..num_payback_attachments {
            let header = word_at(attachment_offset)?;
            if header[2] != Felt::ZERO || header[3] != Felt::ZERO {
                return Err(NoteError::other(
                    "SWAP payback attachment header padding must be zero",
                ));
            }

            let attachment_scheme = u16::try_from(header[0].as_canonical_u64())
                .map_err(|_| NoteError::other("SWAP payback attachment scheme exceeds u16"))
                .and_then(NoteAttachmentScheme::new)?;
            let num_words = usize::try_from(header[1].as_canonical_u64())
                .map_err(|_| NoteError::other("SWAP payback attachment size exceeds usize"))?;

            let content_offset = attachment_offset + Word::NUM_ELEMENTS;
            let words = (0..num_words)
                .map(|word_idx| word_at(content_offset + word_idx * Word::NUM_ELEMENTS))
                .collect::<Result<Vec<_>, _>>()?;

            payback_attachments.push(NoteAttachment::with_words(attachment_scheme, words)?);
            attachment_offset = content_offset + num_words * Word::NUM_ELEMENTS;
        }

        if attachment_offset != note_storage.len() {
            return Err(NoteError::other(
                "SWAP note storage length does not match the declared payback storage and attachments",
            ));
        }

        Self::new(
            requested_asset,
            payback_tag,
            NoteAttachments::new(payback_attachments)?,
            payback,
        )
    }
}

/// Returns the serial number of the default P2ID payback note of a SWAP note.
///
/// It increments the least significant element of the SWAP serial number, so creators can
/// recompute it offline to track or consume the payback note after the SWAP is filled.
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

    /// Filling a SWAP note typically creates the default P2ID payback note.
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
    use miden_protocol::crypto::rand::EidosRandomCoin;
    use miden_protocol::note::{NoteStorage, NoteType};
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    };
    use rstest::rstest;

    use super::*;
    use crate::note::{NetworkAccountTarget, NoteExecutionHint, P2idNote};

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

    /// Returns two payback attachments, one of them spanning several words.
    fn dummy_payback_attachments() -> anyhow::Result<NoteAttachments> {
        let target = NetworkAccountTarget::new(fungible_faucet(), NoteExecutionHint::Always)?;
        let multi_word = NoteAttachment::with_words(
            NoteAttachmentScheme::new(42)?,
            vec![dummy_recipient_digest(), Word::from([1, 2, 3, 4u32])],
        )?;
        Ok(NoteAttachments::new(vec![target.into(), multi_word])?)
    }

    /// Returns a recipient whose storage length is not a multiple of the word size, so encoding
    /// it requires padding.
    fn dummy_payback_recipient() -> anyhow::Result<NoteRecipient> {
        let storage = NoteStorage::new(vec![Felt::from(5u32), Felt::from(6u32), Felt::from(7u32)])?;
        Ok(NoteRecipient::new(
            Word::from([9, 8, 7, 6u32]),
            NoteScript::from_root(P2idNote::script_root()),
            storage,
        ))
    }

    /// The built note must carry the offered asset and a storage that encodes the payback
    /// configuration, while the payback note details target the sender with the serial number
    /// derived from the SWAP serial number.
    #[rstest]
    #[case::private_payback(NoteType::Private)]
    #[case::public_payback(NoteType::Public)]
    fn swap_note_builder(#[case] payback_note_type: NoteType) -> anyhow::Result<()> {
        let sender = dummy_target_id();
        let attachment = NoteAttachment::with_word(
            NetworkAccountTarget::ATTACHMENT_SCHEME,
            dummy_recipient_digest(),
        );
        let payback_attachments = dummy_payback_attachments()?;
        let swap_note_type = NoteType::Public;
        let swap_note = SwapNote::builder()
            .sender(sender)
            .offered_asset(fungible_asset())
            .requested_asset(non_fungible_asset())
            .note_type(swap_note_type)
            .payback_note_type(payback_note_type)
            .attachment(attachment.clone())
            .payback_attachments(payback_attachments.iter().cloned())
            .generate_serial_number(&mut EidosRandomCoin::new(Word::from([1, 2, 3, 4u32])))
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
        assert_eq!(storage.payback_attachments(), &payback_attachments);

        assert_eq!(payback_note.assets().iter().next(), Some(&non_fungible_asset()));
        assert_eq!(payback_note.recipient().serial_num(), payback_serial_from_swap(serial_number));
        assert_eq!(payback_note.recipient().script().root(), P2idNote::script_root());

        // Both payback modes must resolve to the payback note the creator was handed: privately
        // through the embedded recipient digest, publicly through the embedded recipient.
        match (payback_note_type, storage.payback()) {
            (NoteType::Private, SwapPayback::Private { recipient }) => {
                assert_eq!(*recipient, payback_note.recipient().digest());
            },
            (NoteType::Public, SwapPayback::Public { recipient }) => {
                assert_eq!(recipient, payback_note.recipient());
            },
            (note_type, payback) => {
                anyhow::bail!("payback {payback:?} does not match {note_type:?}")
            },
        }

        Ok(())
    }

    #[test]
    fn swap_note_storage_round_trip_fungible_private() -> anyhow::Result<()> {
        let storage = SwapNoteStorage::new_private(
            fungible_asset(),
            dummy_recipient_digest(),
            dummy_payback_tag(),
            dummy_payback_attachments()?,
        )?;

        let note_storage = NoteStorage::from(storage.clone());
        assert_eq!(storage.payback_note_type(), NoteType::Private);
        assert_eq!(storage.requested_asset(), fungible_asset());
        assert_eq!(storage.payback_tag(), dummy_payback_tag());
        assert_eq!(storage.payback_attachments(), &dummy_payback_attachments()?);
        assert_matches!(
            storage.payback(),
            SwapPayback::Private { recipient } if *recipient == dummy_recipient_digest()
        );

        assert_eq!(SwapNoteStorage::try_from(note_storage.items())?, storage);
        Ok(())
    }

    #[test]
    fn swap_note_storage_round_trip_non_fungible_public() -> anyhow::Result<()> {
        let recipient = dummy_payback_recipient()?;
        let storage = SwapNoteStorage::new_public(
            non_fungible_asset(),
            recipient.clone(),
            dummy_payback_tag(),
            dummy_payback_attachments()?,
        )?;

        let note_storage = NoteStorage::from(storage.clone());
        assert_eq!(storage.payback_note_type(), NoteType::Public);
        assert_eq!(storage.requested_asset(), non_fungible_asset());
        assert_eq!(storage.payback_tag(), dummy_payback_tag());
        assert_eq!(storage.payback_attachments(), &dummy_payback_attachments()?);
        assert_matches!(storage.payback(), SwapPayback::Public { recipient: payback } if *payback == recipient);

        assert_eq!(SwapNoteStorage::try_from(note_storage.items())?, storage);
        Ok(())
    }

    #[test]
    fn swap_note_storage_rejects_trailing_items() -> anyhow::Result<()> {
        let mut items: Vec<Felt> = NoteStorage::from(SwapNoteStorage::new_public(
            fungible_asset(),
            dummy_payback_recipient()?,
            dummy_payback_tag(),
            dummy_payback_attachments()?,
        )?)
        .items()
        .to_vec();

        items.push(Felt::ZERO);
        let err = SwapNoteStorage::try_from(items.as_slice())
            .expect_err("storage with items after the last attachment must be rejected");
        assert_matches!(
            err,
            NoteError::Other { error_msg, .. }
                if error_msg == "SWAP note storage length does not match the declared payback storage and attachments".into()
        );
        Ok(())
    }

    #[test]
    fn swap_note_storage_rejects_too_many_items() -> anyhow::Result<()> {
        let payback_storage = NoteStorage::new(vec![Felt::ZERO; MAX_NOTE_STORAGE_ITEMS])?;
        let recipient = NoteRecipient::new(
            Word::empty(),
            NoteScript::from_root(P2idNote::script_root()),
            payback_storage,
        );

        let err = SwapNoteStorage::new_public(
            fungible_asset(),
            recipient,
            dummy_payback_tag(),
            NoteAttachments::empty(),
        )
        .expect_err("a payback storage that does not fit into the SWAP storage must be rejected");
        assert_matches!(
            err,
            NoteError::TooManyStorageItems(num_items)
                if num_items == SwapNoteStorage::MIN_NUM_ITEMS + MAX_NOTE_STORAGE_ITEMS
        );
        Ok(())
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

    /// A SWAP note holds the offered asset and its payback holds the requested one, so a zero
    /// amount on either side leaves one of those two notes empty.
    #[test]
    fn swap_note_builder_rejects_a_zero_asset() {
        let zero = Asset::from(FungibleAsset::new(fungible_faucet(), 0).unwrap());

        let err = SwapNote::builder()
            .sender(dummy_target_id())
            .offered_asset(zero)
            .requested_asset(non_fungible_asset())
            .note_type(NoteType::Public)
            .generate_serial_number(&mut EidosRandomCoin::new(Word::from([1, 2, 3, 4u32])))
            .build()
            .expect_err("a zero offered asset must be rejected");
        assert_matches!(
            err,
            NoteError::Other { error_msg, .. }
                if error_msg == "offered asset must be non-zero".into()
        );

        let err = SwapNote::builder()
            .sender(dummy_target_id())
            .offered_asset(non_fungible_asset())
            .requested_asset(zero)
            .note_type(NoteType::Public)
            .generate_serial_number(&mut EidosRandomCoin::new(Word::from([1, 2, 3, 4u32])))
            .build()
            .expect_err("a zero requested asset must be rejected");
        assert_matches!(
            err,
            NoteError::Other { error_msg, .. }
                if error_msg == "requested asset must be non-zero".into()
        );
    }
}
