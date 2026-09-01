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
    NoteRecipient,
    NoteScript,
    NoteScriptRoot,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS, Word};

use crate::StandardsLib;
use crate::note::costs::{MINT_CONSUMPTION_CYCLES, NoteConsumptionCost};
use crate::note::{NetworkAccountTarget, P2idNote};

// NOTE SCRIPT
// ================================================================================================

/// Path to the MINT note script procedure in the standards library.
const MINT_SCRIPT_PATH: &str = "::miden::standards::notes::mint::main";

// Initialize the MINT note script only once
static MINT_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(MINT_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains MINT note script procedure")
});

// MINT NOTE
// ================================================================================================

/// A MINT note: instructs a network faucet to mint the asset embedded in its storage.
///
/// The single MINT script works against both fungible and non-fungible faucets: it reads the asset
/// directly from the note's storage, in the same layout for both faucet kinds, and calls the
/// `mint_and_send` matching that asset's composition. MINT notes are always public (for network
/// execution) and carry no assets; the output note minted on consumption can be private or public
/// depending on the [`MintNoteStorage`] variant, which the script reads from the selector in the
/// note's first storage item.
///
/// A MINT note for a public faucet is tagged for that faucet and carries a
/// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) attachment naming it, both derived
/// from the asset in the note's storage, so the network can route the note to it. A private faucet
/// can never be a network account, so a note for one is only tagged and carries no such
/// attachment.
///
/// Construct one with the [builder](MintNote::builder); convert it into a protocol [`Note`]
/// infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct MintNote {
    sender: AccountId,
    storage: MintNoteStorage,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl MintNote {
    /// Builds a new [`MintNote`] that mints the asset embedded in `mint_storage`.
    ///
    /// The faucet the note is bound to comes from [`MintNoteStorage`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the attachments carry a `NetworkAccountTarget` for an account other than the faucet.
    /// - the attachments exceed their protocol limit (see [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] mut attachments: Vec<NoteAttachment>,
        sender: AccountId,
        #[builder(name = mint_storage)] storage: MintNoteStorage,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // The network routes the note on this attachment; the stored ASSET_ID is what binds the
        // script to the same faucet on consumption.
        NetworkAccountTarget::ensure_presence_if_public(&mut attachments, storage.faucet_id())
            .map_err(|err| {
                NoteError::other_with_source("failed to target the MINT note at its faucet", err)
            })?;

        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            storage,
            serial_number,
            attachments,
        })
    }
}

impl MintNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of a MINT note (private mode).
    ///
    /// Layout: selector(1) + tag(1) + padding(2) + ASSET_ID(4) + ASSET_VALUE(4) + RECIPIENT(4).
    pub const NUM_STORAGE_ITEMS_PRIVATE: usize = 16;

    /// Minimum number of storage items of a MINT note (public mode).
    ///
    /// Layout: selector(1) + tag(1) + padding(2) + ASSET_ID(4) + ASSET_VALUE(4) + SCRIPT_ROOT(4) +
    /// SERIAL_NUM(4) + variable output-note storage. The variable portion starts at offset 20
    /// (word-aligned) and may contain zero or more items.
    pub const MIN_NUM_STORAGE_ITEMS_PUBLIC: usize = 20;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the MINT note.
    pub fn script() -> NoteScript {
        MINT_SCRIPT.clone()
    }

    /// Returns the MINT note script root.
    pub fn script_root() -> NoteScriptRoot {
        MINT_SCRIPT.root()
    }

    /// Returns the account ID of the faucet that will mint the asset.
    pub fn faucet_id(&self) -> AccountId {
        self.storage.faucet_id()
    }

    /// Returns the account ID of the note's sender (the faucet owner).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the note's storage configuration.
    pub fn storage(&self) -> &MintNoteStorage {
        &self.storage
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the attachments carried by the note.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: mint_note_builder::State> MintNoteBuilder<S> {
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

impl<S: mint_note_builder::State> MintNoteBuilder<S>
where
    S::SerialNumber: mint_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> MintNoteBuilder<mint_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<MintNote> for Note {
    fn from(note: MintNote) -> Self {
        // MINT notes are always public for network execution and carry no assets; the asset to mint
        // lives in the note's storage.
        let faucet_id = note.storage.faucet_id();
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(faucet_id));
        let recipient = NoteRecipient::new(
            note.serial_number,
            MintNote::script(),
            NoteStorage::from(note.storage),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// MINT NOTE STORAGE
// ================================================================================================

/// Represents the different storage formats for MINT notes.
///
/// The MINT note serves both fungible and non-fungible faucets, and both use the same layout: the
/// note embeds the full [`Asset`] (`ASSET_ID` + `ASSET_VALUE`, 8 felts). The `ASSET_ID` is what
/// binds the note to one faucet - the faucet's `mint_and_send` derives the asset for the active
/// account and asserts it equals the stored `ASSET_ID`, so a note created for one faucet cannot be
/// minted by another. This works for non-fungible assets too, since a non-fungible `ASSET_ID` is
/// `f(faucet_id, ASSET_VALUE)` and is therefore known when the note is built. Its composition is
/// also what the script dispatches the faucet kind on, so no separate marker is stored for it.
///
/// The first storage item is the selector telling the script which of the two variants the note
/// was built as; the layouts share everything up to the asset and differ only in the tail:
///
/// - Private (16 items): selector + tag + padding(2) + ASSET_ID + ASSET_VALUE + RECIPIENT.
/// - Public (20+ items): selector + tag + padding(2) + ASSET_ID + ASSET_VALUE + SCRIPT_ROOT +
///   SERIAL_NUM + variable output-note storage (word-aligned at offset 20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintNoteStorage {
    Private {
        recipient_digest: Word,
        asset: Asset,
        tag: NoteTag,
    },
    Public {
        recipient: NoteRecipient,
        asset: Asset,
        tag: NoteTag,
    },
}

impl MintNoteStorage {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Output note mode selectors stored in the first storage item. Keep in sync with `mint.masm`.
    const SELECTOR_PRIVATE: u8 = 0;
    const SELECTOR_PUBLIC: u8 = 1;

    /// Builds private-mode storage (creates a private output note).
    pub fn new_private(recipient_digest: Word, asset: impl Into<Asset>, tag: NoteTag) -> Self {
        Self::Private {
            recipient_digest,
            asset: asset.into(),
            tag,
        }
    }

    /// Builds public-mode storage (creates a public output note).
    pub fn new_public(
        recipient: NoteRecipient,
        asset: impl Into<Asset>,
        tag: NoteTag,
    ) -> Result<Self, NoteError> {
        let total_storage_items =
            MintNote::MIN_NUM_STORAGE_ITEMS_PUBLIC + recipient.storage().num_items() as usize;

        if total_storage_items > MAX_NOTE_STORAGE_ITEMS {
            return Err(NoteError::TooManyStorageItems(total_storage_items));
        }

        Ok(Self::Public { recipient, asset: asset.into(), tag })
    }

    /// Returns the asset that will be minted.
    pub fn asset(&self) -> Asset {
        match self {
            Self::Private { asset, .. } | Self::Public { asset, .. } => *asset,
        }
    }

    /// Returns the account ID of the faucet that will mint the asset.
    pub fn faucet_id(&self) -> AccountId {
        self.asset().faucet_id()
    }

    /// Returns the storage items shared by both variants: the selector and the tag, followed by 2
    /// padding felts so the asset - and everything after it - stays word-aligned.
    fn header(selector: u8, tag: NoteTag, asset: Asset) -> [Felt; 12] {
        let mut header = [Felt::ZERO; 12];
        header[0] = Felt::from(selector);
        header[1] = tag.into();
        header[4..].copy_from_slice(&asset.as_elements());
        header
    }
}

impl From<MintNoteStorage> for NoteStorage {
    fn from(mint_storage: MintNoteStorage) -> Self {
        match mint_storage {
            MintNoteStorage::Private { recipient_digest, asset, tag } => {
                let mut storage_values = Vec::with_capacity(MintNote::NUM_STORAGE_ITEMS_PRIVATE);
                storage_values.extend_from_slice(&MintNoteStorage::header(
                    MintNoteStorage::SELECTOR_PRIVATE,
                    tag,
                    asset,
                ));
                storage_values.extend_from_slice(recipient_digest.as_elements());
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
            MintNoteStorage::Public { recipient, asset, tag } => {
                let mut storage_values = Vec::new();
                storage_values.extend_from_slice(&MintNoteStorage::header(
                    MintNoteStorage::SELECTOR_PUBLIC,
                    tag,
                    asset,
                ));
                storage_values.extend_from_slice(recipient.script().root().as_elements());
                storage_values.extend_from_slice(recipient.serial_num().as_elements());
                storage_values.extend_from_slice(recipient.storage().items());
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
        }
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for MintNote {
    fn consumption_cycles() -> u32 {
        MINT_CONSUMPTION_CYCLES
    }

    /// Consuming a MINT note typically creates the P2ID note delivering the minted asset
    /// (the recipient digest may encode any script; P2ID is the standard flow).
    fn created_notes() -> Vec<NoteScriptRoot> {
        vec![P2idNote::script_root()]
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountType;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::crypto::rand::RandomCoin;

    use super::*;
    use crate::note::{NetworkNoteExt, NoteExecutionHint};

    fn faucet() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([1; 32])
    }

    fn private_faucet() -> AccountId {
        AccountId::builder().account_type(AccountType::Private).build_with_seed([1; 32])
    }

    fn owner() -> AccountId {
        AccountId::builder().account_type(AccountType::Private).build_with_seed([2; 32])
    }

    fn build_mint_note(faucet_id: AccountId) -> MintNote {
        let asset = FungibleAsset::new(faucet_id, 50).unwrap();
        let mut rng = RandomCoin::new(Word::empty());
        MintNote::builder()
            .sender(owner())
            .mint_storage(MintNoteStorage::new_private(Word::empty(), asset, NoteTag::default()))
            .generate_serial_number(&mut rng)
            .build()
            .unwrap()
    }

    /// The builder produces a public, asset-less note tagged for the faucet and routed to it by a
    /// derived network target. How that target treats caller-supplied attachments is covered by the
    /// `network_account_target` tests.
    #[test]
    fn builder_builds_public_mint_note() {
        let mint_note = build_mint_note(faucet());

        assert_eq!(mint_note.faucet_id(), faucet());
        assert_eq!(mint_note.sender(), owner());
        assert_eq!(mint_note.attachments().num_attachments(), 1);

        let note = Note::from(mint_note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(faucet()));
        assert_eq!(note.assets().num_assets(), 0);
        assert!(note.is_network_note());

        let target = NetworkAccountTarget::try_from(note.attachments()).unwrap();
        assert_eq!(target.target_id(), faucet());
        assert_eq!(target.execution_hint(), NoteExecutionHint::Always);
    }

    /// The private-mode storage pins the layout `mint.masm` reads: the selector in the first item,
    /// the tag in the second, then the asset at the word-aligned offset 4 and the recipient at 12.
    #[test]
    fn private_storage_lays_out_selector_tag_and_asset() {
        let asset = Asset::from(FungibleAsset::new(faucet(), 50).unwrap());
        let recipient_digest = Word::from([9u32, 8, 7, 6]);
        let tag = NoteTag::with_account_target(faucet());

        let storage = NoteStorage::from(MintNoteStorage::new_private(recipient_digest, asset, tag));
        let items = storage.items();

        assert_eq!(items.len(), MintNote::NUM_STORAGE_ITEMS_PRIVATE);
        assert_eq!(items[0], Felt::from(MintNoteStorage::SELECTOR_PRIVATE));
        assert_eq!(items[1], Felt::from(tag));
        assert_eq!(items[2..4], [Felt::ZERO, Felt::ZERO]);
        assert_eq!(items[4..12], asset.as_elements());
        assert_eq!(items[12..16], *recipient_digest.as_elements());
    }

    /// The public-mode storage shares the private layout up to the asset and continues with the
    /// output note's recipient parts, keeping its variable storage word-aligned at offset 20.
    #[test]
    fn public_storage_lays_out_selector_tag_and_asset() {
        let asset = Asset::from(FungibleAsset::new(faucet(), 50).unwrap());
        let tag = NoteTag::with_account_target(faucet());
        let recipient = NoteRecipient::new(
            Word::from([1u32, 2, 3, 4]),
            MintNote::script(),
            NoteStorage::new(vec![Felt::from(7u32)]).unwrap(),
        );

        let storage =
            NoteStorage::from(MintNoteStorage::new_public(recipient.clone(), asset, tag).unwrap());
        let items = storage.items();

        assert_eq!(items.len(), MintNote::MIN_NUM_STORAGE_ITEMS_PUBLIC + 1);
        assert_eq!(items[0], Felt::from(MintNoteStorage::SELECTOR_PUBLIC));
        assert_eq!(items[1], Felt::from(tag));
        assert_eq!(items[2..4], [Felt::ZERO, Felt::ZERO]);
        assert_eq!(items[4..12], asset.as_elements());
        assert_eq!(items[12..16], *recipient.script().root().as_elements());
        assert_eq!(items[16..20], *recipient.serial_num().as_elements());
        assert_eq!(items[20..], *recipient.storage().items());
    }

    /// A private faucet is never a network account, so no target is derived for it. The note is
    /// still tagged for the faucet and remains consumable by it.
    #[test]
    fn builder_omits_network_target_for_private_faucet() {
        let mint_note = build_mint_note(private_faucet());

        assert_eq!(mint_note.attachments().num_attachments(), 0);

        let note = Note::from(mint_note);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(private_faucet()));
        assert!(!note.is_network_note());
    }
}
