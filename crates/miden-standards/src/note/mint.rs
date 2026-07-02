use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::{Asset, FungibleAsset};
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

// NOTE SCRIPT
// ================================================================================================

/// Path to the MINT note script procedure in the standards library.
const MINT_SCRIPT_PATH: &str = "::miden::standards::notes::mint::main";

// Initialize the MINT note script only once
static MINT_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(MINT_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains MINT note script procedure")
});

// MINT NOTE
// ================================================================================================

/// A MINT note: instructs a network faucet to mint the asset embedded in its storage.
///
/// The MINT script reads the asset directly from the note's storage and passes it to the faucet's
/// `mint_and_send` procedure, which rejects an asset that does not belong to the consuming faucet.
/// A MINT note bound to faucet A therefore cannot be redirected to faucet B even when both share an
/// owner. MINT notes are always public (for network execution) and carry no assets; the output note
/// minted on consumption can be private or public depending on the [`MintNoteStorage`] variant.
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
    /// # Errors
    ///
    /// Returns an error if the attachments exceed their protocol limit (see
    /// [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        #[builder(name = mint_storage)] storage: MintNoteStorage,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
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

    /// Expected number of storage items of the MINT note (private mode).
    ///
    /// Layout: RECIPIENT(4) + ASSET_KEY(4) + ASSET_VALUE(4) + tag(1).
    pub const NUM_STORAGE_ITEMS_PRIVATE: usize = 13;

    /// Minimum number of storage items of the MINT note (public mode).
    ///
    /// Layout: SCRIPT_ROOT(4) + SERIAL_NUM(4) + ASSET_KEY(4) + ASSET_VALUE(4) + tag(1) +
    /// padding(3) + variable output-note storage. The variable portion starts at offset 20
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
        self.storage.asset().faucet_id()
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
        let faucet_id = note.storage.asset().faucet_id();
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
/// - Private: Creates a private output note using a precomputed recipient digest (13 MINT note
///   storage items: RECIPIENT + ASSET_KEY + ASSET_VALUE + tag).
/// - Public: Creates a public output note by providing script root, serial number, and
///   variable-length storage (20+ MINT note storage items: 20 fixed + variable output note storage
///   items, with the variable section word-aligned at offset 20).
///
/// The asset (`ASSET_KEY` + `ASSET_VALUE`, 8 felts) is embedded in storage so that the
/// faucet executing the MINT note can be checked against the asset's faucet ID at mint time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintNoteStorage {
    Private {
        recipient_digest: Word,
        asset: FungibleAsset,
        tag: Felt,
    },
    Public {
        recipient: NoteRecipient,
        asset: FungibleAsset,
        tag: Felt,
    },
}

impl MintNoteStorage {
    pub fn new_private(recipient_digest: Word, asset: FungibleAsset, tag: Felt) -> Self {
        Self::Private { recipient_digest, asset, tag }
    }

    pub fn new_public(
        recipient: NoteRecipient,
        asset: FungibleAsset,
        tag: Felt,
    ) -> Result<Self, NoteError> {
        let total_storage_items =
            MintNote::MIN_NUM_STORAGE_ITEMS_PUBLIC + recipient.storage().num_items() as usize;

        if total_storage_items > MAX_NOTE_STORAGE_ITEMS {
            return Err(NoteError::TooManyStorageItems(total_storage_items));
        }

        Ok(Self::Public { recipient, asset, tag })
    }

    /// Returns the asset that will be minted on consumption.
    pub fn asset(&self) -> FungibleAsset {
        match self {
            Self::Private { asset, .. } | Self::Public { asset, .. } => *asset,
        }
    }
}

impl From<MintNoteStorage> for NoteStorage {
    fn from(mint_storage: MintNoteStorage) -> Self {
        match mint_storage {
            MintNoteStorage::Private { recipient_digest, asset, tag } => {
                let mut storage_values = Vec::with_capacity(MintNote::NUM_STORAGE_ITEMS_PRIVATE);
                storage_values.extend_from_slice(recipient_digest.as_elements());
                storage_values.extend_from_slice(&Asset::from(asset).as_elements());
                storage_values.push(tag);
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
            MintNoteStorage::Public { recipient, asset, tag } => {
                let mut storage_values = Vec::new();
                storage_values.extend_from_slice(recipient.script().root().as_elements());
                storage_values.extend_from_slice(recipient.serial_num().as_elements());
                storage_values.extend_from_slice(&Asset::from(asset).as_elements());
                // tag followed by 3 padding felts so the variable storage that follows starts at
                // a word-aligned offset (20).
                storage_values.extend_from_slice(&[tag, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
                storage_values.extend_from_slice(recipient.storage().items());
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::rand::RandomCoin;

    use super::*;

    fn faucet() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([1; 32])
    }

    fn owner() -> AccountId {
        AccountId::builder().account_type(AccountType::Private).build_with_seed([2; 32])
    }

    /// The builder produces a public, asset-less note tagged for the faucet.
    #[test]
    fn builder_builds_public_mint_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let asset = FungibleAsset::new(faucet(), 50).unwrap();
        let mint_storage = MintNoteStorage::new_private(Word::empty(), asset, Felt::ZERO);
        let mint_note = MintNote::builder()
            .sender(owner())
            .mint_storage(mint_storage)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(mint_note.faucet_id(), faucet());
        assert_eq!(mint_note.sender(), owner());

        let note = Note::from(mint_note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(faucet()));
        assert_eq!(note.assets().num_assets(), 0);
    }
}
