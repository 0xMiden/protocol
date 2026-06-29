use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::Word;
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

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the non-fungible BURN note script procedure in the standards library.
const BURN_SCRIPT_PATH: &str = "::miden::standards::notes::burn_nft::main";

static BURN_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(BURN_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains non-fungible BURN note script procedure")
});

// NON-FUNGIBLE BURN NOTE
// ================================================================================================

/// A note that instructs a non-fungible faucet to burn the NFT it carries.
///
/// When consumed by the faucet that issued the NFT, the script calls
/// `non_fungible::receive_and_burn`. BURN notes are always public.
///
/// Build one with [`NonFungibleBurnNote::builder`], then convert it into a [`Note`] via [`From`].
#[derive(Debug, Clone)]
pub struct NonFungibleBurnNote {
    sender: AccountId,
    serial_number: Word,
    asset: Asset,
    attachments: NoteAttachments,
}

#[bon::bon]
impl NonFungibleBurnNote {
    /// Builds a [`NonFungibleBurnNote`] that burns `asset` against the faucet that issued it.
    ///
    /// # Errors
    ///
    /// Returns an error if the attachments exceed their protocol limit (see
    /// [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        #[builder(into)] asset: Asset,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        let attachments = NoteAttachments::new(attachments)?;
        Ok(Self {
            sender,
            serial_number,
            asset,
            attachments,
        })
    }
}

impl NonFungibleBurnNote {
    /// Expected number of storage items of the BURN note.
    pub const NUM_STORAGE_ITEMS: usize = 0;

    /// Returns the script of the non-fungible BURN note.
    pub fn script() -> NoteScript {
        BURN_SCRIPT.clone()
    }

    /// Returns the non-fungible BURN note script root.
    pub fn script_root() -> NoteScriptRoot {
        BURN_SCRIPT.root()
    }

    /// Returns the account ID of the note creator.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the faucet that will burn the asset (the asset's own faucet).
    pub fn faucet_id(&self) -> AccountId {
        self.asset.faucet_id()
    }

    /// Returns the note serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the non-fungible asset to be burned.
    pub fn asset(&self) -> &Asset {
        &self.asset
    }

    /// Returns the note attachments.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: non_fungible_burn_note_builder::State> NonFungibleBurnNoteBuilder<S> {
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

impl<S: non_fungible_burn_note_builder::State> NonFungibleBurnNoteBuilder<S>
where
    S::SerialNumber: non_fungible_burn_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> NonFungibleBurnNoteBuilder<non_fungible_burn_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<NonFungibleBurnNote> for Note {
    fn from(note: NonFungibleBurnNote) -> Self {
        // BURN notes are always public and carry no storage; the tag routes to the asset's faucet.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.asset.faucet_id()));
        let recipient = NoteRecipient::new(
            note.serial_number,
            NonFungibleBurnNote::script(),
            NoteStorage::default(),
        );
        let assets = NoteAssets::new(vec![note.asset]).expect("a single asset is valid");

        Note::with_attachments(assets, metadata, recipient, note.attachments)
    }
}
