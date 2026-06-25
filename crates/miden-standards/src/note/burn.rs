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

/// Path to the BURN note script procedure in the standards library.
const BURN_SCRIPT_PATH: &str = "::miden::standards::notes::burn::main";

// Initialize the BURN note script only once
static BURN_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(BURN_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains BURN note script procedure")
});

// BURN NOTE
// ================================================================================================

/// A BURN note: instructs a fungible faucet to burn the asset carried by the note.
///
/// When consumed by the `faucet_id` faucet, the note's asset is destroyed via the faucet's
/// `fungible::receive_and_burn` procedure. BURN notes are always public so they can be executed by
/// the network.
///
/// Construct one with the [builder](BurnNote::builder); convert it into a protocol [`Note`]
/// infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct BurnNote {
    sender: AccountId,
    faucet_id: AccountId,
    serial_number: Word,
    assets: NoteAssets,
    attachments: NoteAttachments,
}

#[bon::bon]
impl BurnNote {
    /// Builds a new [`BurnNote`] instructing `faucet_id` to burn `fungible_asset`.
    ///
    /// # Errors
    ///
    /// Returns an error if the asset or attachments exceed their protocol limits (see
    /// [`NoteAssets::new`] and [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        faucet_id: AccountId,
        #[builder(into)] fungible_asset: Asset,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        let assets = NoteAssets::new(vec![fungible_asset])?;
        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            faucet_id,
            serial_number,
            assets,
            attachments,
        })
    }
}

impl BurnNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the BURN note.
    pub const NUM_STORAGE_ITEMS: usize = 0;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the BURN note.
    pub fn script() -> NoteScript {
        BURN_SCRIPT.clone()
    }

    /// Returns the BURN note script root.
    pub fn script_root() -> NoteScriptRoot {
        BURN_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the faucet that will burn the assets.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the assets carried by the note (the assets to be burned).
    pub fn assets(&self) -> &NoteAssets {
        &self.assets
    }

    /// Returns the attachments carried by the note.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: burn_note_builder::State> BurnNoteBuilder<S> {
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

impl<S: burn_note_builder::State> BurnNoteBuilder<S>
where
    S::SerialNumber: burn_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> BurnNoteBuilder<burn_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<BurnNote> for Note {
    fn from(note: BurnNote) -> Self {
        // BURN notes are always public for network execution and carry no storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.faucet_id));
        let recipient = NoteRecipient::new(
            note.serial_number,
            BurnNote::script(),
            NoteStorage::new(vec![]).expect("a BURN note has no storage items"),
        );

        Note::with_attachments(note.assets, metadata, recipient, note.attachments)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountIdVersion, AccountType};
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::crypto::rand::RandomCoin;

    use super::*;

    fn sender() -> AccountId {
        AccountId::dummy([1u8; 15], AccountIdVersion::Version1, AccountType::Private)
    }

    fn faucet() -> AccountId {
        AccountId::dummy([2u8; 15], AccountIdVersion::Version1, AccountType::Public)
    }

    /// The builder produces a public note, tagged for the faucet, carrying the asset to burn.
    #[test]
    fn builder_builds_public_burn_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let asset = FungibleAsset::new(faucet(), 100).unwrap();

        let burn_note = BurnNote::builder()
            .sender(sender())
            .faucet_id(faucet())
            .fungible_asset(asset)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(burn_note.sender(), sender());
        assert_eq!(burn_note.faucet_id(), faucet());
        assert_eq!(burn_note.assets().num_assets(), 1);
        assert_ne!(burn_note.serial_number(), Word::empty());

        let note = Note::from(burn_note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(faucet()));
        assert_eq!(note.assets().num_assets(), 1);
    }
}
