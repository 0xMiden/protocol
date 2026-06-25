use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
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

/// Path to the non-fungible MINT note script procedure in the standards library.
const MINT_SCRIPT_PATH: &str = "::miden::standards::notes::mint_nft::main";

static MINT_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(MINT_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains non-fungible MINT note script procedure")
});

// NON-FUNGIBLE MINT NOTE
// ================================================================================================

/// A note that instructs a non-fungible network faucet to mint the NFT for the embedded
/// commitment.
///
/// When consumed by the target faucet, the script calls `non_fungible::mint_and_send`. MINT notes
/// carry no assets and are always public.
///
/// Build one with [`NonFungibleMintNote::builder`], then convert it into a [`Note`] via [`From`].
/// Attachments can be appended one at a time with
/// [`attachment`](NonFungibleMintNoteBuilder::attachment).
#[derive(Debug, Clone)]
pub struct NonFungibleMintNote {
    sender: AccountId,
    faucet_id: AccountId,
    serial_number: Word,
    storage: NonFungibleMintNoteStorage,
    attachments: NoteAttachments,
}

#[bon::bon]
impl NonFungibleMintNote {
    /// Builds a [`NonFungibleMintNote`].
    ///
    /// # Parameters
    /// - `sender`: the account ID of the note creator.
    /// - `faucet_id`: the network faucet that will mint the asset (used for the note tag /
    ///   routing).
    /// - `storage`: the storage configuration specifying private or public output mode.
    /// - `serial_number`: the note serial number (see [`Self::generate_serial_number`]).
    #[builder]
    pub fn new(
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        faucet_id: AccountId,
        storage: NonFungibleMintNoteStorage,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        let attachments = NoteAttachments::new(attachments)?;
        Ok(Self {
            sender,
            faucet_id,
            serial_number,
            storage,
            attachments,
        })
    }
}

impl<S: non_fungible_mint_note_builder::State> NonFungibleMintNoteBuilder<S> {
    /// Appends a single attachment to the note.
    pub fn attachment(mut self, attachment: impl Into<NoteAttachment>) -> Self {
        self.attachments.push(attachment.into());
        self
    }
}

impl NonFungibleMintNote {
    /// Expected number of storage items of the MINT note (private mode).
    ///
    /// Layout: RECIPIENT(4) + COMMITMENT(4) + tag(1).
    pub const NUM_STORAGE_ITEMS_PRIVATE: usize = 9;

    /// Minimum number of storage items of the MINT note (public mode).
    ///
    /// Layout: SCRIPT_ROOT(4) + SERIAL_NUM(4) + COMMITMENT(4) + tag(1) + padding(3) + variable
    /// output-note storage (word-aligned at offset 16).
    pub const MIN_NUM_STORAGE_ITEMS_PUBLIC: usize = 16;

    /// Returns the script of the non-fungible MINT note.
    pub fn script() -> NoteScript {
        MINT_SCRIPT.clone()
    }

    /// Returns the non-fungible MINT note script root.
    pub fn script_root() -> NoteScriptRoot {
        MINT_SCRIPT.root()
    }

    /// Draws a fresh serial number from the provided RNG.
    pub fn generate_serial_number<R: FeltRng>(rng: &mut R) -> Word {
        rng.draw_word()
    }

    /// Returns the account ID of the note creator.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the network faucet that will mint the asset.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// Returns the note serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the MINT note storage configuration.
    pub fn storage(&self) -> &NonFungibleMintNoteStorage {
        &self.storage
    }

    /// Returns the note attachments.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }
}

impl From<NonFungibleMintNote> for Note {
    fn from(note: NonFungibleMintNote) -> Self {
        let tag = NoteTag::with_account_target(note.faucet_id);
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public).with_tag(tag);
        let assets = NoteAssets::new(vec![]).expect("no assets is valid");
        let storage = NoteStorage::from(note.storage);
        let recipient =
            NoteRecipient::new(note.serial_number, NonFungibleMintNote::script(), storage);

        Note::with_attachments(assets, metadata, recipient, note.attachments)
    }
}

// NON-FUNGIBLE MINT NOTE STORAGE
// ================================================================================================

/// Storage formats for non-fungible MINT notes.
///
/// - Private: creates a private output note from a precomputed recipient digest (9 items: RECIPIENT
///   + COMMITMENT + tag).
/// - Public: creates a public output note from a script root, serial number, and variable-length
///   storage (16+ items, the variable section word-aligned at offset 16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonFungibleMintNoteStorage {
    Private {
        recipient_digest: Word,
        commitment: Word,
        tag: NoteTag,
    },
    Public {
        recipient: NoteRecipient,
        commitment: Word,
        tag: NoteTag,
    },
}

impl NonFungibleMintNoteStorage {
    pub fn new_private(recipient_digest: Word, commitment: Word, tag: NoteTag) -> Self {
        Self::Private { recipient_digest, commitment, tag }
    }

    pub fn new_public(
        recipient: NoteRecipient,
        commitment: Word,
        tag: NoteTag,
    ) -> Result<Self, NoteError> {
        let total_storage_items = NonFungibleMintNote::MIN_NUM_STORAGE_ITEMS_PUBLIC
            + recipient.storage().num_items() as usize;

        if total_storage_items > MAX_NOTE_STORAGE_ITEMS {
            return Err(NoteError::TooManyStorageItems(total_storage_items));
        }

        Ok(Self::Public { recipient, commitment, tag })
    }

    /// Returns the asset commitment that will be minted on consumption.
    pub fn commitment(&self) -> Word {
        match self {
            Self::Private { commitment, .. } | Self::Public { commitment, .. } => *commitment,
        }
    }
}

impl From<NonFungibleMintNoteStorage> for NoteStorage {
    fn from(mint_storage: NonFungibleMintNoteStorage) -> Self {
        match mint_storage {
            NonFungibleMintNoteStorage::Private { recipient_digest, commitment, tag } => {
                let mut storage_values =
                    Vec::with_capacity(NonFungibleMintNote::NUM_STORAGE_ITEMS_PRIVATE);
                storage_values.extend_from_slice(recipient_digest.as_elements());
                storage_values.extend_from_slice(commitment.as_elements());
                storage_values.push(tag.into());
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
            NonFungibleMintNoteStorage::Public { recipient, commitment, tag } => {
                let mut storage_values = Vec::new();
                storage_values.extend_from_slice(recipient.script().root().as_elements());
                storage_values.extend_from_slice(recipient.serial_num().as_elements());
                storage_values.extend_from_slice(commitment.as_elements());
                storage_values.extend_from_slice(&[tag.into(), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
                storage_values.extend_from_slice(recipient.storage().items());
                NoteStorage::new(storage_values)
                    .expect("number of storage items should not exceed max storage items")
            },
        }
    }
}
