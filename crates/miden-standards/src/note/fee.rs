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
    NoteRecipient,
    NoteScript,
    NoteScriptRoot,
    NoteStorage,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::utils::sync::LazyLock;

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the FEE note script procedure in the standards library.
const FEE_SCRIPT_PATH: &str = "::miden::standards::notes::fee::main";

// Initialize the FEE note script only once
static FEE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(FEE_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains FEE note script procedure")
});

// FEE NOTE
// ================================================================================================

/// A FEE note: the canonical way a transaction pays its fee to a batch builder.
///
/// It carries the fee assets and a script that moves them into the consuming account's vault. There
/// is no target account check and no sender check, so it is consumable by *anyone* - whichever
/// account builds the batch consumes it during batch construction. This matters because the payer
/// generally does not know who the batch builder will be.
///
/// It is essentially a [`P2idNote`](crate::note::P2idNote) without the target account check.
///
/// # Warning
///
/// This note pays whoever consumes it first, so it cannot be used to pay a specific party.
///
/// The script performs no structural checks, so [`FeeNote::script_root`] guarantees only which code
/// runs. It does *not* guarantee that a note bearing that root is public, carries no storage, or
/// carries a particular asset: anyone can build such a note by hand. This builder emits public,
/// storage-less, attachment-less notes, but a consumer must not infer that from the script root
/// alone.
///
/// Construct one with the [builder](FeeNote::builder); convert it into a protocol [`Note`]
/// infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct FeeNote {
    sender: AccountId,
    serial_number: Word,
    assets: NoteAssets,
}

#[bon::bon]
impl FeeNote {
    /// Builds a new [`FeeNote`] carrying `assets`, consumable by any account.
    ///
    /// Prefer the builder's `generate_serial_number` over supplying a serial number by hand: an
    /// otherwise identical FEE note (same sender, same assets) reusing a serial number produces a
    /// duplicate nullifier, leaving the second note permanently unconsumable.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `assets` is empty. A fee note that pays nothing is never intended.
    /// - `assets` contains duplicates or exceeds the protocol limit (see [`NoteAssets::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] assets: Vec<Asset>,
        sender: AccountId,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        if assets.is_empty() {
            return Err(NoteError::other("a FEE note must contain at least one asset"));
        }

        let assets = NoteAssets::new(assets)?;

        Ok(Self { sender, serial_number, assets })
    }
}

impl FeeNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the FEE note.
    pub const NUM_STORAGE_ITEMS: usize = 0;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the FEE note.
    pub fn script() -> NoteScript {
        FEE_SCRIPT.clone()
    }

    /// Returns the FEE note script root.
    pub fn script_root() -> NoteScriptRoot {
        FEE_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the assets carried by the note.
    pub fn assets(&self) -> &NoteAssets {
        &self.assets
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: fee_note_builder::State> FeeNoteBuilder<S> {
    /// Adds a single asset to the note.
    pub fn asset(mut self, asset: impl Into<Asset>) -> Self {
        self.assets.push(asset.into());
        self
    }

    /// Adds multiple assets to the note.
    pub fn assets(mut self, assets: impl IntoIterator<Item = impl Into<Asset>>) -> Self {
        self.assets.extend(assets.into_iter().map(Into::into));
        self
    }
}

impl<S: fee_note_builder::State> FeeNoteBuilder<S>
where
    S::SerialNumber: fee_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> FeeNoteBuilder<fee_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<FeeNote> for Note {
    fn from(note: FeeNote) -> Self {
        // FEE notes are always public so the batch builder can discover and consume them. They
        // carry the default tag rather than an account target, because they are payable to nobody.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public);
        let recipient =
            NoteRecipient::new(note.serial_number, FeeNote::script(), NoteStorage::default());

        Note::new(note.assets, metadata, recipient)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::{AccountId, AccountType};
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::crypto::rand::RandomCoin;

    use super::*;
    use crate::note::StandardNote;

    fn sender() -> AccountId {
        AccountId::builder().account_type(AccountType::Private).build_with_seed([1; 32])
    }

    fn faucet() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([2; 32])
    }

    fn other_faucet() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([3; 32])
    }

    /// The builder produces a public, storage-less note carrying the fee assets.
    #[test]
    fn builder_builds_public_fee_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let asset = FungibleAsset::new(faucet(), 100).unwrap();

        let fee_note = FeeNote::builder()
            .sender(sender())
            .asset(asset)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(fee_note.sender(), sender());
        assert_eq!(fee_note.assets().num_assets(), 1);
        assert_ne!(fee_note.serial_number(), Word::empty());

        let note = Note::from(fee_note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.storage().num_items(), FeeNote::NUM_STORAGE_ITEMS as u16);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.attachments().num_attachments(), 0);
    }

    /// The plural `assets` setter accumulates, and assets from distinct faucets coexist.
    #[test]
    fn builder_accepts_multiple_assets() {
        let mut rng = RandomCoin::new(Word::empty());
        let asset_a = FungibleAsset::new(faucet(), 100).unwrap();
        let asset_b = FungibleAsset::new(other_faucet(), 250).unwrap();

        let fee_note = FeeNote::builder()
            .sender(sender())
            .assets([asset_a, asset_b])
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(fee_note.assets().num_assets(), 2);
    }

    /// A fee note that pays nothing is never intended, so the constructor rejects it.
    #[test]
    fn builder_rejects_empty_assets() {
        let err = FeeNote::builder()
            .sender(sender())
            .serial_number(Word::empty())
            .build()
            .expect_err("a note without assets must be rejected");

        assert_matches!(err, NoteError::Other { error_msg, .. } => {
            assert!(error_msg.contains("note must contain at least one asset"))
        });
    }

    /// Two fungible assets from the same faucet are a duplicate, which `NoteAssets` rejects.
    #[test]
    fn builder_rejects_duplicate_assets() {
        let asset = FungibleAsset::new(faucet(), 100).unwrap();

        let err = FeeNote::builder()
            .sender(sender())
            .asset(asset)
            .asset(asset)
            .serial_number(Word::empty())
            .build()
            .expect_err("duplicate assets must be rejected");

        assert_matches!(err, NoteError::DuplicateFungibleAsset(_));
    }

    /// The FEE script root must resolve back to `StandardNote::FEE`, otherwise every consumer that
    /// dispatches on the script root silently treats fee notes as unknown.
    #[test]
    fn script_root_resolves_to_standard_note() {
        let standard_note = StandardNote::from_script_root(FeeNote::script_root())
            .expect("FEE script root should resolve to a standard note");

        assert_eq!(standard_note.name(), "FEE");
        assert_eq!(standard_note.expected_num_storage_items(), FeeNote::NUM_STORAGE_ITEMS);
        assert_eq!(standard_note.script_root(), FeeNote::script_root());
    }
}
