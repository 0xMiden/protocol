use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteRecipient,
    NoteScript,
    NoteScriptRoot,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the BATCH_FEE note script procedure in the standards library.
const BATCH_FEE_SCRIPT_PATH: &str = "::miden::standards::notes::batch_fee::main";

// Initialize the BATCH_FEE note script only once
static BATCH_FEE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(BATCH_FEE_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains BATCH_FEE note script procedure")
});

// FEE NOTE
// ================================================================================================

/// A BATCH_FEE note: the canonical way for a transaction to pay its fee to a batch builder.
///
/// Unlike a [`P2idNote`](crate::note::P2idNote), the note does not restrict who can consume it:
/// any account (i.e. whichever account builds the batch) can consume the note and claim its
/// assets. The note is completely unopinionated about which assets are used to pay the fee.
///
/// BATCH_FEE notes are always [public](NoteType::Public), carry no storage and no attachments, and
/// are tagged with the unique [`BatchFeeNote::TAG`].
///
/// Construct one with the [builder](BatchFeeNote::builder), which requires at least one asset.
/// Convert a `BatchFeeNote` into a protocol [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct BatchFeeNote {
    sender: AccountId,
    serial_number: Word,
    assets: NoteAssets,
}

#[bon::bon]
impl BatchFeeNote {
    /// Builds a new [`BatchFeeNote`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No assets were provided.
    /// - The assets exceed their protocol limits (see [`NoteAssets::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] assets: Vec<Asset>,
        sender: AccountId,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        if assets.is_empty() {
            return Err(NoteError::other("a BATCH_FEE note must contain at least one asset"));
        }

        let assets = NoteAssets::new(assets)?;

        Ok(Self { sender, serial_number, assets })
    }
}

impl BatchFeeNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the BATCH_FEE note.
    pub const NUM_STORAGE_ITEMS: usize = 0;

    /// The unique note tag of BATCH_FEE notes (`0xFEE`, "fee" in hex).
    ///
    /// The tag's 18 least significant bits are non-zero, so it can never collide with a default
    /// account-target tag, which has its 18 least significant bits set to zero (see
    /// [`NoteTag::with_account_target`]). Note that this guarantee does not extend to custom
    /// account-target tags built with a length greater than 14 bits (see
    /// [`NoteTag::with_custom_account_target`]), which can set lower bits.
    ///
    /// This constant must be kept in sync with the `BATCH_FEE_NOTE_TAG` constant in the BATCH_FEE
    /// note's MASM script.
    pub const TAG: NoteTag = NoteTag::new(0xfee);

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the BATCH_FEE note.
    pub fn script() -> NoteScript {
        BATCH_FEE_SCRIPT.clone()
    }

    /// Returns the BATCH_FEE note script root.
    pub fn script_root() -> NoteScriptRoot {
        BATCH_FEE_SCRIPT.root()
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

    // SERIAL NUMBER DERIVATION
    // --------------------------------------------------------------------------------------------

    /// Derives the serial number that `miden::standards::fee::auth::singlesig::pay_fee` uses for
    /// the BATCH_FEE note it creates during a transaction.
    ///
    /// The serial number is `[ref_block_num, initial_nonce, account_id_suffix,
    /// account_id_prefix]`, which is unique per (account, nonce) pair and lets clients precompute
    /// the note's recipient before executing the transaction.
    ///
    /// This derivation must be kept in sync with `create_and_fund_fee_note` in the
    /// `miden::standards::fee` MASM module.
    pub fn derive_serial_number(
        sender: AccountId,
        initial_nonce: Felt,
        ref_block_num: BlockNumber,
    ) -> Word {
        Word::from([
            Felt::from(ref_block_num.as_u32()),
            initial_nonce,
            sender.suffix(),
            sender.prefix().as_felt(),
        ])
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: batch_fee_note_builder::State> BatchFeeNoteBuilder<S> {
    /// Adds a single asset to the note. At least one asset is required for `.build()` to succeed.
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

impl<S: batch_fee_note_builder::State> BatchFeeNoteBuilder<S>
where
    S::SerialNumber: batch_fee_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> BatchFeeNoteBuilder<batch_fee_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<BatchFeeNote> for Note {
    fn from(note: BatchFeeNote) -> Self {
        // BATCH_FEE notes are always public, carry no storage, and use the unique BATCH_FEE note
        // tag.
        let metadata =
            PartialNoteMetadata::new(note.sender, NoteType::Public).with_tag(BatchFeeNote::TAG);
        let recipient =
            NoteRecipient::new(note.serial_number, BatchFeeNote::script(), NoteStorage::default());

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
    use miden_protocol::block::BlockNumber;
    use miden_protocol::{Felt, Word};

    use super::*;
    use crate::note::{NoteConsumptionStatus, StandardNote};

    fn sender() -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Private)
            .build_with_seed([1u8; 32])
    }

    fn unrelated_consumer() -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([2u8; 32])
    }

    fn faucet_a() -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([3u8; 32])
    }

    // CONVERSION TESTS
    // --------------------------------------------------------------------------------------------

    /// The protocol note produced from a BATCH_FEE note is public, tagged with the unique BATCH_FEE
    /// note tag, and carries no storage and no attachments.
    #[test]
    fn conversion_produces_public_untargeted_note() {
        let serial_number = Word::from([1u32, 2, 3, 4]);
        let note: Note = BatchFeeNote::builder()
            .sender(sender())
            .serial_number(serial_number)
            .asset(FungibleAsset::new(faucet_a(), 100).unwrap())
            .build()
            .unwrap()
            .into();

        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().sender(), sender());
        assert_eq!(note.metadata().tag(), BatchFeeNote::TAG);
        assert_eq!(usize::from(note.storage().num_items()), BatchFeeNote::NUM_STORAGE_ITEMS);
        assert_eq!(note.attachments().num_attachments(), 0);
        assert_eq!(
            *note.recipient(),
            NoteRecipient::new(serial_number, BatchFeeNote::script(), NoteStorage::default())
        );
    }

    /// The BATCH_FEE note tag can never collide with a default account-target tag: those have their
    /// 18 least significant bits set to zero, while the BATCH_FEE note tag has non-zero bits
    /// there.
    #[test]
    fn tag_never_collides_with_default_account_target_tags() {
        const LOW_18_BITS: u32 = (1 << 18) - 1;
        assert_ne!(BatchFeeNote::TAG.as_u32() & LOW_18_BITS, 0);
        assert_eq!(Felt::from(BatchFeeNote::TAG), Felt::from(0xfee_u32));
    }

    // CONSUMPTION ANALYSIS TESTS
    // --------------------------------------------------------------------------------------------

    /// Static consumption analysis accepts a well-formed BATCH_FEE note for an arbitrary account
    /// and rejects a note that shares the BATCH_FEE script root but carries unexpected storage
    /// items (such a note would panic in the note script on execution).
    #[test]
    fn is_consumable_validates_storage() {
        let block_ref = BlockNumber::from(0u32);
        let asset = FungibleAsset::new(faucet_a(), 100).unwrap();

        let standard_note = StandardNote::from_script_root(BatchFeeNote::script_root())
            .expect("BATCH_FEE script root should be recognized as a standard note");

        let fee_note: Note = BatchFeeNote::builder()
            .sender(sender())
            .serial_number(Word::empty())
            .asset(asset)
            .build()
            .unwrap()
            .into();

        assert_matches!(
            standard_note.is_consumable(&fee_note, unrelated_consumer(), block_ref),
            Some(NoteConsumptionStatus::ConsumableWithAuthorization)
        );

        // A note with the BATCH_FEE script root but non-empty storage can never be consumed.
        let malformed_storage = NoteStorage::new(vec![Felt::from(1u32)]).unwrap();
        let malformed_note = Note::new(
            NoteAssets::new(vec![asset.into()]).unwrap(),
            PartialNoteMetadata::new(sender(), NoteType::Public).with_tag(BatchFeeNote::TAG),
            NoteRecipient::new(Word::empty(), BatchFeeNote::script(), malformed_storage),
        );

        assert_matches!(
            standard_note.is_consumable(&malformed_note, unrelated_consumer(), block_ref),
            Some(NoteConsumptionStatus::NeverConsumable(_))
        );
    }
}
