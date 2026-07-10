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
    NoteTag,
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

/// A FEE note: the canonical way for a transaction to pay its fee to a batch builder.
///
/// Unlike a [`P2idNote`](crate::note::P2idNote), the note does not restrict who can consume it:
/// any account (i.e. whichever account builds the batch) can consume the note and claim its
/// assets. The note is completely unopinionated about which assets are used to pay the fee.
///
/// FEE notes are always [public](NoteType::Public), carry no storage and no attachments, and are
/// tagged with the unique [`FeeNote::TAG`].
///
/// Construct one with the [builder](FeeNote::builder), which requires at least one asset. Convert
/// a `FeeNote` into a protocol [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct FeeNote {
    sender: AccountId,
    serial_number: Word,
    assets: NoteAssets,
}

#[bon::bon]
impl FeeNote {
    /// Builds a new [`FeeNote`].
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

    /// The unique note tag of FEE notes (`0xFEE`, "fee" in hex).
    ///
    /// The tag's 18 least significant bits are non-zero, so it can never collide with a default
    /// account-target tag, which has its 18 least significant bits set to zero (see
    /// [`NoteTag::with_account_target`]). Note that this guarantee does not extend to custom
    /// account-target tags built with a length greater than 14 bits (see
    /// [`NoteTag::with_custom_account_target`]), which can set lower bits.
    ///
    /// This constant must be kept in sync with the `FEE_NOTE_TAG` constant in the FEE note's MASM
    /// script.
    pub const TAG: NoteTag = NoteTag::new(0xfee);

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
        // FEE notes are always public, carry no storage, and use the unique FEE note tag.
        let metadata =
            PartialNoteMetadata::new(note.sender, NoteType::Public).with_tag(FeeNote::TAG);
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
    use miden_protocol::block::BlockNumber;
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::errors::NoteError;
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

    fn faucet_b() -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([4u8; 32])
    }

    // BUILDER TESTS
    // --------------------------------------------------------------------------------------------

    /// The minimal builder only requires a sender, a serial number and one asset.
    #[test]
    fn builder_minimal() {
        let note = FeeNote::builder()
            .sender(sender())
            .serial_number(Word::empty())
            .asset(FungibleAsset::new(faucet_a(), 1).unwrap())
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender());
        assert_eq!(note.assets().num_assets(), 1);
    }

    /// `.asset()` and `.assets()` both append, so they can be combined and called repeatedly.
    #[test]
    fn builder_accumulates_assets() {
        let mut rng = RandomCoin::new(Word::empty());
        let note = FeeNote::builder()
            .sender(sender())
            .asset(FungibleAsset::new(faucet_a(), 100).unwrap())
            .assets([Asset::from(FungibleAsset::new(faucet_b(), 200).unwrap())])
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.assets().num_assets(), 2);
        assert_ne!(note.serial_number(), Word::empty());
    }

    /// A FEE note must carry at least one asset.
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

    // CONVERSION TESTS
    // --------------------------------------------------------------------------------------------

    /// The protocol note produced from a FEE note is public, tagged with the unique FEE note tag,
    /// and carries no storage and no attachments.
    #[test]
    fn conversion_produces_public_untargeted_note() {
        let serial_number = Word::from([1u32, 2, 3, 4]);
        let note: Note = FeeNote::builder()
            .sender(sender())
            .serial_number(serial_number)
            .asset(FungibleAsset::new(faucet_a(), 100).unwrap())
            .build()
            .unwrap()
            .into();

        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().sender(), sender());
        assert_eq!(note.metadata().tag(), FeeNote::TAG);
        assert_eq!(usize::from(note.storage().num_items()), FeeNote::NUM_STORAGE_ITEMS);
        assert_eq!(note.attachments().num_attachments(), 0);
        assert_eq!(
            *note.recipient(),
            NoteRecipient::new(serial_number, FeeNote::script(), NoteStorage::default())
        );
    }

    /// The FEE note tag can never collide with a default account-target tag: those have their 18
    /// least significant bits set to zero, while the FEE note tag has non-zero bits there.
    #[test]
    fn tag_never_collides_with_default_account_target_tags() {
        const LOW_18_BITS: u32 = (1 << 18) - 1;
        assert_ne!(FeeNote::TAG.as_u32() & LOW_18_BITS, 0);
        assert_eq!(Felt::from(FeeNote::TAG), Felt::from(0xfee_u32));
    }

    // CONSUMPTION ANALYSIS TESTS
    // --------------------------------------------------------------------------------------------

    /// Static consumption analysis accepts a well-formed FEE note for an arbitrary account and
    /// rejects a note that shares the FEE script root but carries unexpected storage items (such
    /// a note would panic in the note script on execution).
    #[test]
    fn is_consumable_validates_storage() {
        let block_ref = BlockNumber::from(0u32);
        let asset = FungibleAsset::new(faucet_a(), 100).unwrap();

        let standard_note = StandardNote::from_script_root(FeeNote::script_root())
            .expect("FEE script root should be recognized as a standard note");

        let fee_note: Note = FeeNote::builder()
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

        // A note with the FEE script root but non-empty storage can never be consumed.
        let malformed_storage = NoteStorage::new(vec![Felt::from(1u32)]).unwrap();
        let malformed_note = Note::new(
            NoteAssets::new(vec![asset.into()]).unwrap(),
            PartialNoteMetadata::new(sender(), NoteType::Public).with_tag(FeeNote::TAG),
            NoteRecipient::new(Word::empty(), FeeNote::script(), malformed_storage),
        );

        assert_matches!(
            standard_note.is_consumable(&malformed_note, unrelated_consumer(), block_ref),
            Some(NoteConsumptionStatus::NeverConsumable(_))
        );
    }
}
