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
use miden_protocol::{Felt, Hasher, Word};

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the TX_FEE note script procedure in the standards library.
const TX_FEE_SCRIPT_PATH: &str = "::miden::standards::notes::tx_fee::main";

// Initialize the TX_FEE note script only once
static TX_FEE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(TX_FEE_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains TX_FEE note script procedure")
});

// FEE NOTE
// ================================================================================================

/// A TX_FEE note: the canonical way for a transaction to pay its fee to a batch builder.
///
/// Unlike a [`P2idNote`](crate::note::P2idNote), the note does not restrict who can consume it:
/// any account (i.e. whichever account builds the batch) can consume the note and claim its
/// assets. The note is completely unopinionated about which assets are used to pay the fee.
///
/// TX_FEE notes are always [public](NoteType::Public), carry no storage and no attachments, and
/// are tagged with the unique [`TxFeeNote::TAG`].
///
/// Construct one with the [builder](TxFeeNote::builder), which requires at least one asset.
/// Convert a `TxFeeNote` into a protocol [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct TxFeeNote {
    sender: AccountId,
    serial_number: Word,
    assets: NoteAssets,
}

#[bon::bon]
impl TxFeeNote {
    /// Builds a new [`TxFeeNote`].
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
            return Err(NoteError::other("a TX_FEE note must contain at least one asset"));
        }

        let assets = NoteAssets::new(assets)?;

        Ok(Self { sender, serial_number, assets })
    }
}

impl TxFeeNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the TX_FEE note.
    pub const NUM_STORAGE_ITEMS: usize = 0;

    /// The raw `u32` value of [`Self::TAG`] (`0xFEE`, "fee" in hex), also used as the
    /// domain-separation tag by [`Self::derive_serial_number`].
    ///
    /// This constant must be kept in sync with the `TX_FEE_NOTE_TAG` and `FEE_DOMAIN_TAG`
    /// constants in the standards MASM library.
    pub const TAG_ID: u32 = 0xfee;

    /// The unique note tag of TX_FEE notes.
    ///
    /// The tag's 18 least significant bits are non-zero, so it can never collide with a default
    /// account-target tag, which has its 18 least significant bits set to zero (see
    /// [`NoteTag::with_account_target`]). Note that this guarantee does not extend to custom
    /// account-target tags built with a length greater than 14 bits (see
    /// [`NoteTag::with_custom_account_target`]), which can set lower bits.
    pub const TAG: NoteTag = NoteTag::new(Self::TAG_ID);

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the TX_FEE note.
    pub fn script() -> NoteScript {
        TX_FEE_SCRIPT.clone()
    }

    /// Returns the TX_FEE note script root.
    pub fn script_root() -> NoteScriptRoot {
        TX_FEE_SCRIPT.root()
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

    /// Derives the serial number that `miden::standards::fee::pay_fee` uses for
    /// the TX_FEE note it creates during a transaction.
    ///
    /// The serial number is `hash(FEE_DOMAIN || [ref_block_num, initial_nonce,
    /// account_id_suffix, account_id_prefix])` with the FEE domain tag `[0xFEE, 0, 0, 0]`. It is
    /// unique per (account, nonce) pair and lets clients precompute the note's recipient before
    /// executing the transaction, while the domain tag separates it from serial numbers derived
    /// from similar tuples in other contexts.
    ///
    /// This derivation must be kept in sync with `create_and_fund_fee_note` in the
    /// `miden::standards::fee` MASM module.
    pub fn derive_serial_number(
        sender: AccountId,
        initial_nonce: Felt,
        ref_block_num: BlockNumber,
    ) -> Word {
        // Domain-separation tag for the fee note's serial number ("fee" in hex).
        let fee_domain = Word::from([Felt::from(Self::TAG_ID), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
        let tuple = Word::from([
            Felt::from(ref_block_num.as_u32()),
            initial_nonce,
            sender.suffix(),
            sender.prefix().as_felt(),
        ]);

        Hasher::merge(&[fee_domain, tuple])
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: tx_fee_note_builder::State> TxFeeNoteBuilder<S> {
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

impl<S: tx_fee_note_builder::State> TxFeeNoteBuilder<S>
where
    S::SerialNumber: tx_fee_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> TxFeeNoteBuilder<tx_fee_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<TxFeeNote> for Note {
    fn from(note: TxFeeNote) -> Self {
        // TX_FEE notes are always public, carry no storage, and use the unique TX_FEE note
        // tag.
        let metadata =
            PartialNoteMetadata::new(note.sender, NoteType::Public).with_tag(TxFeeNote::TAG);
        let recipient =
            NoteRecipient::new(note.serial_number, TxFeeNote::script(), NoteStorage::default());

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

    /// The protocol note produced from a TX_FEE note is public, tagged with the unique TX_FEE
    /// note tag, and carries no storage and no attachments.
    #[test]
    fn conversion_produces_public_untargeted_note() {
        let serial_number = Word::from([1u32, 2, 3, 4]);
        let note: Note = TxFeeNote::builder()
            .sender(sender())
            .serial_number(serial_number)
            .asset(FungibleAsset::new(faucet_a(), 100).unwrap())
            .build()
            .unwrap()
            .into();

        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().sender(), sender());
        assert_eq!(note.metadata().tag(), TxFeeNote::TAG);
        assert_eq!(usize::from(note.storage().num_items()), TxFeeNote::NUM_STORAGE_ITEMS);
        assert_eq!(note.attachments().num_attachments(), 0);
        assert_eq!(
            *note.recipient(),
            NoteRecipient::new(serial_number, TxFeeNote::script(), NoteStorage::default())
        );
    }

    /// The TX_FEE note tag can never collide with a default account-target tag: those have their
    /// 18 least significant bits set to zero, while the TX_FEE note tag has non-zero bits
    /// there.
    #[test]
    fn tag_never_collides_with_default_account_target_tags() {
        const LOW_18_BITS: u32 = (1 << 18) - 1;
        assert_ne!(TxFeeNote::TAG.as_u32() & LOW_18_BITS, 0);
        assert_eq!(Felt::from(TxFeeNote::TAG), Felt::from(TxFeeNote::TAG_ID));
    }

    // CONSUMPTION ANALYSIS TESTS
    // --------------------------------------------------------------------------------------------

    /// Static consumption analysis accepts a well-formed TX_FEE note for an arbitrary account
    /// and rejects a note that shares the TX_FEE script root but carries unexpected storage
    /// items (such a note would panic in the note script on execution).
    #[test]
    fn is_consumable_validates_storage() {
        let block_ref = BlockNumber::from(0u32);
        let asset = FungibleAsset::new(faucet_a(), 100).unwrap();

        let standard_note = StandardNote::from_script_root(TxFeeNote::script_root())
            .expect("TX_FEE script root should be recognized as a standard note");

        let fee_note: Note = TxFeeNote::builder()
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

        // A note with the TX_FEE script root but non-empty storage can never be consumed.
        let malformed_storage = NoteStorage::new(vec![Felt::from(1u32)]).unwrap();
        let malformed_note = Note::new(
            NoteAssets::new(vec![asset.into()]).unwrap(),
            PartialNoteMetadata::new(sender(), NoteType::Public).with_tag(TxFeeNote::TAG),
            NoteRecipient::new(Word::empty(), TxFeeNote::script(), malformed_storage),
        );

        assert_matches!(
            standard_note.is_consumable(&malformed_note, unrelated_consumer(), block_ref),
            Some(NoteConsumptionStatus::NeverConsumable(_))
        );
    }
}
