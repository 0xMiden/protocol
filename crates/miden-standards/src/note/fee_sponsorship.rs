use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteId,
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

use super::decode_optional_block_height;
use crate::StandardsLib;
use crate::note::costs::{FEE_SPONSORSHIP_CONSUMPTION_CYCLES, NoteConsumptionCost};

// NOTE SCRIPT
// ================================================================================================

/// Path to the FEE_SPONSORSHIP note script procedure in the standards library.
const FEE_SPONSORSHIP_SCRIPT_PATH: &str = "::miden::standards::notes::fee_sponsorship::main";

// Initialize the FEE_SPONSORSHIP note script only once
static FEE_SPONSORSHIP_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(FEE_SPONSORSHIP_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains FEE_SPONSORSHIP note script procedure")
});

// FEE SPONSORSHIP NOTE
// ================================================================================================

/// A FEE_SPONSORSHIP note: carries the fee for exactly one feature note.
///
/// Under the sponsorship fee model, the feature note (`BURN`, `CLAIM`, `B2AGG`, ...) stays
/// entirely fee-unaware. The fee travels in this separate note as exactly one asset; the note
/// names the feature note it pays for by carrying that note's [`NoteId`] in its note storage. The
/// note carries no attachments; its tag routes it to the network account the feature note targets.
///
/// # Consumption
///
/// The note may only be consumed in a transaction that also consumes the bound feature note; it
/// does not restrict who that consumer is. Consumption rights are thereby inherited from the
/// feature note: whoever may consume the feature note may take its sponsorship in the same
/// transaction. The script enforces the pairing itself, rather than relying on the account: the
/// sponsor trusts neither the consuming account nor the transaction builder, but does choose the
/// note's script root.
///
/// The mirror-image check (that a feature note is not consumed *without* sponsorship) protects
/// the consuming account rather than the sponsor, and so lives in the account's auth procedure.
/// That check binds sponsorships to feature notes by note ID, so the note can be at any position in
/// the input notes. Several sponsorship notes may be bound to the same feature note to top up its
/// fee between them.
///
/// # Reclaim
///
/// Every consumption without the bound feature note is a reclaim: the note returns to its
/// `reclaimer` once `reclaim_height` is reached. If the bound feature note is consumed by some
/// other transaction, reclaim is the only way to recover the assets. A reclaim cannot happen in a
/// transaction that also collects fees, which rejects a sponsorship whose feature note is absent.
///
/// # Representation
///
/// The note's parts are held in strongly typed form: `From<FeeSponsorshipNote> for Note` builds the
/// on-chain note and [`FeeSponsorshipNote::try_from`] parses one back, so a note read from a block
/// round-trips unchanged. The type stores the note's [`NoteTag`] rather than the target account ID,
/// because a tag only keeps the high bits of the target's account ID prefix and so cannot be
/// inverted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeSponsorshipNote {
    sender: AccountId,
    serial_number: Word,
    asset: FungibleAsset,
    tag: NoteTag,
    storage: FeeSponsorshipNoteStorage,
}

#[bon::bon]
impl FeeSponsorshipNote {
    /// Builds a new [`FeeSponsorshipNote`] sponsoring `feature_note_id`, tagged for `target`.
    ///
    /// Prefer the builder's `generate_serial_number` over supplying a serial number by hand.
    ///
    /// The fee is exactly one fungible asset; the note script rejects notes carrying any other
    /// number of assets, which keeps fee collection simple. Fees are always denominated in the fee
    /// asset the collecting account configures.
    ///
    /// The reclaimer, the account allowed to reclaim the note after `reclaim_height`, defaults to
    /// `sender` when left unset.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the target account is not public. A network note's tag must route to a public account.
    #[builder]
    pub fn new(
        sender: AccountId,
        #[builder(name = target_account)] target: AccountId,
        feature_note_id: NoteId,
        asset: FungibleAsset,
        serial_number: Word,
        reclaimer: Option<AccountId>,
        reclaim_height: Option<BlockNumber>,
    ) -> Result<Self, NoteError> {
        if !target.is_public() {
            return Err(NoteError::other("fee sponsorship target account must be public"));
        }

        // The reclaimer is the account allowed to reclaim the note; it defaults to the sender.
        let reclaimer = reclaimer.unwrap_or(sender);
        let storage = FeeSponsorshipNoteStorage::new(feature_note_id, reclaimer, reclaim_height);

        Ok(Self {
            sender,
            serial_number,
            asset,
            // The tag routes the note to the network account the feature note targets.
            tag: NoteTag::with_account_target(target),
            storage,
        })
    }
}

impl FeeSponsorshipNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the FEE_SPONSORSHIP note.
    pub const NUM_STORAGE_ITEMS: usize = FeeSponsorshipNoteStorage::NUM_ITEMS;

    /// Expected number of assets of the FEE_SPONSORSHIP note.
    ///
    /// Must match `NUM_ASSETS` in `asm/standards/notes/fee_sponsorship.masm`.
    pub const NUM_ASSETS: usize = 1;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the FEE_SPONSORSHIP note.
    pub fn script() -> NoteScript {
        FEE_SPONSORSHIP_SCRIPT.clone()
    }

    /// Returns the FEE_SPONSORSHIP note script root.
    pub fn script_root() -> NoteScriptRoot {
        FEE_SPONSORSHIP_SCRIPT.root()
    }

    /// Returns the account ID of the sponsor which created the note.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the tag of the note, which routes it to the network account the feature note
    /// targets.
    ///
    /// The tag is a discovery hint for the network transaction builder; the script itself does not
    /// restrict consumption to the targeted account.
    pub fn tag(&self) -> NoteTag {
        self.tag
    }

    /// Returns the single fungible asset the note carries as the fee.
    pub fn asset(&self) -> FungibleAsset {
        self.asset
    }

    /// Returns the ID of the bound feature note this note sponsors.
    pub fn feature_note_id(&self) -> NoteId {
        self.storage.feature_note_id()
    }

    /// Returns the account ID allowed to reclaim the note after `reclaim_height`.
    pub fn reclaimer(&self) -> AccountId {
        self.storage.reclaimer()
    }

    /// Returns the block height at or after which the reclaimer may reclaim the note, if reclaim is
    /// enabled.
    pub fn reclaim_height(&self) -> Option<BlockNumber> {
        self.storage.reclaim_height()
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: fee_sponsorship_note_builder::State> FeeSponsorshipNoteBuilder<S>
where
    S::SerialNumber: fee_sponsorship_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> FeeSponsorshipNoteBuilder<fee_sponsorship_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<FeeSponsorshipNote> for Note {
    fn from(note: FeeSponsorshipNote) -> Self {
        let assets = NoteAssets::new(vec![note.asset.into()])
            .expect("a single asset is a valid note asset list");

        // Network notes must be public so the network can discover and execute them.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public).with_tag(note.tag);

        Note::new(assets, metadata, note.storage.into_recipient(note.serial_number))
    }
}

impl TryFrom<&Note> for FeeSponsorshipNote {
    type Error = NoteError;

    /// Attempts to interpret `note` as a FEE_SPONSORSHIP note.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the note's script root is not the FEE_SPONSORSHIP script root.
    /// - the note is not public, or carries attachments. Neither shape can be built, so accepting
    ///   one would break the round-trip back into a [`Note`].
    /// - the note storage does not decode as [`FeeSponsorshipNoteStorage`].
    /// - the note does not carry exactly one fungible asset.
    ///
    /// The note script asserts the storage length and the asset count itself, and fee collection
    /// only accepts the collecting account's fungible fee asset, so a note rejected here could
    /// never be consumed as a sponsorship anyway.
    fn try_from(note: &Note) -> Result<Self, Self::Error> {
        if note.script().root() != Self::script_root() {
            return Err(NoteError::other(
                "note script root does not match the FEE_SPONSORSHIP script root",
            ));
        }

        if note.metadata().note_type() != NoteType::Public {
            return Err(NoteError::other("FEE_SPONSORSHIP note must be public"));
        }

        if note.attachments().num_attachments() != 0 {
            return Err(NoteError::other("FEE_SPONSORSHIP note must not carry attachments"));
        }

        let storage = FeeSponsorshipNoteStorage::try_from(note.storage().items())?;

        if note.assets().num_assets() != Self::NUM_ASSETS {
            return Err(NoteError::other("FEE_SPONSORSHIP note must carry exactly one asset"));
        }

        let asset = note
            .assets()
            .iter()
            .next()
            .expect("note carries exactly one asset as asserted above")
            .as_fungible()
            .ok_or_else(|| NoteError::other("FEE_SPONSORSHIP note asset must be fungible"))?;

        Ok(Self {
            sender: note.metadata().sender(),
            serial_number: note.recipient().serial_num(),
            asset,
            tag: note.metadata().tag(),
            storage,
        })
    }
}

// FEE SPONSORSHIP NOTE STORAGE
// ================================================================================================

/// Canonical storage representation for a FEE_SPONSORSHIP note.
///
/// Binds the sponsorship to its feature note by [`NoteId`] and stores the reclaimer together
/// with the optional reclaim height controlling when the note can be reclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSponsorshipNoteStorage {
    feature_note_id: NoteId,
    reclaimer: AccountId,
    reclaim_height: Option<BlockNumber>,
}

impl FeeSponsorshipNoteStorage {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items in this layout.
    pub const NUM_ITEMS: usize = 7;

    // Indices of the storage items. Must match the `*_ITEM` offsets from `STORAGE_PTR` in
    // `asm/standards/notes/fee_sponsorship.masm`. The feature note ID occupies items 0 to 3.
    const FEATURE_NOTE_ID_IDX: usize = 0;
    const RECLAIMER_SUFFIX_IDX: usize = 4;
    const RECLAIMER_PREFIX_IDX: usize = 5;
    const RECLAIM_HEIGHT_IDX: usize = 6;

    /// Creates new FEE_SPONSORSHIP note storage.
    pub fn new(
        feature_note_id: NoteId,
        reclaimer: AccountId,
        reclaim_height: Option<BlockNumber>,
    ) -> Self {
        Self {
            feature_note_id,
            reclaimer,
            reclaim_height,
        }
    }

    /// Consumes the storage and returns a FEE_SPONSORSHIP [`NoteRecipient`] with the provided
    /// serial number.
    pub fn into_recipient(self, serial_num: Word) -> NoteRecipient {
        NoteRecipient::new(serial_num, FeeSponsorshipNote::script(), self.into())
    }

    /// Returns the ID of the feature note the sponsorship is bound to.
    pub fn feature_note_id(&self) -> NoteId {
        self.feature_note_id
    }

    /// Returns the reclaimer account ID.
    pub fn reclaimer(&self) -> AccountId {
        self.reclaimer
    }

    /// Returns the reclaim block height (if any).
    pub fn reclaim_height(&self) -> Option<BlockNumber> {
        self.reclaim_height
    }
}

impl From<FeeSponsorshipNoteStorage> for NoteStorage {
    fn from(storage: FeeSponsorshipNoteStorage) -> Self {
        // an absent height is encoded as zero, which the script reads as "reclaim disabled"
        let reclaim = storage.reclaim_height.map_or(Felt::ZERO, Felt::from);

        // the item order must match the `*_IDX` constants that `try_from` decodes with
        let mut items = Vec::with_capacity(FeeSponsorshipNoteStorage::NUM_ITEMS);
        items.extend_from_slice(storage.feature_note_id.as_word().as_elements());
        items.push(storage.reclaimer.suffix());
        items.push(storage.reclaimer.prefix().as_felt());
        items.push(reclaim);

        NoteStorage::new(items)
            .expect("number of storage items should not exceed max storage items")
    }
}

impl TryFrom<&[Felt]> for FeeSponsorshipNoteStorage {
    type Error = NoteError;

    fn try_from(note_storage: &[Felt]) -> Result<Self, Self::Error> {
        if note_storage.len() != Self::NUM_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: Self::NUM_ITEMS,
                actual: note_storage.len(),
            });
        }

        let feature_note_id = NoteId::from_raw(Word::new([
            note_storage[Self::FEATURE_NOTE_ID_IDX],
            note_storage[Self::FEATURE_NOTE_ID_IDX + 1],
            note_storage[Self::FEATURE_NOTE_ID_IDX + 2],
            note_storage[Self::FEATURE_NOTE_ID_IDX + 3],
        ]));

        let reclaimer = AccountId::try_from_elements(
            note_storage[Self::RECLAIMER_SUFFIX_IDX],
            note_storage[Self::RECLAIMER_PREFIX_IDX],
        )
        .map_err(|err| {
            NoteError::other_with_source("failed to create reclaimer account id", err)
        })?;

        let reclaim_height = decode_optional_block_height(
            note_storage[Self::RECLAIM_HEIGHT_IDX],
            "invalid reclaim height in note storage",
        )?;

        Ok(Self::new(feature_note_id, reclaimer, reclaim_height))
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for FeeSponsorshipNote {
    fn consumption_cycles() -> u32 {
        FEE_SPONSORSHIP_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::AccountType;
    use miden_protocol::asset::{Asset, NonFungibleAsset};
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::note::{NoteAttachment, NoteAttachmentScheme, NoteAttachments};
    use rstest::rstest;

    use super::*;
    use crate::note::P2idNote;

    fn sponsor() -> AccountId {
        AccountId::builder().account_type(AccountType::Private).build_with_seed([1; 32])
    }

    fn faucet() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([2; 32])
    }

    fn other_faucet() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([4; 32])
    }

    fn network_account() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([3; 32])
    }

    fn other_reclaimer() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([5; 32])
    }

    fn feature_note_id() -> NoteId {
        NoteId::from_raw(Word::from([7, 8, 9, 10u32]))
    }

    fn fee_asset() -> FungibleAsset {
        FungibleAsset::new(faucet(), 100).unwrap()
    }

    /// The builder produces a public note tagged for the target, carrying no attachments and the
    /// seven storage items: the bound feature note ID, the reclaimer (defaulting to the sender)
    /// and the reclaim height (zero when reclaim is disabled, which the script reads as "reclaim
    /// disabled").
    #[rstest]
    #[case::default_reclaimer(None, Some(BlockNumber::from(42u32)), sponsor(), Felt::from(42u32))]
    #[case::absent_reclaim_height(None, None, sponsor(), Felt::ZERO)]
    #[case::explicit_reclaimer(Some(other_reclaimer()), None, other_reclaimer(), Felt::ZERO)]
    fn builder_builds_public_sponsorship_note(
        #[case] reclaimer: Option<AccountId>,
        #[case] reclaim_height: Option<BlockNumber>,
        #[case] expected_reclaimer: AccountId,
        #[case] expected_reclaim_height: Felt,
    ) {
        let mut rng = RandomCoin::new(Word::empty());

        let sponsorship = FeeSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(network_account())
            .feature_note_id(feature_note_id())
            .asset(fee_asset())
            .maybe_reclaimer(reclaimer)
            .maybe_reclaim_height(reclaim_height)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(sponsorship.tag(), NoteTag::with_account_target(network_account()));
        assert_eq!(sponsorship.feature_note_id(), feature_note_id());
        assert_eq!(sponsorship.reclaimer(), expected_reclaimer);

        let note = Note::from(sponsorship);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(network_account()));
        assert_eq!(note.storage().num_items(), FeeSponsorshipNote::NUM_STORAGE_ITEMS as u16);
        assert_eq!(&note.storage().items()[..4], feature_note_id().as_word().as_elements());
        assert_eq!(note.storage().items()[4], expected_reclaimer.suffix());
        assert_eq!(note.storage().items()[5], expected_reclaimer.prefix().as_felt());
        assert_eq!(note.storage().items()[6], expected_reclaim_height);
        assert_eq!(note.attachments().num_attachments(), 0);
    }

    /// The tag of a network note must route to a public account.
    #[test]
    fn builder_rejects_private_target() {
        let private_target =
            AccountId::builder().account_type(AccountType::Private).build_with_seed([9; 32]);

        let err = FeeSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(private_target)
            .feature_note_id(feature_note_id())
            .asset(fee_asset())
            .serial_number(Word::empty())
            .build()
            .expect_err("a private target must be rejected");

        assert_matches!(err, NoteError::Other { error_msg, .. } => {
            assert!(error_msg.contains("must be public"))
        });
    }

    // CONVERSION TESTS
    // --------------------------------------------------------------------------------------------

    /// Builds a public note without attachments from the given script, storage items and assets,
    /// bypassing the builder so that shapes the builder cannot produce can be constructed.
    fn note_with(script: NoteScript, storage_items: Vec<Felt>, assets: Vec<Asset>) -> Note {
        note_with_shape(script, storage_items, assets, NoteType::Public, NoteAttachments::default())
    }

    /// Same as [`note_with`], but with the given note type and attachments.
    fn note_with_shape(
        script: NoteScript,
        storage_items: Vec<Felt>,
        assets: Vec<Asset>,
        note_type: NoteType,
        attachments: NoteAttachments,
    ) -> Note {
        let metadata = PartialNoteMetadata::new(sponsor(), note_type)
            .with_tag(NoteTag::with_account_target(network_account()));
        let recipient =
            NoteRecipient::new(Word::empty(), script, NoteStorage::new(storage_items).unwrap());

        Note::with_attachments(NoteAssets::new(assets).unwrap(), metadata, recipient, attachments)
    }

    /// Valid FEE_SPONSORSHIP storage items, with the sponsor as the reclaimer.
    fn valid_storage() -> Vec<Felt> {
        raw_storage(sponsor().suffix(), sponsor().prefix().as_felt(), Felt::from(42u32))
    }

    /// A single attachment, which a FEE_SPONSORSHIP note never carries.
    fn one_attachment() -> NoteAttachments {
        NoteAttachments::new(vec![NoteAttachment::with_word(
            NoteAttachmentScheme::new(64).unwrap(),
            Word::empty(),
        )])
        .unwrap()
    }

    /// A built note round-trips through [`Note`] and back with its fields intact.
    #[test]
    fn try_from_round_trips_built_note() {
        let mut rng = RandomCoin::new(Word::empty());

        let sponsorship = FeeSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(network_account())
            .feature_note_id(feature_note_id())
            .asset(fee_asset())
            .reclaim_height(BlockNumber::from(42u32))
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        let note = Note::from(sponsorship.clone());
        let decoded = FeeSponsorshipNote::try_from(&note)
            .expect("a built FEE_SPONSORSHIP note must be detected");

        assert_eq!(decoded, sponsorship);
        assert_eq!(Note::from(decoded.clone()), note);
        assert_eq!(decoded.sender(), sponsor());
        assert_eq!(decoded.tag(), NoteTag::with_account_target(network_account()));
        assert_eq!(decoded.asset(), fee_asset());
        assert_eq!(decoded.feature_note_id(), feature_note_id());
        assert_eq!(decoded.reclaimer(), sponsor());
        assert_eq!(decoded.reclaim_height(), Some(BlockNumber::from(42u32)));
    }

    /// A note carrying a different script is not a FEE_SPONSORSHIP note, even with matching
    /// storage and assets.
    #[test]
    fn try_from_rejects_other_script_root() {
        let note = note_with(P2idNote::script(), valid_storage(), vec![fee_asset().into()]);

        let err = FeeSponsorshipNote::try_from(&note)
            .expect_err("a note with another script must be rejected");

        assert_matches!(err, NoteError::Other { error_msg, .. } => {
            assert!(error_msg.contains("script root"))
        });
    }

    /// The fee is exactly one fungible asset: the note script asserts the asset count, and fees
    /// are denominated in the collecting account's fee asset, which is fungible.
    #[rstest]
    #[case::no_assets(vec![], "exactly one asset")]
    #[case::two_assets(
        vec![fee_asset().into(), FungibleAsset::new(other_faucet(), 100).unwrap().into()],
        "exactly one asset"
    )]
    #[case::non_fungible_asset(
        vec![NonFungibleAsset::from_parts(faucet(), Word::from([1, 2, 3, 4u32])).into()],
        "must be fungible"
    )]
    fn try_from_rejects_invalid_assets(#[case] assets: Vec<Asset>, #[case] expected_error: &str) {
        let note = note_with(FeeSponsorshipNote::script(), valid_storage(), assets);

        let err = FeeSponsorshipNote::try_from(&note).expect_err("invalid assets must be rejected");

        assert_matches!(err, NoteError::Other { error_msg, .. } => {
            assert!(error_msg.contains(expected_error))
        });
    }

    /// A sponsorship is always built as a public note without attachments, so neither shape parses
    /// back: accepting one would break the round-trip into a [`Note`].
    #[rstest]
    #[case::private_note(NoteType::Private, NoteAttachments::default(), "must be public")]
    #[case::with_attachments(NoteType::Public, one_attachment(), "attachments")]
    fn try_from_rejects_unbuildable_shapes(
        #[case] note_type: NoteType,
        #[case] attachments: NoteAttachments,
        #[case] expected_error: &str,
    ) {
        let note = note_with_shape(
            FeeSponsorshipNote::script(),
            valid_storage(),
            vec![fee_asset().into()],
            note_type,
            attachments,
        );

        let err = FeeSponsorshipNote::try_from(&note)
            .expect_err("a shape the builder cannot produce must be rejected");

        assert_matches!(err, NoteError::Other { error_msg, .. } => {
            assert!(error_msg.contains(expected_error))
        });
    }

    // STORAGE TESTS
    // --------------------------------------------------------------------------------------------

    // A suffix/prefix pair that does not decode to a valid account ID: the prefix's version check
    // runs first, and `888 & 0xf == 8` is not a known version.
    const INVALID_ID_SUFFIX: Felt = Felt::new_unchecked(999);
    const INVALID_ID_PREFIX: Felt = Felt::new_unchecked(888);

    /// Builds the seven storage items with the layout spelled out literally, so these tests pin
    /// the item order independently of the encoder.
    fn raw_storage(reclaimer_suffix: Felt, reclaimer_prefix: Felt, height: Felt) -> Vec<Felt> {
        let mut storage = feature_note_id().as_word().as_elements().to_vec();
        storage.push(reclaimer_suffix);
        storage.push(reclaimer_prefix);
        storage.push(height);
        storage
    }

    /// A zero height decodes as `None`, which the script reads as "reclaim disabled".
    #[rstest]
    #[case::with_reclaim_height(Felt::from(42u32), Some(BlockNumber::from(42u32)))]
    #[case::zero_height_disables_reclaim(Felt::ZERO, None)]
    fn try_from_decodes_valid_storage(
        #[case] height: Felt,
        #[case] expected_reclaim_height: Option<BlockNumber>,
    ) {
        let reclaimer = network_account();
        let storage = raw_storage(reclaimer.suffix(), reclaimer.prefix().as_felt(), height);

        let decoded = FeeSponsorshipNoteStorage::try_from(storage.as_slice())
            .expect("valid FEE_SPONSORSHIP storage should decode");

        assert_eq!(decoded.feature_note_id(), feature_note_id());
        assert_eq!(decoded.reclaimer(), reclaimer);
        assert_eq!(decoded.reclaim_height(), expected_reclaim_height);
    }

    #[test]
    fn try_from_invalid_length_fails() {
        let storage = vec![Felt::ZERO; 3];

        let err = FeeSponsorshipNoteStorage::try_from(storage.as_slice())
            .expect_err("wrong length must fail");

        assert_matches!(
            err,
            NoteError::InvalidNoteStorageLength {
                expected: FeeSponsorshipNoteStorage::NUM_ITEMS,
                actual: 3
            }
        );
    }

    #[test]
    fn try_from_invalid_reclaimer_fails() {
        let storage = raw_storage(INVALID_ID_SUFFIX, INVALID_ID_PREFIX, Felt::ZERO);

        let err = FeeSponsorshipNoteStorage::try_from(storage.as_slice())
            .expect_err("invalid reclaimer encoding must fail");

        assert_matches!(err, NoteError::Other { error_msg, source: Some(_), .. } => {
            assert!(error_msg.contains("reclaimer"));
        });
    }

    /// The encoder and the decoder must agree on the item order. The layout itself is pinned by
    /// the hand-built storage vectors in the `try_from_*` tests above.
    #[test]
    fn storage_round_trips_through_note_storage() {
        let storage = FeeSponsorshipNoteStorage::new(
            feature_note_id(),
            network_account(),
            Some(BlockNumber::from(42u32)),
        );

        let encoded: NoteStorage = storage.into();
        let decoded = FeeSponsorshipNoteStorage::try_from(encoded.items()).unwrap();

        assert_eq!(decoded, storage);
    }
}
