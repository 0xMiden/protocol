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
    NoteAttachment,
    NoteAttachments,
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

use crate::StandardsLib;
use crate::note::{FeeSponsorship, NetworkAccountTarget, NoteExecutionHint};

// NOTE SCRIPT
// ================================================================================================

/// Path to the NETWORK_SPONSORSHIP note script procedure in the standards library.
const NETWORK_SPONSORSHIP_SCRIPT_PATH: &str =
    "::miden::standards::notes::network_sponsorship::main";

// Initialize the NETWORK_SPONSORSHIP note script only once
static NETWORK_SPONSORSHIP_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(NETWORK_SPONSORSHIP_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains NETWORK_SPONSORSHIP note script procedure")
});

// NETWORK SPONSORSHIP NOTE
// ================================================================================================

/// A NETWORK_SPONSORSHIP note: carries the fee for exactly one feature note.
///
/// Under the sponsorship fee model, the feature note (`BURN`, `CLAIM`, `B2AGG`, ...) stays entirely
/// fee-unaware. The fee travels in this separate note, which names the feature note it pays for by
/// carrying that note's [`NoteId`] in a [`FeeSponsorship`] attachment, and names the network
/// account that may consume it in a [`NetworkAccountTarget`] attachment.
///
/// # Consumption
///
/// The target network account may consume the note, but only in a transaction that also consumes
/// the bound feature note. The script enforces this itself, rather than relying on the account: the
/// sponsor trusts neither the network account nor the transaction builder, but does choose the
/// note's script root.
///
/// The mirror-image check -- that a feature note is not consumed *without* sponsorship -- costs the
/// account rather than the sponsor, and so lives in the account's auth procedure.
///
/// # Reclaim
///
/// Anyone other than the target may only reclaim the note back to its `reclaimer`, once
/// `reclaim_height` is reached. This is load-bearing rather than a convenience: if the bound
/// feature note is consumed by some other transaction, this note's presence check can never pass
/// again, and reclaim is the only way to recover the assets. The reclaimer is stored in the note
/// and defaults to the sender.
#[derive(Debug, Clone)]
pub struct NetworkSponsorshipNote {
    sender: AccountId,
    serial_number: Word,
    assets: NoteAssets,
    target: NetworkAccountTarget,
    feature_note_id: NoteId,
    reclaimer: AccountId,
    reclaim_height: Option<BlockNumber>,
}

#[bon::bon]
impl NetworkSponsorshipNote {
    /// Builds a new [`NetworkSponsorshipNote`] sponsoring `feature_note_id` against `target`.
    ///
    /// Prefer the builder's `generate_serial_number` over supplying a serial number by hand.
    ///
    /// The reclaimer, the account allowed to reclaim the note after `reclaim_height`, defaults to
    /// `sender` when left unset.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `assets` is empty. A sponsorship that pays nothing is never intended.
    /// - `assets` contains duplicates or exceeds the protocol limit (see [`NoteAssets::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] assets: Vec<Asset>,
        sender: AccountId,
        #[builder(
            name = target_account,
            with = |target_id: AccountId| -> Result<_, NoteError> {
                NetworkAccountTarget::new(target_id, NoteExecutionHint::Always).map_err(|error| {
                    NoteError::other_with_source("invalid network sponsorship target", error)
                })
            },
        )]
        target: NetworkAccountTarget,
        feature_note_id: NoteId,
        serial_number: Word,
        reclaimer: Option<AccountId>,
        reclaim_height: Option<BlockNumber>,
    ) -> Result<Self, NoteError> {
        if assets.is_empty() {
            return Err(NoteError::other(
                "a NETWORK_SPONSORSHIP note must contain at least one asset",
            ));
        }

        let assets = NoteAssets::new(assets)?;
        // The reclaimer is the account allowed to reclaim the note; it defaults to the sender.
        let reclaimer = reclaimer.unwrap_or(sender);

        Ok(Self {
            sender,
            serial_number,
            assets,
            target,
            feature_note_id,
            reclaimer,
            reclaim_height,
        })
    }
}

impl NetworkSponsorshipNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the NETWORK_SPONSORSHIP note.
    ///
    /// The layout is `[reclaimer_suffix, reclaimer_prefix, reclaim_block_height]`, matching the
    /// `*_PTR` offsets in `asm/standards/notes/network_sponsorship.masm`.
    pub const NUM_STORAGE_ITEMS: usize = 3;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the NETWORK_SPONSORSHIP note.
    pub fn script() -> NoteScript {
        NETWORK_SPONSORSHIP_SCRIPT.clone()
    }

    /// Returns the NETWORK_SPONSORSHIP note script root.
    pub fn script_root() -> NoteScriptRoot {
        NETWORK_SPONSORSHIP_SCRIPT.root()
    }

    /// Returns the account ID of the network account that may consume the note.
    pub fn target_id(&self) -> AccountId {
        self.target.target_id()
    }

    /// Returns the ID of the feature note this note sponsors.
    pub fn feature_note_id(&self) -> NoteId {
        self.feature_note_id
    }

    /// Returns the account ID allowed to reclaim the note after `reclaim_height`.
    pub fn reclaimer(&self) -> AccountId {
        self.reclaimer
    }

    /// Returns the block height at or after which the reclaimer may reclaim the note, if reclaim is
    /// enabled.
    pub fn reclaim_height(&self) -> Option<BlockNumber> {
        self.reclaim_height
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: network_sponsorship_note_builder::State> NetworkSponsorshipNoteBuilder<S> {
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

impl<S: network_sponsorship_note_builder::State> NetworkSponsorshipNoteBuilder<S>
where
    S::SerialNumber: network_sponsorship_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> NetworkSponsorshipNoteBuilder<network_sponsorship_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<NetworkSponsorshipNote> for Note {
    fn from(note: NetworkSponsorshipNote) -> Self {
        // Network notes must be public so the network can discover and execute them. The tag routes
        // the note to the network account that may consume it.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target.target_id()));

        // Storage layout must match the `*_PTR` offsets in the note's MASM script:
        // [reclaimer_suffix, reclaimer_prefix, reclaim_block_height]. An absent reclaim height is
        // encoded as 0, which the script reads as "reclaim disabled".
        let storage = NoteStorage::new(vec![
            note.reclaimer.suffix(),
            note.reclaimer.prefix().as_felt(),
            Felt::from(note.reclaim_height.unwrap_or_default().as_u32()),
        ])
        .expect("three storage items never exceed the note storage limit");

        let recipient =
            NoteRecipient::new(note.serial_number, NetworkSponsorshipNote::script(), storage);

        let attachments = NoteAttachments::new(vec![
            NoteAttachment::from(note.target),
            NoteAttachment::from(FeeSponsorship::new(note.feature_note_id)),
        ])
        .expect("two attachments never exceed the note attachment limit");

        Note::with_attachments(note.assets, metadata, recipient, attachments)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::AccountType;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::crypto::rand::RandomCoin;

    use super::*;

    fn sponsor() -> AccountId {
        AccountId::builder().account_type(AccountType::Private).build_with_seed([1; 32])
    }

    fn faucet() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([2; 32])
    }

    fn network_account() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([3; 32])
    }

    fn feature_note_id() -> NoteId {
        NoteId::from_raw(Word::from([7, 8, 9, 10u32]))
    }

    /// The builder produces a public note tagged for the target, carrying both attachments and the
    /// three storage items.
    #[test]
    fn builder_builds_public_sponsorship_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let asset = FungibleAsset::new(faucet(), 100).unwrap();

        let sponsorship = NetworkSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(network_account())
            .unwrap()
            .feature_note_id(feature_note_id())
            .asset(asset)
            .reclaim_height(BlockNumber::from(42u32))
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(sponsorship.target_id(), network_account());
        assert_eq!(sponsorship.feature_note_id(), feature_note_id());

        let note = Note::from(sponsorship);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(network_account()));
        assert_eq!(note.storage().num_items(), NetworkSponsorshipNote::NUM_STORAGE_ITEMS as u16);
        // The reclaimer defaults to the sender, followed by the reclaim height.
        assert_eq!(note.storage().items()[0], sponsor().suffix());
        assert_eq!(note.storage().items()[1], sponsor().prefix().as_felt());
        assert_eq!(note.storage().items()[2], Felt::from(42u32));
        assert_eq!(note.attachments().num_attachments(), 2);

        // Both attachments must decode back to what was put in.
        let target = NetworkAccountTarget::try_from(note.attachments()).unwrap();
        assert_eq!(target.target_id(), network_account());

        let sponsorship = FeeSponsorship::try_from(note.attachments()).unwrap();
        assert_eq!(sponsorship.feature_note_id(), feature_note_id());
    }

    /// A reclaim height of `None` encodes as 0, which the script reads as "reclaim disabled".
    #[test]
    fn absent_reclaim_height_encodes_as_zero() {
        let mut rng = RandomCoin::new(Word::empty());
        let asset = FungibleAsset::new(faucet(), 100).unwrap();

        let sponsorship = NetworkSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(network_account())
            .unwrap()
            .feature_note_id(feature_note_id())
            .asset(asset)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        let note = Note::from(sponsorship);
        assert_eq!(note.storage().items()[2], Felt::from(0u32));
    }

    /// An explicit reclaimer overrides the sender in the note storage.
    #[test]
    fn explicit_reclaimer_is_stored() {
        let mut rng = RandomCoin::new(Word::empty());
        let asset = FungibleAsset::new(faucet(), 100).unwrap();
        let reclaimer =
            AccountId::builder().account_type(AccountType::Public).build_with_seed([5; 32]);

        let sponsorship = NetworkSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(network_account())
            .unwrap()
            .feature_note_id(feature_note_id())
            .asset(asset)
            .reclaimer(reclaimer)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(sponsorship.reclaimer(), reclaimer);

        let note = Note::from(sponsorship);
        assert_eq!(note.storage().items()[0], reclaimer.suffix());
        assert_eq!(note.storage().items()[1], reclaimer.prefix().as_felt());
    }

    /// A sponsorship that pays nothing is never intended, so the constructor rejects it.
    #[test]
    fn builder_rejects_empty_assets() {
        let err = NetworkSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(network_account())
            .unwrap()
            .feature_note_id(feature_note_id())
            .serial_number(Word::empty())
            .build()
            .expect_err("a sponsorship without assets must be rejected");

        assert_matches!(err, NoteError::Other { error_msg, .. } => {
            assert!(error_msg.contains("must contain at least one asset"))
        });
    }

    /// The target of a network note must be a public account.
    #[test]
    fn builder_rejects_private_target() {
        let private_target =
            AccountId::builder().account_type(AccountType::Private).build_with_seed([9; 32]);

        let result = NetworkSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(private_target);

        assert!(result.is_err(), "a private target must be rejected");
    }
}
