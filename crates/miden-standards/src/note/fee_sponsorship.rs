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

// NOTE SCRIPT
// ================================================================================================

/// Path to the FEE_SPONSORSHIP note script procedure in the standards library.
const FEE_SPONSORSHIP_SCRIPT_PATH: &str = "::miden::standards::notes::fee_sponsorship::main";

// Initialize the FEE_SPONSORSHIP note script only once
static FEE_SPONSORSHIP_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(FEE_SPONSORSHIP_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains FEE_SPONSORSHIP note script procedure")
});

// FEE SPONSORSHIP NOTE
// ================================================================================================

/// A FEE_SPONSORSHIP note: carries the fee for exactly one companion note.
///
/// Under the sponsorship fee model, the companion note (`BURN`, `CLAIM`, `B2AGG`, ...) stays
/// entirely fee-unaware. The fee travels in this separate note, which names the companion note it
/// pays for by carrying that note's [`NoteId`] in its note storage. The note carries no
/// attachments; its tag routes it to the network account the companion note targets.
///
/// # Consumption
///
/// The note may only be consumed in a transaction that also consumes the bound companion note; it
/// does not restrict who that consumer is. Consumption rights are thereby inherited from the
/// companion note: whoever may consume the companion note may take its sponsorship in the same
/// transaction. The script enforces the pairing itself, rather than relying on the account: the
/// sponsor trusts neither the consuming account nor the transaction builder, but does choose the
/// note's script root.
///
/// The mirror-image check (that a companion note is not consumed *without* sponsorship) costs the
/// account rather than the sponsor, and so lives in the account's auth procedure.
///
/// On the sponsorship path the script leaves the note's assets untouched, so the note demands no
/// wallet interface from the account it sponsors. Collecting the assets is the consuming account's
/// job (for a network account, typically its auth procedure); asset conservation forces the
/// transaction to claim them somewhere. Only the reclaim path moves assets, into the reclaimer's
/// vault.
///
/// # Reclaim
///
/// Every consumption without the bound companion note is a reclaim: the note returns to its
/// `reclaimer`, once `reclaim_height` is reached. Reclaim is load-bearing rather than a
/// convenience: if the bound companion note is consumed by some other transaction, this note's
/// presence check can never pass again, and reclaim is the only way to recover the assets. The
/// reclaimer is stored in the note and defaults to the sender.
#[derive(Debug, Clone)]
pub struct FeeSponsorshipNote {
    sender: AccountId,
    serial_number: Word,
    assets: NoteAssets,
    target: AccountId,
    companion_note_id: NoteId,
    reclaimer: AccountId,
    reclaim_height: Option<BlockNumber>,
}

#[bon::bon]
impl FeeSponsorshipNote {
    /// Builds a new [`FeeSponsorshipNote`] sponsoring `companion_note_id`, tagged for `target`.
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
                if !target_id.is_public() {
                    return Err(NoteError::other(
                        "fee sponsorship target account must be public",
                    ));
                }
                Ok(target_id)
            },
        )]
        target: AccountId,
        companion_note_id: NoteId,
        serial_number: Word,
        reclaimer: Option<AccountId>,
        reclaim_height: Option<BlockNumber>,
    ) -> Result<Self, NoteError> {
        if assets.is_empty() {
            return Err(NoteError::other("a FEE_SPONSORSHIP note must contain at least one asset"));
        }

        let assets = NoteAssets::new(assets)?;
        // The reclaimer is the account allowed to reclaim the note; it defaults to the sender.
        let reclaimer = reclaimer.unwrap_or(sender);

        Ok(Self {
            sender,
            serial_number,
            assets,
            target,
            companion_note_id,
            reclaimer,
            reclaim_height,
        })
    }
}

impl FeeSponsorshipNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the FEE_SPONSORSHIP note.
    ///
    /// The layout is `[COMPANION_NOTE_ID, reclaimer_suffix, reclaimer_prefix,
    /// reclaim_block_height]`, matching the `*_ITEM` offsets in
    /// `asm/standards/notes/fee_sponsorship.masm`.
    pub const NUM_STORAGE_ITEMS: usize = 7;

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

    /// Returns the account ID of the network account the note's tag routes to.
    ///
    /// The tag is a discovery hint for the network transaction builder; the script itself does not
    /// restrict consumption to this account.
    pub fn target_id(&self) -> AccountId {
        self.target
    }

    /// Returns the ID of the companion note this note sponsors.
    pub fn companion_note_id(&self) -> NoteId {
        self.companion_note_id
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

impl<S: fee_sponsorship_note_builder::State> FeeSponsorshipNoteBuilder<S> {
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
        // Network notes must be public so the network can discover and execute them. The tag routes
        // the note to the network account the companion note targets.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));

        // Storage layout must match the `*_ITEM` offsets in the note's MASM script:
        // [COMPANION_NOTE_ID, reclaimer_suffix, reclaimer_prefix, reclaim_block_height]. An absent
        // reclaim height is encoded as 0, which the script reads as "reclaim disabled".
        let mut items = Vec::with_capacity(FeeSponsorshipNote::NUM_STORAGE_ITEMS);
        items.extend_from_slice(note.companion_note_id.as_word().as_elements());
        items.push(note.reclaimer.suffix());
        items.push(note.reclaimer.prefix().as_felt());
        items.push(Felt::from(note.reclaim_height.unwrap_or_default().as_u32()));
        let storage = NoteStorage::new(items)
            .expect("seven storage items never exceed the note storage limit");

        let recipient =
            NoteRecipient::new(note.serial_number, FeeSponsorshipNote::script(), storage);

        Note::new(note.assets, metadata, recipient)
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

    fn companion_note_id() -> NoteId {
        NoteId::from_raw(Word::from([7, 8, 9, 10u32]))
    }

    /// The builder produces a public note tagged for the target, carrying no attachments and the
    /// seven storage items.
    #[test]
    fn builder_builds_public_sponsorship_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let asset = FungibleAsset::new(faucet(), 100).unwrap();

        let sponsorship = FeeSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(network_account())
            .unwrap()
            .companion_note_id(companion_note_id())
            .asset(asset)
            .reclaim_height(BlockNumber::from(42u32))
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(sponsorship.target_id(), network_account());
        assert_eq!(sponsorship.companion_note_id(), companion_note_id());

        let note = Note::from(sponsorship);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(network_account()));
        assert_eq!(note.storage().num_items(), FeeSponsorshipNote::NUM_STORAGE_ITEMS as u16);
        // The bound companion note ID comes first, then the reclaimer (defaulting to the sender),
        // then the reclaim height.
        assert_eq!(&note.storage().items()[..4], companion_note_id().as_word().as_elements());
        assert_eq!(note.storage().items()[4], sponsor().suffix());
        assert_eq!(note.storage().items()[5], sponsor().prefix().as_felt());
        assert_eq!(note.storage().items()[6], Felt::from(42u32));
        assert_eq!(note.attachments().num_attachments(), 0);
    }

    /// A reclaim height of `None` encodes as 0, which the script reads as "reclaim disabled".
    #[test]
    fn absent_reclaim_height_encodes_as_zero() {
        let mut rng = RandomCoin::new(Word::empty());
        let asset = FungibleAsset::new(faucet(), 100).unwrap();

        let sponsorship = FeeSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(network_account())
            .unwrap()
            .companion_note_id(companion_note_id())
            .asset(asset)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        let note = Note::from(sponsorship);
        assert_eq!(note.storage().items()[6], Felt::from(0u32));
    }

    /// An explicit reclaimer overrides the sender in the note storage.
    #[test]
    fn explicit_reclaimer_is_stored() {
        let mut rng = RandomCoin::new(Word::empty());
        let asset = FungibleAsset::new(faucet(), 100).unwrap();
        let reclaimer =
            AccountId::builder().account_type(AccountType::Public).build_with_seed([5; 32]);

        let sponsorship = FeeSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(network_account())
            .unwrap()
            .companion_note_id(companion_note_id())
            .asset(asset)
            .reclaimer(reclaimer)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(sponsorship.reclaimer(), reclaimer);

        let note = Note::from(sponsorship);
        assert_eq!(note.storage().items()[4], reclaimer.suffix());
        assert_eq!(note.storage().items()[5], reclaimer.prefix().as_felt());
    }

    /// A sponsorship that pays nothing is never intended, so the constructor rejects it.
    #[test]
    fn builder_rejects_empty_assets() {
        let err = FeeSponsorshipNote::builder()
            .sender(sponsor())
            .target_account(network_account())
            .unwrap()
            .companion_note_id(companion_note_id())
            .serial_number(Word::empty())
            .build()
            .expect_err("a sponsorship without assets must be rejected");

        assert_matches!(err, NoteError::Other { error_msg, .. } => {
            assert!(error_msg.contains("must contain at least one asset"))
        });
    }

    /// The tag of a network note must route to a public account.
    #[test]
    fn builder_rejects_private_target() {
        let private_target =
            AccountId::builder().account_type(AccountType::Private).build_with_seed([9; 32]);

        let result = FeeSponsorshipNote::builder().sender(sponsor()).target_account(private_target);

        assert!(result.is_err(), "a private target must be rejected");
    }
}
