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
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::utils::sync::LazyLock;

use crate::StandardsLib;
use crate::note::NetworkAccountTarget;
use crate::note::costs::{BURN_CONSUMPTION_CYCLES, NoteConsumptionCost};

// NOTE SCRIPT
// ================================================================================================

/// Path to the BURN note script procedure in the standards library.
const BURN_SCRIPT_PATH: &str = "::miden::standards::notes::burn::main";

// Initialize the BURN note script only once
static BURN_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(BURN_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains BURN note script procedure")
});

// BURN NOTE
// ================================================================================================

/// A BURN note: instructs a faucet to burn the asset carried by the note and embedded in its
/// storage.
///
/// When consumed by the faucet that issued the asset, the note's asset is destroyed via the
/// faucet's `receive_and_burn` procedure. The single BURN script works against both fungible and
/// non-fungible faucets: it detects the faucet kind by reflection (via the `CodeInspection`
/// component) and calls the matching `receive_and_burn`. BURN notes are always public so they are
/// visible on-chain and discoverable by the network; whether consuming one requires a signature
/// depends on the target faucet's auth component.
///
/// A note whose faucet is public is routed to it by a
/// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) attachment derived from the asset. A
/// private faucet can never be a network account, so such a note carries no target.
///
/// Construct one with the [builder](BurnNote::builder); convert it into a protocol [`Note`]
/// infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct BurnNote {
    sender: AccountId,
    serial_number: Word,
    asset: Asset,
    attachments: NoteAttachments,
}

#[bon::bon]
impl BurnNote {
    /// Builds a new [`BurnNote`] that burns `asset` against the faucet that issued it.
    ///
    /// The target faucet is the asset's own issuing faucet.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the attachments carry a `NetworkAccountTarget` for an account other than that faucet.
    /// - the attachments exceed their protocol limit (see [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] mut attachments: Vec<NoteAttachment>,
        sender: AccountId,
        #[builder(into)] asset: Asset,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // The network routes the note on this attachment; the asset it carries is what binds the
        // script to the same faucet on consumption. That bind is a plain value comparison and so
        // works for a private faucet too, which has no network target to derive.
        NetworkAccountTarget::ensure_presence_if_public(&mut attachments, asset.faucet_id())
            .map_err(|err| {
                NoteError::other_with_source("failed to target the BURN note at its faucet", err)
            })?;

        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            serial_number,
            asset,
            attachments,
        })
    }
}

impl BurnNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items of the BURN note: ASSET_ID(4) + ASSET_VALUE(4).
    pub const NUM_STORAGE_ITEMS: usize = 8;

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

    /// Returns the account ID of the faucet that will burn the asset (the asset's own faucet).
    pub fn faucet_id(&self) -> AccountId {
        self.asset.faucet_id()
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the asset carried by the note (the asset to be burned).
    pub fn asset(&self) -> Asset {
        self.asset
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
        // BURN notes are always public for network execution. The NetworkAccountTarget attachment
        // routes the note to the asset's issuing faucet, while storage binds the script to the
        // asset it must burn.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public);
        let storage = NoteStorage::new(note.asset.as_elements().to_vec())
            .expect("an asset always fits in BURN note storage");
        let recipient = NoteRecipient::new(note.serial_number, BurnNote::script(), storage);

        let assets = NoteAssets::new(vec![note.asset])
            .expect("a single asset never exceeds the note asset limit");
        Note::with_attachments(assets, metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for BurnNote {
    fn consumption_cycles() -> u32 {
        BURN_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountType;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::note::NoteTag;

    use super::*;
    use crate::note::{NetworkNoteExt, NoteExecutionHint};

    fn sender() -> AccountId {
        AccountId::builder().account_type(AccountType::Private).build_with_seed([1; 32])
    }

    fn faucet() -> AccountId {
        AccountId::builder().account_type(AccountType::Public).build_with_seed([2; 32])
    }

    fn private_faucet() -> AccountId {
        AccountId::builder().account_type(AccountType::Private).build_with_seed([2; 32])
    }

    fn build_burn_note(faucet_id: AccountId) -> BurnNote {
        let mut rng = RandomCoin::new(Word::empty());
        BurnNote::builder()
            .sender(sender())
            .asset(FungibleAsset::new(faucet_id, 100).unwrap())
            .generate_serial_number(&mut rng)
            .build()
            .unwrap()
    }

    /// The builder produces a public note carrying the asset to burn and routed to its faucet by a
    /// derived network target. How that target treats caller-supplied attachments is covered by the
    /// `network_account_target` tests.
    #[test]
    fn builder_builds_public_burn_note() {
        let asset = FungibleAsset::new(faucet(), 100).unwrap();

        let burn_note = build_burn_note(faucet());

        assert_eq!(burn_note.sender(), sender());
        assert_eq!(burn_note.faucet_id(), faucet());
        assert_eq!(burn_note.asset(), asset.into());
        assert_ne!(burn_note.serial_number(), Word::empty());
        assert_eq!(burn_note.attachments().num_attachments(), 1);

        let note = Note::from(burn_note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::default());
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.recipient().storage().items(), Asset::from(asset).as_elements());
        assert!(note.is_network_note());

        let target = NetworkAccountTarget::try_from(note.attachments()).unwrap();
        assert_eq!(target.target_id(), faucet());
        assert_eq!(target.execution_hint(), NoteExecutionHint::Always);
    }

    /// A private faucet is never a network account, so no target is derived for it. The note stays
    /// consumable by that faucet, which is bound by the asset the note carries.
    #[test]
    fn builder_omits_network_target_for_private_faucet() {
        let burn_note = build_burn_note(private_faucet());

        assert_eq!(burn_note.attachments().num_attachments(), 0);
        assert!(!Note::from(burn_note).is_network_note());
    }
}
