use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::AssetAmount;
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
use miden_protocol::{Felt, Word};

use crate::StandardsLib;
use crate::note::NetworkAccountTarget;
use crate::note::costs::{MIN_BURN_AMOUNT_CONFIG_CONSUMPTION_CYCLES, NoteConsumptionCost};

// NOTE SCRIPT
// ================================================================================================

/// Path to the MIN_BURN_AMOUNT_CONFIG note script procedure in the standards library.
const MIN_BURN_AMOUNT_CONFIG_SCRIPT_PATH: &str =
    "::miden::standards::notes::min_burn_amount_config::main";

// Initialize the MIN_BURN_AMOUNT_CONFIG note script only once.
static MIN_BURN_AMOUNT_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(MIN_BURN_AMOUNT_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains MIN_BURN_AMOUNT_CONFIG note script procedure")
});

// MIN BURN AMOUNT CONFIG NOTE
// ================================================================================================

/// A MinBurnAmountConfig note: updates the minimum burn amount of a faucet's
/// [`MinBurnAmount`](crate::account::policies::MinBurnAmount) burn policy by calling its
/// `set_min_burn_amount` procedure on the faucet that consumes it.
///
/// The new threshold is carried in the note's storage as `[min_burn_amount]` (see the [`Note`]
/// conversion below). Because the storage is fixed at note creation and bound into the note
/// commitment, the authorized party is the note sender: the consuming faucet's
/// `set_min_burn_amount` procedure authorizes the sender through the account-wide
/// [`Authority`](crate::account::access::Authority) component.
///
/// The note is always public (for network execution) and tagged for `target` - the faucet carrying
/// the `MinBurnAmount` component whose threshold is being updated. The `sender` is the account
/// authorized for the update per the faucet's `Authority` configuration (the owner under
/// [`OwnerControlled`](crate::account::access::Authority::OwnerControlled), or a role member under
/// [`RbacControlled`](crate::account::access::Authority::RbacControlled)).
///
/// The note is bound to the target account by a
/// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) attachment: the script asserts that
/// the consuming account matches that target before calling `set_min_burn_amount`, so the note
/// cannot be consumed by a third-party account that merely accepts its sender.
///
/// Note that the threshold only takes effect while `MinBurnAmount` is the faucet's active burn
/// policy; it is stored on the component either way, so it can be configured before the policy is
/// switched in.
///
/// Construct one with the [builder](MinBurnAmountConfigNote::builder); convert it into a protocol
/// [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct MinBurnAmountConfigNote {
    sender: AccountId,
    target: AccountId,
    min_burn_amount: AssetAmount,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl MinBurnAmountConfigNote {
    /// Builds a new [`MinBurnAmountConfigNote`] setting `min_burn_amount` on `target`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `target` is not a public account (the note is bound to it via a `NetworkAccountTarget`,
    ///   which requires a public target).
    /// - the attachments carry a `NetworkAccountTarget` for an account other than `target`.
    /// - the attachments exceed their protocol limit (see [`NoteAttachments::new`]); the target
    ///   attachment occupies one of the available slots when the caller does not supply it.
    #[builder]
    pub fn new(
        #[builder(field)] mut attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        min_burn_amount: AssetAmount,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // Bind the note to `target`: the note script asserts, before calling
        // `set_min_burn_amount`, that the consuming account matches this `NetworkAccountTarget`.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source(
                "failed to bind the MinBurnAmountConfig note to its target account",
                err,
            )
        })?;

        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            target,
            min_burn_amount,
            serial_number,
            attachments,
        })
    }
}

impl MinBurnAmountConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a MinBurnAmountConfig note: the new minimum burn amount.
    ///
    /// Must be kept in sync with `NUM_STORAGE_ITEMS` in the note script, which asserts the count.
    pub const NUM_STORAGE_ITEMS: usize = 1;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the MinBurnAmountConfig note.
    pub fn script() -> NoteScript {
        MIN_BURN_AMOUNT_CONFIG_SCRIPT.clone()
    }

    /// Returns the MinBurnAmountConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        MIN_BURN_AMOUNT_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the update).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed faucet: the account the note is tagged for and bound
    /// to via its `NetworkAccountTarget` attachment (only this account can consume the note).
    pub fn account(&self) -> AccountId {
        self.target
    }

    /// Returns the minimum burn amount the note sets on the faucet.
    pub fn min_burn_amount(&self) -> AssetAmount {
        self.min_burn_amount
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the attachments carried by the note.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: min_burn_amount_config_note_builder::State> MinBurnAmountConfigNoteBuilder<S> {
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

impl<S: min_burn_amount_config_note_builder::State> MinBurnAmountConfigNoteBuilder<S>
where
    S::SerialNumber: min_burn_amount_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> MinBurnAmountConfigNoteBuilder<min_burn_amount_config_note_builder::SetSerialNumber<S>>
    {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<MinBurnAmountConfigNote> for Note {
    fn from(note: MinBurnAmountConfigNote) -> Self {
        // MinBurnAmountConfig notes carry no assets and are always public for network execution;
        // the new threshold lives in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let storage = NoteStorage::new(vec![Felt::from(note.min_burn_amount)])
            .expect("number of storage items should not exceed max storage items");
        let recipient =
            NoteRecipient::new(note.serial_number, MinBurnAmountConfigNote::script(), storage);

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for MinBurnAmountConfigNote {
    fn consumption_cycles() -> u32 {
        MIN_BURN_AMOUNT_CONFIG_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::note::NoteAttachmentScheme;

    use super::*;
    use crate::note::{NetworkAccountTargetError, NoteExecutionHint};

    fn account_id(seed: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([seed; 32])
    }

    /// The builder produces a public, asset-less note tagged for the managed faucet.
    #[test]
    fn builder_builds_min_burn_amount_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let faucet = account_id(1);
        let sender = account_id(2);

        let note = MinBurnAmountConfigNote::builder()
            .sender(sender)
            .target(faucet)
            .min_burn_amount(AssetAmount::new(100).unwrap())
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender);
        assert_eq!(note.account(), faucet);
        assert_eq!(note.min_burn_amount(), AssetAmount::new(100).unwrap());

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(faucet));
        assert_eq!(note.assets().num_assets(), 0);
    }

    /// The built note carries a `NetworkAccountTarget` attachment bound to the faucet, so the note
    /// script can reject consumption by any other account.
    #[test]
    fn note_is_bound_to_target_account() {
        let faucet = account_id(1);
        let note = MinBurnAmountConfigNote::builder()
            .sender(account_id(2))
            .target(faucet)
            .min_burn_amount(AssetAmount::new(100).unwrap())
            .serial_number(Word::empty())
            .build()
            .unwrap();

        let built = Note::from(note);
        let target = NetworkAccountTarget::try_from(built.attachments())
            .expect("note should carry a network account target attachment");
        assert_eq!(target.target_id(), faucet);
    }

    /// A caller-supplied `NetworkAccountTarget` for another account is rejected rather than
    /// silently coexisting with the note's own target.
    #[test]
    fn caller_supplied_target_for_other_account_is_rejected() {
        let rogue_target =
            NetworkAccountTarget::new(account_id(3), NoteExecutionHint::Always).unwrap();

        let err = MinBurnAmountConfigNote::builder()
            .sender(account_id(2))
            .target(account_id(1))
            .min_burn_amount(AssetAmount::new(100).unwrap())
            .serial_number(Word::empty())
            .attachment(rogue_target)
            .build()
            .unwrap_err();

        assert_matches!(err, NoteError::Other { source, .. } => {
            assert_matches!(
              *source.unwrap().downcast().unwrap(),
              NetworkAccountTargetError::TargetMismatch { .. }
            )
        });
    }

    /// A non-public target account is rejected by the builder, since the note binds to it via a
    /// `NetworkAccountTarget`, which requires a public target.
    #[test]
    fn private_target_account_is_rejected() {
        let private_account =
            AccountId::builder().account_type(AccountType::Private).build_with_seed([9; 32]);

        let err = MinBurnAmountConfigNote::builder()
            .sender(account_id(2))
            .target(private_account)
            .min_burn_amount(AssetAmount::new(100).unwrap())
            .serial_number(Word::empty())
            .build()
            .unwrap_err();

        assert_matches!(err, NoteError::Other { source, .. } => {
            assert_matches!(
              *source.unwrap().downcast().unwrap(),
              NetworkAccountTargetError::TargetNotPublic { .. }
            )
        });
    }

    /// The bound target attachment reserves one of the `NoteAttachments::MAX_COUNT` slots, so a
    /// caller supplying `MAX_COUNT` attachments of their own overflows the limit.
    #[test]
    fn caller_attachments_beyond_limit_are_rejected() {
        let mut builder = MinBurnAmountConfigNote::builder()
            .sender(account_id(2))
            .target(account_id(1))
            .min_burn_amount(AssetAmount::new(100).unwrap())
            .serial_number(Word::empty());
        for scheme in 0..NoteAttachments::MAX_COUNT as u16 {
            let extra = NoteAttachment::with_word(
                NoteAttachmentScheme::new(64 + scheme).unwrap(),
                Word::empty(),
            );
            builder = builder.attachment(extra);
        }

        assert!(matches!(builder.build(), Err(NoteError::TooManyAttachments(_))));
    }

    /// Storage is `[min_burn_amount]`.
    #[test]
    fn storage_layout() {
        let min_burn_amount = AssetAmount::new(777).unwrap();

        let note = MinBurnAmountConfigNote::builder()
            .sender(account_id(2))
            .target(account_id(1))
            .min_burn_amount(min_burn_amount)
            .serial_number(Word::empty())
            .build()
            .unwrap();

        let built = Note::from(note);
        assert_eq!(built.storage().items(), [Felt::from(min_burn_amount)]);
        assert_eq!(built.storage().items().len(), MinBurnAmountConfigNote::NUM_STORAGE_ITEMS);
    }

    /// The config-note script root is registered in the [`StandardNote`](crate::note::StandardNote)
    /// reverse lookup.
    #[test]
    fn script_root_is_registered_standard_note() {
        use crate::note::StandardNote;

        let standard = StandardNote::from_script_root(MinBurnAmountConfigNote::script_root())
            .expect("config note script root should be a registered standard note");
        assert_eq!(standard.name(), "MIN_BURN_AMOUNT_CONFIG");
    }
}
