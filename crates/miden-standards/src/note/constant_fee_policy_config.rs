use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::FungibleAsset;
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
use crate::note::costs::{CONSTANT_FEE_POLICY_CONFIG_CONSUMPTION_CYCLES, NoteConsumptionCost};

// NOTE SCRIPT
// ================================================================================================

/// Path to the CONSTANT_FEE_POLICY_CONFIG note script procedure in the standards library.
const CONSTANT_FEE_POLICY_CONFIG_SCRIPT_PATH: &str =
    "::miden::standards::notes::constant_fee_policy_config::main";

// Initialize the CONSTANT_FEE_POLICY_CONFIG note script only once.
static CONSTANT_FEE_POLICY_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(CONSTANT_FEE_POLICY_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains CONSTANT_FEE_POLICY_CONFIG note script procedure")
});

// CONSTANT FEE POLICY CONFIG NOTE
// ================================================================================================

/// A ConstantFeePolicyConfig note: schedules a fee for a note script root in a
/// [`BasicConstantFeePolicy`](crate::account::fees::BasicConstantFeePolicy)'s fee schedule by
/// calling the [`ConstantFeeManager`](crate::account::fees::ConstantFeeManager)'s
/// `set_note_fee` procedure on the account that consumes it.
///
/// The note script root and fee asset are carried in the note's storage as
/// `[NOTE_SCRIPT_ROOT, FEE_ASSET_ID, FEE_ASSET_VALUE]` (see the [`Note`] conversion below). Because
/// the storage is fixed at note creation and bound into the note commitment, the authorized party
/// is the note sender: the consuming account's `set_note_fee` procedure authorizes the sender
/// through the account-wide [`Authority`](crate::account::access::Authority) component, which the
/// requirements below mandate be owner- or role-controlled. The fee asset's ID must match the
/// account's configured fee asset ID.
///
/// The note is bound to the target `account` by a
/// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) attachment: the script asserts the
/// consuming account matches that target before calling `set_note_fee`, so the note cannot be
/// consumed by a third-party account that merely accepts its sender.
///
/// # Consuming account requirements
///
/// The fee schedule and the fee asset ID live on an
/// [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount), so this note is consumed by a
/// network account, which must:
/// - install the [`ConstantFeeManager`](crate::account::fees::ConstantFeeManager) gated by an
///   [`Authority`](crate::account::access::Authority) in
///   [`OwnerControlled`](crate::account::access::Authority::OwnerControlled) or
///   [`RbacControlled`](crate::account::access::Authority::RbacControlled) mode. It must NOT use
///   [`AuthControlled`](crate::account::access::Authority::AuthControlled): that makes
///   `set_note_fee` permissionless, letting anyone author a config note that rewrites the fee
///   schedule.
/// - allowlist this note's own script root ([`Self::script_root`]) so a network transaction is
///   allowed to consume it.
/// - already carry a set-marked fee schedule entry for this note's own script root (typically a 0
///   fee, so the note is free to consume). A network account prices every consumed note through its
///   active fee policy, so an unscheduled config-note root would itself be unpriced. This is
///   typically bootstrapped at account creation, before the first config note is consumed.
///
/// # Operational notes
///
/// - Allowlisting and 0-fee-scheduling this note's script root makes it a free, unauthenticated
///   entry point into the account's network-transaction queue: anyone can author a public note with
///   this (publicly known) script root targeting the account. Unauthorized or wrongly targeted ones
///   abort at the target/authorization checks with no state change and no fee, but because the
///   transaction aborts, the nullifier is never produced - such notes are never consumable and
///   remain as permanently-unconsumable entries, which may require operator-side filtering. This is
///   inherent to any allowlisted network-note root, not specific to this note.
/// - The scheduled `note_script_root` is unconstrained, so an authorized config note can set the
///   fee for its *own* script root. Scheduling a non-zero fee there can make subsequent config
///   notes unpayable, and since the manager is only reachable through a consumed note, that bricks
///   fee management unless the account also exposes a transaction-script path to `set_note_fee`.
///   Keep this note's own root scheduled at 0.
#[derive(Debug, Clone)]
pub struct ConstantFeePolicyConfigNote {
    sender: AccountId,
    target: AccountId,
    note_script_root: NoteScriptRoot,
    fee_asset: FungibleAsset,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl ConstantFeePolicyConfigNote {
    /// Builds a new [`ConstantFeePolicyConfigNote`] scheduling `fee_asset` for
    /// `note_script_root` on `account`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `account` is not a public account (the note is bound to it via a `NetworkAccountTarget`,
    ///   which requires a public target).
    /// - the attachments carry a `NetworkAccountTarget` for an account other than `account`.
    /// - the attachments exceed their protocol limit (see [`NoteAttachments::new`]); the target
    ///   attachment occupies one of the available slots when the caller does not supply it.
    #[builder]
    pub fn new(
        #[builder(field)] mut attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        note_script_root: NoteScriptRoot,
        fee_asset: FungibleAsset,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // Bind the note to `account`: the note script asserts, before calling `set_note_fee`, that
        // the consuming account matches this `NetworkAccountTarget`.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source("failed to bind the note to its target account", err)
        })?;

        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            target,
            note_script_root,
            fee_asset,
            serial_number,
            attachments,
        })
    }
}

impl ConstantFeePolicyConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a ConstantFeePolicyConfig note: the note script root word
    /// plus the fee asset (its ID and value words).
    ///
    /// Must be kept in sync with `NUM_STORAGE_ITEMS` in the note script, which asserts the count.
    pub const NUM_STORAGE_ITEMS: usize = 12;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the ConstantFeePolicyConfig note.
    pub fn script() -> NoteScript {
        CONSTANT_FEE_POLICY_CONFIG_SCRIPT.clone()
    }

    /// Returns the ConstantFeePolicyConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        CONSTANT_FEE_POLICY_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed account: the account the note is tagged for and bound
    /// to via its `NetworkAccountTarget` attachment (only this account can consume the note).
    pub fn account(&self) -> AccountId {
        self.target
    }

    /// Returns the note script root the fee is scheduled for.
    pub fn note_script_root(&self) -> NoteScriptRoot {
        self.note_script_root
    }

    /// Returns the fee asset scheduled for the note script root.
    pub fn fee_asset(&self) -> FungibleAsset {
        self.fee_asset
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the attachments carried by the note.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the note storage values encoding the action, laid out as
    /// `[NOTE_SCRIPT_ROOT, FEE_ASSET_ID, FEE_ASSET_VALUE]`.
    fn to_storage_values(&self) -> Vec<Felt> {
        let mut values = Vec::with_capacity(Self::NUM_STORAGE_ITEMS);
        values.extend_from_slice(self.note_script_root.as_word().as_elements());
        values.extend_from_slice(self.fee_asset.to_id_word().as_elements());
        values.extend_from_slice(self.fee_asset.to_value_word().as_elements());
        values
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: constant_fee_policy_config_note_builder::State> ConstantFeePolicyConfigNoteBuilder<S> {
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

impl<S: constant_fee_policy_config_note_builder::State> ConstantFeePolicyConfigNoteBuilder<S>
where
    S::SerialNumber: constant_fee_policy_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> ConstantFeePolicyConfigNoteBuilder<
        constant_fee_policy_config_note_builder::SetSerialNumber<S>,
    > {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<ConstantFeePolicyConfigNote> for Note {
    fn from(note: ConstantFeePolicyConfigNote) -> Self {
        // ConstantFeePolicyConfig notes carry no assets and are always public for network
        // execution; the note script root and fee asset live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let storage = NoteStorage::new(note.to_storage_values())
            .expect("number of storage items should not exceed max storage items");
        let recipient =
            NoteRecipient::new(note.serial_number, ConstantFeePolicyConfigNote::script(), storage);

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for ConstantFeePolicyConfigNote {
    fn consumption_cycles() -> u32 {
        CONSTANT_FEE_POLICY_CONFIG_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::rand::RandomCoin;
    use miden_protocol::note::NoteAttachmentScheme;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    use super::*;
    use crate::note::{NetworkAccountTargetError, NoteExecutionHint};

    fn account_id(seed: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([seed; 32])
    }

    fn note_root(seed: u32) -> NoteScriptRoot {
        NoteScriptRoot::from_array([seed, seed + 1, seed + 2, seed + 3])
    }

    fn fee_asset(amount: u64) -> FungibleAsset {
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), amount).unwrap()
    }

    /// The builder produces a public, asset-less note tagged for the managed account.
    #[test]
    fn builder_builds_constant_fee_policy_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let account = account_id(1);
        let sender = account_id(2);

        let note = ConstantFeePolicyConfigNote::builder()
            .sender(sender)
            .target(account)
            .note_script_root(note_root(10))
            .fee_asset(fee_asset(500))
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender);
        assert_eq!(note.account(), account);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(account));
        assert_eq!(note.assets().num_assets(), 0);
    }

    /// The built note carries a `NetworkAccountTarget` attachment bound to `account`, so the note
    /// script can reject consumption by any other account.
    #[test]
    fn note_is_bound_to_target_account() {
        let account = account_id(1);
        let note = ConstantFeePolicyConfigNote::builder()
            .sender(account_id(2))
            .target(account)
            .note_script_root(note_root(10))
            .fee_asset(fee_asset(500))
            .serial_number(Word::empty())
            .build()
            .unwrap();

        let built = Note::from(note);
        let target = NetworkAccountTarget::try_from(built.attachments())
            .expect("note should carry a network account target attachment");
        assert_eq!(target.target_id(), account);
    }

    /// A caller-supplied `NetworkAccountTarget` for another account is rejected rather than
    /// silently coexisting with the note's own target.
    #[test]
    fn caller_supplied_target_for_other_account_is_rejected() {
        let rogue_target =
            NetworkAccountTarget::new(account_id(3), NoteExecutionHint::Always).unwrap();

        let err = ConstantFeePolicyConfigNote::builder()
            .sender(account_id(2))
            .target(account_id(1))
            .note_script_root(note_root(10))
            .fee_asset(fee_asset(500))
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

    /// A non-public `account` is rejected by the builder, since the note binds to it via a
    /// `NetworkAccountTarget`, which requires a public target.
    #[test]
    fn private_target_account_is_rejected() {
        let private_account =
            AccountId::builder().account_type(AccountType::Private).build_with_seed([9; 32]);

        let err = ConstantFeePolicyConfigNote::builder()
            .sender(account_id(2))
            .target(private_account)
            .note_script_root(note_root(10))
            .fee_asset(fee_asset(500))
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
        let mut builder = ConstantFeePolicyConfigNote::builder()
            .sender(account_id(2))
            .target(account_id(1))
            .note_script_root(note_root(10))
            .fee_asset(fee_asset(500))
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

    /// Storage is `[NOTE_SCRIPT_ROOT, FEE_ASSET_ID, FEE_ASSET_VALUE]`.
    #[test]
    fn storage_layout() {
        let root = note_root(10);
        let asset = fee_asset(777);

        let note = ConstantFeePolicyConfigNote::builder()
            .sender(account_id(2))
            .target(account_id(1))
            .note_script_root(root)
            .fee_asset(asset)
            .serial_number(Word::empty())
            .build()
            .unwrap();

        let built = Note::from(note);
        let mut expected = Vec::from(root.as_word().as_elements());
        expected.extend_from_slice(asset.to_id_word().as_elements());
        expected.extend_from_slice(asset.to_value_word().as_elements());
        assert_eq!(built.storage().items(), expected.as_slice());
        assert_eq!(built.storage().items().len(), ConstantFeePolicyConfigNote::NUM_STORAGE_ITEMS);
    }

    /// The config-note script root is registered in the [`StandardNote`](crate::note::StandardNote)
    /// reverse lookup.
    #[test]
    fn script_root_is_registered_standard_note() {
        use crate::note::StandardNote;

        let standard = StandardNote::from_script_root(ConstantFeePolicyConfigNote::script_root())
            .expect("config note script root should be a registered standard note");
        assert_eq!(standard.name(), "CONSTANT_FEE_POLICY_CONFIG");
    }
}
