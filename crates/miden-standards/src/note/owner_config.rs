use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
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
use crate::note::costs::{NoteConsumptionCost, OWNER_CONFIG_CONSUMPTION_CYCLES};
use crate::note::{AccountTargetNetworkNote, NetworkAccountTarget};

// NOTE SCRIPT
// ================================================================================================

/// Path to the OWNER_CONFIG note script procedure in the standards library.
const OWNER_CONFIG_SCRIPT_PATH: &str = "::miden::standards::notes::owner_config::main";

// Initialize the OWNER_CONFIG note script only once.
static OWNER_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(OWNER_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains OWNER_CONFIG note script procedure")
});

// OWNER CONFIG
// ================================================================================================

/// A management action of the [`Ownable2Step`](crate::account::access::Ownable2Step) component
/// that an [`OwnerConfigNote`] triggers on the account that consumes it.
///
/// The action, together with its arguments, is encoded into the note's storage (see
/// [`NoteStorage`] conversion below). Because the storage is fixed at note creation and bound into
/// the note commitment, the authorized party is the note sender: the consuming account's
/// `Ownable2Step` procedures authorize against `active_note::get_sender`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerConfig {
    /// Nominate `new_owner` as the new owner (two-step transfer; the nominee must later accept via
    /// [`OwnerConfig::AcceptOwnership`]). A `new_owner` of `None` cancels any pending nomination.
    /// Only the current owner is authorized.
    TransferOwnership { new_owner: Option<AccountId> },
    /// Accept a pending ownership nomination. Only the nominated owner is authorized.
    AcceptOwnership,
    /// Renounce ownership, leaving the component permanently ownerless. Only the current owner is
    /// authorized.
    RenounceOwnership,
}

impl OwnerConfig {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Config note selectors stored in the first storage item. Keep in sync with
    // `owner_config.masm`.
    const SELECTOR_TRANSFER_OWNERSHIP: u8 = 0;
    const SELECTOR_ACCEPT_OWNERSHIP: u8 = 1;
    const SELECTOR_RENOUNCE_OWNERSHIP: u8 = 2;

    /// Returns the note storage values encoding this action, laid out as `[selector, ..args]`.
    fn to_storage_values(self) -> Vec<Felt> {
        match self {
            OwnerConfig::TransferOwnership { new_owner } => {
                // [selector, new_owner_suffix, new_owner_prefix]; the zero address (0, 0) is the
                // cancel value understood by `ownable2step::transfer_ownership`.
                let (suffix, prefix) = match new_owner {
                    Some(id) => (id.suffix(), id.prefix().as_felt()),
                    None => (Felt::ZERO, Felt::ZERO),
                };
                vec![Felt::from(Self::SELECTOR_TRANSFER_OWNERSHIP), suffix, prefix]
            },
            OwnerConfig::AcceptOwnership => {
                vec![Felt::from(Self::SELECTOR_ACCEPT_OWNERSHIP)]
            },
            OwnerConfig::RenounceOwnership => {
                vec![Felt::from(Self::SELECTOR_RENOUNCE_OWNERSHIP)]
            },
        }
    }
}

impl From<OwnerConfig> for NoteStorage {
    fn from(config: OwnerConfig) -> Self {
        NoteStorage::new(config.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// OWNER CONFIG NOTE
// ================================================================================================

/// An OwnerConfig note: triggers an [`Ownable2Step`](crate::account::access::Ownable2Step)
/// management action on the account that consumes it.
///
/// A single note script dispatches on a selector in the note's storage to one of the component's
/// management procedures (`transfer_ownership`, `accept_ownership`, `renounce_ownership`). All
/// authorization is enforced by those procedures against the note sender, so the note carries no
/// assets and its authorization is bound to `sender` at creation time.
///
/// The note is always public and tagged for `account` — the account carrying the `Ownable2Step`
/// component whose ownership state is being managed. The `sender` is the account authorized for the
/// selected action: the current owner for `TransferOwnership` / `RenounceOwnership`, or the
/// nominated owner for `AcceptOwnership`.
///
/// The note is bound to the target `account` by a [`NetworkAccountTarget`] attachment: the script
/// asserts that the consuming account matches that target before dispatching, so the note cannot be
/// consumed by a third-party account that merely accepts its sender. The binding also
/// makes the note a valid [`AccountTargetNetworkNote`], routing it to `account` for network
/// execution.
///
/// Construct one with the [builder](OwnerConfigNote::builder); convert it into a protocol [`Note`]
/// infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct OwnerConfigNote {
    sender: AccountId,
    target: AccountId,
    config: OwnerConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl OwnerConfigNote {
    /// Builds a new [`OwnerConfigNote`] that applies `config` to `account`.
    ///
    /// The note is bound to `account` by a [`NetworkAccountTarget`] attachment that the builder
    /// appends unless the caller already supplied one for `account`.
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
        config: OwnerConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // The note script asserts that the consuming account matches this target before
        // dispatching.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source(
                "failed to bind the OwnerConfig note to its target account",
                err,
            )
        })?;
        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            target,
            config,
            serial_number,
            attachments,
        })
    }
}

impl OwnerConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Upper bound on the number of storage items of an OwnerConfig note.
    ///
    /// The layout is variable: `TransferOwnership` uses 3 items (`[selector, new_owner_suffix,
    /// new_owner_prefix]`), while `AcceptOwnership` / `RenounceOwnership` use 1 (`[selector]`).
    pub const MAX_NUM_STORAGE_ITEMS: usize = 3;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the OwnerConfig note.
    pub fn script() -> NoteScript {
        OWNER_CONFIG_SCRIPT.clone()
    }

    /// Returns the OwnerConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        OWNER_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed account (the account the note is tagged for).
    pub fn account(&self) -> AccountId {
        self.target
    }

    /// Returns the management action carried by the note.
    pub fn config(&self) -> OwnerConfig {
        self.config
    }

    /// Returns the note's serial number.
    pub fn serial_number(&self) -> Word {
        self.serial_number
    }

    /// Returns the attachments carried by the note, which always include a
    /// [`NetworkAccountTarget`].
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: owner_config_note_builder::State> OwnerConfigNoteBuilder<S> {
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

impl<S: owner_config_note_builder::State> OwnerConfigNoteBuilder<S>
where
    S::SerialNumber: owner_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> OwnerConfigNoteBuilder<owner_config_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<OwnerConfigNote> for Note {
    fn from(note: OwnerConfigNote) -> Self {
        // OwnerConfig notes carry no assets and are always public for network execution; the action
        // and its arguments live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            OwnerConfigNote::script(),
            NoteStorage::from(note.config),
        );
        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

impl From<OwnerConfigNote> for AccountTargetNetworkNote {
    fn from(note: OwnerConfigNote) -> Self {
        AccountTargetNetworkNote::new(Note::from(note))
            .expect("OwnerConfig note is public and carries a network account target attachment")
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for OwnerConfigNote {
    fn consumption_cycles() -> u32 {
        OWNER_CONFIG_CONSUMPTION_CYCLES
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
    use crate::note::{NetworkAccountTargetError, NetworkNoteExt, NoteExecutionHint};

    fn account_id(seed: u8) -> AccountId {
        typed_account_id(seed, AccountType::Public)
    }

    fn typed_account_id(seed: u8, account_type: AccountType) -> AccountId {
        AccountId::builder().account_type(account_type).build_with_seed([seed; 32])
    }

    /// The builder produces a public, asset-less note tagged for the managed account.
    #[test]
    fn builder_builds_owner_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);
        let owner = account_id(2);
        let new_owner = account_id(3);

        let note = OwnerConfigNote::builder()
            .sender(owner)
            .target(managed)
            .config(OwnerConfig::TransferOwnership { new_owner: Some(new_owner) })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), owner);
        assert_eq!(note.account(), managed);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(managed));
        assert_eq!(note.assets().num_assets(), 0);
    }

    /// The builder attaches the network target for the managed account, so the note is a network
    /// note without the caller having to add the attachment.
    #[test]
    fn builder_attaches_network_target() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);

        let note = OwnerConfigNote::builder()
            .sender(account_id(2))
            .target(managed)
            .config(OwnerConfig::AcceptOwnership)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.attachments().num_attachments(), 1);

        let network_note = AccountTargetNetworkNote::from(note);
        assert_eq!(network_note.target_account_id(), managed);
        assert_eq!(network_note.execution_hint(), NoteExecutionHint::Always);
        assert!(network_note.as_note().is_network_note());
    }

    /// Caller-supplied attachments are kept in their order, with the bound network target appended.
    #[test]
    fn builder_keeps_caller_attachments() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);
        let custom_scheme = NoteAttachmentScheme::new(64).unwrap();
        let custom = NoteAttachment::with_word(custom_scheme, Word::from([7u32, 0, 0, 0]));

        let note = OwnerConfigNote::builder()
            .attachment(custom.clone())
            .sender(account_id(2))
            .target(managed)
            .config(OwnerConfig::AcceptOwnership)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        // The target is appended, so the caller's attachment comes first.
        assert_eq!(note.attachments().num_attachments(), 2);
        assert_eq!(note.attachments().get(0), Some(&custom));

        let network_note = AccountTargetNetworkNote::from(note);
        assert_eq!(network_note.target_account_id(), managed);
    }

    /// A caller-supplied `NetworkAccountTarget` for another account is rejected rather than
    /// silently coexisting with the note's own target.
    #[test]
    fn builder_rejects_target_for_other_account() {
        let mut rng = RandomCoin::new(Word::empty());
        let rogue_target =
            NetworkAccountTarget::new(account_id(3), NoteExecutionHint::None).unwrap();

        let err = OwnerConfigNote::builder()
            .attachment(rogue_target)
            .sender(account_id(2))
            .target(account_id(1))
            .config(OwnerConfig::AcceptOwnership)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap_err();

        assert_matches!(err, NoteError::Other { source, .. } => {
            assert_matches!(
              *source.unwrap().downcast().unwrap(),
              NetworkAccountTargetError::TargetMismatch { .. }
            )
        });
    }

    /// A non-public managed account cannot be a network target, so the builder rejects it.
    #[test]
    fn builder_rejects_non_public_account() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = typed_account_id(1, AccountType::Private);

        let err = OwnerConfigNote::builder()
            .sender(account_id(2))
            .target(managed)
            .config(OwnerConfig::AcceptOwnership)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap_err();

        assert_matches!(err, NoteError::Other { source, .. } => {
            assert_matches!(
              *source.unwrap().downcast().unwrap(),
              NetworkAccountTargetError::TargetNotPublic { .. }
            )
        });
    }

    /// `TransferOwnership` storage is `[selector, new_owner_suffix, new_owner_prefix]`.
    #[test]
    fn transfer_ownership_storage_layout() {
        let new_owner = account_id(3);
        let storage =
            NoteStorage::from(OwnerConfig::TransferOwnership { new_owner: Some(new_owner) });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(OwnerConfig::SELECTOR_TRANSFER_OWNERSHIP),
                new_owner.suffix(),
                new_owner.prefix().as_felt(),
            ]
        );
    }

    /// A cancelling `TransferOwnership` encodes the zero address.
    #[test]
    fn cancel_transfer_ownership_storage_layout() {
        let storage = NoteStorage::from(OwnerConfig::TransferOwnership { new_owner: None });

        assert_eq!(
            storage.items(),
            &[Felt::from(OwnerConfig::SELECTOR_TRANSFER_OWNERSHIP), Felt::ZERO, Felt::ZERO]
        );
    }

    /// `AcceptOwnership` / `RenounceOwnership` storage is a single selector item.
    #[test]
    fn accept_and_renounce_storage_layout() {
        let accept = NoteStorage::from(OwnerConfig::AcceptOwnership);
        assert_eq!(accept.items(), &[Felt::from(OwnerConfig::SELECTOR_ACCEPT_OWNERSHIP)]);

        let renounce = NoteStorage::from(OwnerConfig::RenounceOwnership);
        assert_eq!(renounce.items(), &[Felt::from(OwnerConfig::SELECTOR_RENOUNCE_OWNERSHIP)]);
    }
}
