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
use crate::note::costs::{NoteConsumptionCost, OWNER_ACTION_CONSUMPTION_CYCLES};

// NOTE SCRIPT
// ================================================================================================

/// Path to the OWNER_ACTION note script procedure in the standards library.
const OWNER_ACTION_SCRIPT_PATH: &str = "::miden::standards::notes::owner_action::main";

// Initialize the OWNER_ACTION note script only once.
static OWNER_ACTION_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(OWNER_ACTION_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains OWNER_ACTION note script procedure")
});

// OWNER ACTION
// ================================================================================================

/// A management action of the [`Ownable2Step`](crate::account::access::Ownable2Step) component
/// that an [`OwnerActionNote`] triggers on the account that consumes it.
///
/// The action, together with its arguments, is encoded into the note's storage (see
/// [`NoteStorage`] conversion below). Because the storage is fixed at note creation and bound into
/// the note commitment, the authorized party is the note sender: the consuming account's
/// `Ownable2Step` procedures authorize against `active_note::get_sender`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerAction {
    /// Nominate `new_owner` as the new owner (two-step transfer; the nominee must later accept via
    /// [`OwnerAction::AcceptOwnership`]). A `new_owner` of `None` cancels any pending nomination.
    /// Only the current owner is authorized.
    TransferOwnership { new_owner: Option<AccountId> },
    /// Accept a pending ownership nomination. Only the nominated owner is authorized.
    AcceptOwnership,
    /// Renounce ownership, leaving the component permanently ownerless. Only the current owner is
    /// authorized.
    RenounceOwnership,
}

impl OwnerAction {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Action selectors stored in the first storage item. Keep in sync with `owner_action.masm`.
    const SELECTOR_TRANSFER_OWNERSHIP: u8 = 0;
    const SELECTOR_ACCEPT_OWNERSHIP: u8 = 1;
    const SELECTOR_RENOUNCE_OWNERSHIP: u8 = 2;

    /// Returns the note storage values encoding this action, laid out as `[selector, ..args]`.
    fn to_storage_values(self) -> Vec<Felt> {
        match self {
            OwnerAction::TransferOwnership { new_owner } => {
                // [selector, new_owner_suffix, new_owner_prefix]; the zero address (0, 0) is the
                // cancel value understood by `ownable2step::transfer_ownership`.
                let (suffix, prefix) = match new_owner {
                    Some(id) => (id.suffix(), id.prefix().as_felt()),
                    None => (Felt::ZERO, Felt::ZERO),
                };
                vec![Felt::from(Self::SELECTOR_TRANSFER_OWNERSHIP), suffix, prefix]
            },
            OwnerAction::AcceptOwnership => {
                vec![Felt::from(Self::SELECTOR_ACCEPT_OWNERSHIP)]
            },
            OwnerAction::RenounceOwnership => {
                vec![Felt::from(Self::SELECTOR_RENOUNCE_OWNERSHIP)]
            },
        }
    }
}

impl From<OwnerAction> for NoteStorage {
    fn from(action: OwnerAction) -> Self {
        NoteStorage::new(action.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// OWNER ACTION NOTE
// ================================================================================================

/// An OwnerAction note: triggers an [`Ownable2Step`](crate::account::access::Ownable2Step)
/// management action on the account that consumes it.
///
/// A single note script dispatches on a selector in the note's storage to one of the component's
/// management procedures (`transfer_ownership`, `accept_ownership`, `renounce_ownership`). All
/// authorization is enforced by those procedures against the note sender, so the note carries no
/// assets and its authorization is bound to `sender` at creation time.
///
/// The note is always public (for network execution) and tagged for `account` — the account
/// carrying the `Ownable2Step` component whose ownership state is being managed. The `sender` is
/// the account authorized for the selected action: the current owner for `TransferOwnership` /
/// `RenounceOwnership`, or the nominated owner for `AcceptOwnership`.
///
/// Construct one with the [builder](OwnerActionNote::builder); convert it into a protocol [`Note`]
/// infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct OwnerActionNote {
    sender: AccountId,
    account: AccountId,
    action: OwnerAction,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl OwnerActionNote {
    /// Builds a new [`OwnerActionNote`] that triggers `action` on `account`.
    ///
    /// # Errors
    ///
    /// Returns an error if the attachments exceed their protocol limit (see
    /// [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        account: AccountId,
        action: OwnerAction,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            account,
            action,
            serial_number,
            attachments,
        })
    }
}

impl OwnerActionNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Upper bound on the number of storage items of an OwnerAction note.
    ///
    /// The layout is variable: `TransferOwnership` uses 3 items (`[selector, new_owner_suffix,
    /// new_owner_prefix]`), while `AcceptOwnership` / `RenounceOwnership` use 1 (`[selector]`).
    pub const MAX_NUM_STORAGE_ITEMS: usize = 3;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the OwnerAction note.
    pub fn script() -> NoteScript {
        OWNER_ACTION_SCRIPT.clone()
    }

    /// Returns the OwnerAction note script root.
    pub fn script_root() -> NoteScriptRoot {
        OWNER_ACTION_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed account (the account the note is tagged for).
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the management action carried by the note.
    pub fn action(&self) -> OwnerAction {
        self.action
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

impl<S: owner_action_note_builder::State> OwnerActionNoteBuilder<S> {
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

impl<S: owner_action_note_builder::State> OwnerActionNoteBuilder<S>
where
    S::SerialNumber: owner_action_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> OwnerActionNoteBuilder<owner_action_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<OwnerActionNote> for Note {
    fn from(note: OwnerActionNote) -> Self {
        // OwnerAction notes carry no assets and are always public for network execution; the action
        // and its arguments live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.account));
        let recipient = NoteRecipient::new(
            note.serial_number,
            OwnerActionNote::script(),
            NoteStorage::from(note.action),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for OwnerActionNote {
    fn consumption_cycles() -> u32 {
        OWNER_ACTION_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::rand::RandomCoin;

    use super::*;

    fn account_id(seed: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([seed; 32])
    }

    /// The builder produces a public, asset-less note tagged for the managed account.
    #[test]
    fn builder_builds_owner_action_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);
        let owner = account_id(2);
        let new_owner = account_id(3);

        let note = OwnerActionNote::builder()
            .sender(owner)
            .account(managed)
            .action(OwnerAction::TransferOwnership { new_owner: Some(new_owner) })
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

    /// `TransferOwnership` storage is `[selector, new_owner_suffix, new_owner_prefix]`.
    #[test]
    fn transfer_ownership_storage_layout() {
        let new_owner = account_id(3);
        let storage =
            NoteStorage::from(OwnerAction::TransferOwnership { new_owner: Some(new_owner) });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(OwnerAction::SELECTOR_TRANSFER_OWNERSHIP),
                new_owner.suffix(),
                new_owner.prefix().as_felt(),
            ]
        );
    }

    /// A cancelling `TransferOwnership` encodes the zero address.
    #[test]
    fn cancel_transfer_ownership_storage_layout() {
        let storage = NoteStorage::from(OwnerAction::TransferOwnership { new_owner: None });

        assert_eq!(
            storage.items(),
            &[Felt::from(OwnerAction::SELECTOR_TRANSFER_OWNERSHIP), Felt::ZERO, Felt::ZERO]
        );
    }

    /// `AcceptOwnership` / `RenounceOwnership` storage is a single selector item.
    #[test]
    fn accept_and_renounce_storage_layout() {
        let accept = NoteStorage::from(OwnerAction::AcceptOwnership);
        assert_eq!(accept.items(), &[Felt::from(OwnerAction::SELECTOR_ACCEPT_OWNERSHIP)]);

        let renounce = NoteStorage::from(OwnerAction::RenounceOwnership);
        assert_eq!(renounce.items(), &[Felt::from(OwnerAction::SELECTOR_RENOUNCE_OWNERSHIP)]);
    }
}
