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
use crate::note::costs::{NoteConsumptionCost, PAUSE_ACTION_CONSUMPTION_CYCLES};

// NOTE SCRIPT
// ================================================================================================

/// Path to the PAUSE_ACTION note script procedure in the standards library.
const PAUSE_ACTION_SCRIPT_PATH: &str = "::miden::standards::notes::pause_action::main";

// Initialize the PAUSE_ACTION note script only once.
static PAUSE_ACTION_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(PAUSE_ACTION_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains PAUSE_ACTION note script procedure")
});

// PAUSE ACTION
// ================================================================================================

/// A management action of the
/// [`PausableManager`](crate::account::access::pausable::PausableManager) component that a
/// [`PauseActionNote`] triggers on the account that consumes it.
///
/// The action is encoded into the note's storage (see [`NoteStorage`] conversion below). Because
/// the storage is fixed at note creation and bound into the note commitment, the authorized party
/// is the note sender: the consuming account's `PausableManager` procedures authorize the sender
/// through the account-wide `Authority` component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseAction {
    /// Pause the account, blocking pause-gated procedures until a matching unpause.
    Pause,
    /// Unpause the account.
    Unpause,
}

impl PauseAction {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Action selectors stored in the first storage item. Keep in sync with `pause_action.masm`.
    const SELECTOR_PAUSE: u8 = 0;
    const SELECTOR_UNPAUSE: u8 = 1;

    /// Returns the note storage values encoding this action, laid out as `[selector]`.
    fn to_storage_values(self) -> Vec<Felt> {
        match self {
            PauseAction::Pause => vec![Felt::from(Self::SELECTOR_PAUSE)],
            PauseAction::Unpause => vec![Felt::from(Self::SELECTOR_UNPAUSE)],
        }
    }
}

impl From<PauseAction> for NoteStorage {
    fn from(action: PauseAction) -> Self {
        NoteStorage::new(action.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// PAUSE ACTION NOTE
// ================================================================================================

/// A PauseAction note: triggers a
/// [`PausableManager`](crate::account::access::pausable::PausableManager) admin action on the
/// account that consumes it.
///
/// A single note script dispatches on a selector in the note's storage to one of the component's
/// admin procedures (`pause`, `unpause`). Authorization is enforced by those procedures through
/// the account-wide `Authority` component against the note sender, so the note carries no assets
/// and its authorization is bound to `sender` at creation time.
///
/// The note is always public (for network execution) and tagged for `account` — the account
/// carrying the `PausableManager` component whose pause state is being managed. The `sender` is
/// the account authorized for the action per the account's `Authority` configuration (the owner
/// under `Authority::OwnerControlled`, or a role member under `Authority::RbacControlled`).
///
/// Construct one with the [builder](PauseActionNote::builder); convert it into a protocol [`Note`]
/// infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct PauseActionNote {
    sender: AccountId,
    account: AccountId,
    action: PauseAction,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl PauseActionNote {
    /// Builds a new [`PauseActionNote`] that triggers `action` on `account`.
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
        action: PauseAction,
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

impl PauseActionNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a PauseAction note: a single selector.
    pub const NUM_STORAGE_ITEMS: usize = 1;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the PauseAction note.
    pub fn script() -> NoteScript {
        PAUSE_ACTION_SCRIPT.clone()
    }

    /// Returns the PauseAction note script root.
    pub fn script_root() -> NoteScriptRoot {
        PAUSE_ACTION_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed account (the account the note is tagged for).
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the admin action carried by the note.
    pub fn action(&self) -> PauseAction {
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

impl<S: pause_action_note_builder::State> PauseActionNoteBuilder<S> {
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

impl<S: pause_action_note_builder::State> PauseActionNoteBuilder<S>
where
    S::SerialNumber: pause_action_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> PauseActionNoteBuilder<pause_action_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<PauseActionNote> for Note {
    fn from(note: PauseActionNote) -> Self {
        // PauseAction notes carry no assets and are always public for network execution; the action
        // lives in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.account));
        let recipient = NoteRecipient::new(
            note.serial_number,
            PauseActionNote::script(),
            NoteStorage::from(note.action),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for PauseActionNote {
    fn consumption_cycles() -> u32 {
        PAUSE_ACTION_CONSUMPTION_CYCLES
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
    fn builder_builds_pause_action_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);
        let sender = account_id(2);

        let note = PauseActionNote::builder()
            .sender(sender)
            .account(managed)
            .action(PauseAction::Pause)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender);
        assert_eq!(note.account(), managed);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(managed));
        assert_eq!(note.assets().num_assets(), 0);
    }

    /// `Pause` / `Unpause` storage is a single selector item.
    #[test]
    fn action_storage_layout() {
        let pause = NoteStorage::from(PauseAction::Pause);
        assert_eq!(pause.items(), &[Felt::from(PauseAction::SELECTOR_PAUSE)]);

        let unpause = NoteStorage::from(PauseAction::Unpause);
        assert_eq!(unpause.items(), &[Felt::from(PauseAction::SELECTOR_UNPAUSE)]);
    }
}
