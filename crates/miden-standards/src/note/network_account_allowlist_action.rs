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
use miden_protocol::transaction::TransactionScriptRoot;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the NETWORK_ACCOUNT_ALLOWLIST_ACTION note script procedure in the standards library.
const NETWORK_ACCOUNT_ALLOWLIST_ACTION_SCRIPT_PATH: &str =
    "::miden::standards::notes::network_account_allowlist_action::main";

// Initialize the NETWORK_ACCOUNT_ALLOWLIST_ACTION note script only once.
static NETWORK_ACCOUNT_ALLOWLIST_ACTION_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(NETWORK_ACCOUNT_ALLOWLIST_ACTION_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains NETWORK_ACCOUNT_ALLOWLIST_ACTION note script procedure")
});

// NETWORK ACCOUNT ALLOWLIST ACTION
// ================================================================================================

/// An allowlist-mutation action of the
/// [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount) component that a
/// [`NetworkAccountAllowlistActionNote`] triggers on the network account that consumes it.
///
/// Each variant adds or removes one script root from the note script or tx script allowlist.
/// Because the allowlist check reads the transaction's initial state, an update only takes effect
/// from the account's next transaction.
///
/// The action is encoded into the note's storage (see [`NoteStorage`] conversion below). Because
/// the storage is fixed at note creation and bound into the note commitment, the authorized party
/// is the note sender: the consuming account's `AuthNetworkAccount` procedures authorize the sender
/// through the account-wide `Authority` component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkAccountAllowlistAction {
    /// Adds `script_root` to the note script allowlist.
    AddNoteScript { script_root: NoteScriptRoot },
    /// Removes `script_root` from the note script allowlist.
    RemoveNoteScript { script_root: NoteScriptRoot },
    /// Adds `script_root` to the tx script allowlist.
    AddTxScript { script_root: TransactionScriptRoot },
    /// Removes `script_root` from the tx script allowlist.
    RemoveTxScript { script_root: TransactionScriptRoot },
}

impl NetworkAccountAllowlistAction {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Action selectors stored in the first storage item. Keep in sync with
    // `network_account_allowlist_action.masm`.
    const SELECTOR_ADD_NOTE_SCRIPT: u8 = 0;
    const SELECTOR_REMOVE_NOTE_SCRIPT: u8 = 1;
    const SELECTOR_ADD_TX_SCRIPT: u8 = 2;
    const SELECTOR_REMOVE_TX_SCRIPT: u8 = 3;

    /// Returns the selector and the affected script root of this action.
    fn parts(self) -> (u8, Word) {
        match self {
            NetworkAccountAllowlistAction::AddNoteScript { script_root } => {
                (Self::SELECTOR_ADD_NOTE_SCRIPT, script_root.as_word())
            },
            NetworkAccountAllowlistAction::RemoveNoteScript { script_root } => {
                (Self::SELECTOR_REMOVE_NOTE_SCRIPT, script_root.as_word())
            },
            NetworkAccountAllowlistAction::AddTxScript { script_root } => {
                (Self::SELECTOR_ADD_TX_SCRIPT, script_root.as_word())
            },
            NetworkAccountAllowlistAction::RemoveTxScript { script_root } => {
                (Self::SELECTOR_REMOVE_TX_SCRIPT, script_root.as_word())
            },
        }
    }

    /// Returns the note storage values encoding this action, laid out as `[SCRIPT_ROOT, selector]`.
    ///
    /// The script root comes first so it is word-aligned in note storage, letting the note script
    /// load it with a single `mem_loadw_le`.
    fn to_storage_values(self) -> Vec<Felt> {
        let (selector, script_root) = self.parts();
        let mut values = Vec::with_capacity(NetworkAccountAllowlistActionNote::NUM_STORAGE_ITEMS);
        values.extend_from_slice(script_root.as_elements());
        values.push(Felt::from(selector));
        values
    }
}

impl From<NetworkAccountAllowlistAction> for NoteStorage {
    fn from(action: NetworkAccountAllowlistAction) -> Self {
        NoteStorage::new(action.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// NETWORK ACCOUNT ALLOWLIST ACTION NOTE
// ================================================================================================

/// A NetworkAccountAllowlistAction note: adds or removes a script root from a network account's
/// note script or tx script allowlist.
///
/// A single note script dispatches on a selector in the note's storage to one of the
/// [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount) component's allowlist
/// procedures. Authorization is enforced by those procedures through the account-wide `Authority`
/// component against the note sender.
///
/// For the consuming network account to accept this note, its own script root must be in the
/// account's note script allowlist; the
/// [`AuthNetworkAccount::with_allowlist_management`](crate::account::auth::AuthNetworkAccount::with_allowlist_management)
/// constructor allowlists it automatically.
///
/// Construct one with the [builder](NetworkAccountAllowlistActionNote::builder); convert it into a
/// protocol [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct NetworkAccountAllowlistActionNote {
    sender: AccountId,
    account: AccountId,
    action: NetworkAccountAllowlistAction,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl NetworkAccountAllowlistActionNote {
    /// Builds a new [`NetworkAccountAllowlistActionNote`] that triggers `action` on `account`.
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
        action: NetworkAccountAllowlistAction,
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

impl NetworkAccountAllowlistActionNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a NetworkAccountAllowlistAction note: a selector plus the script
    /// root word.
    pub const NUM_STORAGE_ITEMS: usize = 5;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the NetworkAccountAllowlistAction note.
    pub fn script() -> NoteScript {
        NETWORK_ACCOUNT_ALLOWLIST_ACTION_SCRIPT.clone()
    }

    /// Returns the NetworkAccountAllowlistAction note script root.
    pub fn script_root() -> NoteScriptRoot {
        NETWORK_ACCOUNT_ALLOWLIST_ACTION_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed network account (the account the note is tagged for).
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the allowlist-mutation action carried by the note.
    pub fn action(&self) -> NetworkAccountAllowlistAction {
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

impl<S: network_account_allowlist_action_note_builder::State>
    NetworkAccountAllowlistActionNoteBuilder<S>
{
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

impl<S: network_account_allowlist_action_note_builder::State>
    NetworkAccountAllowlistActionNoteBuilder<S>
where
    S::SerialNumber: network_account_allowlist_action_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> NetworkAccountAllowlistActionNoteBuilder<
        network_account_allowlist_action_note_builder::SetSerialNumber<S>,
    > {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<NetworkAccountAllowlistActionNote> for Note {
    fn from(note: NetworkAccountAllowlistActionNote) -> Self {
        // NetworkAccountAllowlistAction notes carry no assets and are always public for network
        // execution; the action and its script root live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.account));
        let recipient = NoteRecipient::new(
            note.serial_number,
            NetworkAccountAllowlistActionNote::script(),
            NoteStorage::from(note.action),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
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

    fn note_root(seed: u32) -> NoteScriptRoot {
        NoteScriptRoot::from_array([seed, seed + 1, seed + 2, seed + 3])
    }

    fn tx_root(seed: u32) -> TransactionScriptRoot {
        TransactionScriptRoot::from_raw(Word::from([seed, seed + 1, seed + 2, seed + 3]))
    }

    /// The builder produces a public, asset-less note tagged for the managed network account.
    #[test]
    fn builder_builds_allowlist_action_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let account = account_id(1);
        let sender = account_id(2);

        let note = NetworkAccountAllowlistActionNote::builder()
            .sender(sender)
            .account(account)
            .action(NetworkAccountAllowlistAction::AddNoteScript { script_root: note_root(10) })
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

    /// Storage is `[selector, SCRIPT_ROOT]` with the selector matching the action kind.
    #[test]
    fn storage_layout() {
        let note_root = note_root(10);
        let tx_root = tx_root(20);

        let cases = [
            (
                NetworkAccountAllowlistAction::AddNoteScript { script_root: note_root },
                NetworkAccountAllowlistAction::SELECTOR_ADD_NOTE_SCRIPT,
                note_root.as_word(),
            ),
            (
                NetworkAccountAllowlistAction::RemoveNoteScript { script_root: note_root },
                NetworkAccountAllowlistAction::SELECTOR_REMOVE_NOTE_SCRIPT,
                note_root.as_word(),
            ),
            (
                NetworkAccountAllowlistAction::AddTxScript { script_root: tx_root },
                NetworkAccountAllowlistAction::SELECTOR_ADD_TX_SCRIPT,
                tx_root.as_word(),
            ),
            (
                NetworkAccountAllowlistAction::RemoveTxScript { script_root: tx_root },
                NetworkAccountAllowlistAction::SELECTOR_REMOVE_TX_SCRIPT,
                tx_root.as_word(),
            ),
        ];

        for (action, selector, root_word) in cases {
            let storage = NoteStorage::from(action);
            let mut expected = alloc::vec::Vec::from(root_word.as_elements());
            expected.push(Felt::from(selector));
            assert_eq!(storage.items(), expected.as_slice());
            assert_eq!(storage.items().len(), NetworkAccountAllowlistActionNote::NUM_STORAGE_ITEMS);
        }
    }

    /// The action-note script root is registered in the [`StandardNote`](crate::note::StandardNote)
    /// reverse lookup.
    #[test]
    fn script_root_is_registered_standard_note() {
        use crate::note::StandardNote;

        let standard =
            StandardNote::from_script_root(NetworkAccountAllowlistActionNote::script_root())
                .expect("allowlist action note script root should be a registered standard note");
        assert_eq!(standard.name(), "NETWORK_ACCOUNT_ALLOWLIST_ACTION");
    }
}
