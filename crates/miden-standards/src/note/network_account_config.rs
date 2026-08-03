use alloc::vec::Vec;

use miden_protocol::account::{AccountId, AccountProcedureRoot};
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
use crate::note::NetworkAccountTarget;
use crate::note::costs::{NETWORK_ACCOUNT_CONFIG_CONSUMPTION_CYCLES, NoteConsumptionCost};

// NOTE SCRIPT
// ================================================================================================

/// Path to the NETWORK_ACCOUNT_CONFIG note script procedure in the standards library.
const NETWORK_ACCOUNT_CONFIG_SCRIPT_PATH: &str =
    "::miden::standards::notes::network_account_config::main";

// Initialize the NETWORK_ACCOUNT_CONFIG note script only once.
static NETWORK_ACCOUNT_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(NETWORK_ACCOUNT_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains NETWORK_ACCOUNT_CONFIG note script procedure")
});

// NETWORK ACCOUNT CONFIG
// ================================================================================================

/// A configuration action of the
/// [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount) component that a
/// [`NetworkAccountConfigNote`] triggers on the network account that consumes it.
///
/// Each variant adds or removes one root from the note-script allowlist, the tx-script allowlist,
/// or the allowed fee policy roots map. The allowlist checks read the transaction's initial state,
/// so an update only takes effect from the account's next transaction.
///
/// The action is encoded into the note's storage (see [`NoteStorage`] conversion below). Because
/// the storage is fixed at note creation and bound into the note commitment, the authorized party
/// is the note sender: the consuming account's `AuthNetworkAccount` procedures authorize the sender
/// through the account-wide `Authority` component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkAccountConfig {
    /// Adds `script_root` to the note script allowlist.
    AddAllowedNoteScript { script_root: NoteScriptRoot },
    /// Removes `script_root` from the note script allowlist.
    RemoveAllowedNoteScript { script_root: NoteScriptRoot },
    /// Adds `script_root` to the tx script allowlist.
    AddAllowedTxScript { script_root: TransactionScriptRoot },
    /// Removes `script_root` from the tx script allowlist.
    RemoveAllowedTxScript { script_root: TransactionScriptRoot },
    /// Adds `policy_root` to the allowed fee policy roots map.
    AddAllowedFeePolicy { policy_root: AccountProcedureRoot },
    /// Removes `policy_root` from the allowed fee policy roots map.
    RemoveAllowedFeePolicy { policy_root: AccountProcedureRoot },
}

impl NetworkAccountConfig {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Config note selectors stored in the first storage item. Keep in sync with
    // `network_account_config.masm`.
    const SELECTOR_ADD_ALLOWED_NOTE_SCRIPT: u8 = 0;
    const SELECTOR_REMOVE_ALLOWED_NOTE_SCRIPT: u8 = 1;
    const SELECTOR_ADD_ALLOWED_TX_SCRIPT: u8 = 2;
    const SELECTOR_REMOVE_ALLOWED_TX_SCRIPT: u8 = 3;
    const SELECTOR_ADD_ALLOWED_FEE_POLICY: u8 = 4;
    const SELECTOR_REMOVE_ALLOWED_FEE_POLICY: u8 = 5;

    /// Returns the selector and the affected root of this action.
    fn parts(self) -> (u8, Word) {
        match self {
            NetworkAccountConfig::AddAllowedNoteScript { script_root } => {
                (Self::SELECTOR_ADD_ALLOWED_NOTE_SCRIPT, script_root.as_word())
            },
            NetworkAccountConfig::RemoveAllowedNoteScript { script_root } => {
                (Self::SELECTOR_REMOVE_ALLOWED_NOTE_SCRIPT, script_root.as_word())
            },
            NetworkAccountConfig::AddAllowedTxScript { script_root } => {
                (Self::SELECTOR_ADD_ALLOWED_TX_SCRIPT, script_root.as_word())
            },
            NetworkAccountConfig::RemoveAllowedTxScript { script_root } => {
                (Self::SELECTOR_REMOVE_ALLOWED_TX_SCRIPT, script_root.as_word())
            },
            NetworkAccountConfig::AddAllowedFeePolicy { policy_root } => {
                (Self::SELECTOR_ADD_ALLOWED_FEE_POLICY, policy_root.as_word())
            },
            NetworkAccountConfig::RemoveAllowedFeePolicy { policy_root } => {
                (Self::SELECTOR_REMOVE_ALLOWED_FEE_POLICY, policy_root.as_word())
            },
        }
    }

    /// Returns the note storage values encoding this action, laid out as `[ROOT, selector]`.
    fn to_storage_values(self) -> Vec<Felt> {
        let (selector, script_root) = self.parts();
        let mut values = Vec::with_capacity(NetworkAccountConfigNote::NUM_STORAGE_ITEMS);
        values.extend_from_slice(script_root.as_elements());
        values.push(Felt::from(selector));
        values
    }
}

impl From<NetworkAccountConfig> for NoteStorage {
    fn from(config: NetworkAccountConfig) -> Self {
        NoteStorage::new(config.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// NETWORK ACCOUNT CONFIG NOTE
// ================================================================================================

/// A NetworkAccountConfig note: adds or removes a root from a network account's note-script
/// allowlist, tx-script allowlist, or allowed fee policy roots map.
///
/// A single note script dispatches on a selector in the note's storage to one of the
/// [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount) component's allowlist or
/// fee-policy procedures. Authorization is enforced by those procedures through the account-wide
/// `Authority` component against the note sender.
///
/// For the consuming network account to accept this note, its own script root must be in the
/// account's note script allowlist. Every
/// [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount) allowlists it by default at
/// construction, so no extra setup is required.
///
/// Construct one with the [builder](NetworkAccountConfigNote::builder); convert it into a
/// protocol [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct NetworkAccountConfigNote {
    sender: AccountId,
    target: AccountId,
    config: NetworkAccountConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl NetworkAccountConfigNote {
    /// Builds a new [`NetworkAccountConfigNote`] that applies `config` to `account`.
    ///
    /// The note is bound to `account` with a [`NetworkAccountTarget`] attachment, so that only
    /// `account` can consume it. This attachment is folded into the note commitment and verified
    /// on-chain by the note script.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `account` does not have [`AccountType::Public`](miden_protocol::account::AccountType).
    /// - the attachments carry a `NetworkAccountTarget` for an account other than `account`.
    /// - the attachments exceed their protocol limit (see [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] mut attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        config: NetworkAccountConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // Bind consumption to the target account: the note script rejects any other consumer.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source("failed to bind the note to its target account", err)
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

impl NetworkAccountConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a NetworkAccountConfig note: a selector plus the script
    /// root word.
    pub const NUM_STORAGE_ITEMS: usize = 5;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the NetworkAccountConfig note.
    pub fn script() -> NoteScript {
        NETWORK_ACCOUNT_CONFIG_SCRIPT.clone()
    }

    /// Returns the NetworkAccountConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        NETWORK_ACCOUNT_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed network account (the account the note is tagged for).
    pub fn account(&self) -> AccountId {
        self.target
    }

    /// Returns the allowlist-mutation action carried by the note.
    pub fn config(&self) -> NetworkAccountConfig {
        self.config
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

impl<S: network_account_config_note_builder::State> NetworkAccountConfigNoteBuilder<S> {
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

impl<S: network_account_config_note_builder::State> NetworkAccountConfigNoteBuilder<S>
where
    S::SerialNumber: network_account_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> NetworkAccountConfigNoteBuilder<network_account_config_note_builder::SetSerialNumber<S>>
    {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<NetworkAccountConfigNote> for Note {
    fn from(note: NetworkAccountConfigNote) -> Self {
        // NetworkAccountConfig notes carry no assets and are always public for network
        // execution; the action and its script root live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            NetworkAccountConfigNote::script(),
            NoteStorage::from(note.config),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for NetworkAccountConfigNote {
    fn consumption_cycles() -> u32 {
        NETWORK_ACCOUNT_CONFIG_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

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

    fn policy_root(seed: u32) -> AccountProcedureRoot {
        AccountProcedureRoot::from_raw(Word::from([seed, seed + 1, seed + 2, seed + 3]))
    }

    /// The builder produces a public, asset-less note tagged for the managed network account.
    #[test]
    fn builder_builds_allowlist_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let account = account_id(1);
        let sender = account_id(2);

        let note = NetworkAccountConfigNote::builder()
            .sender(sender)
            .target(account)
            .config(NetworkAccountConfig::AddAllowedNoteScript { script_root: note_root(10) })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender);
        assert_eq!(note.account(), account);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(account));
        assert_eq!(note.assets().num_assets(), 0);

        // The note is bound to its target account by a NetworkAccountTarget attachment
        let target = NetworkAccountTarget::try_from(note.attachments())
            .expect("note must carry a network account target attachment");
        assert_eq!(target.target_id(), account);
    }

    /// Storage is `[ROOT, selector]` with the selector matching the action kind.
    #[test]
    fn storage_layout() {
        let note_root = note_root(10);
        let tx_root = tx_root(20);
        let policy_root = policy_root(30);

        let cases = [
            (
                NetworkAccountConfig::AddAllowedNoteScript { script_root: note_root },
                NetworkAccountConfig::SELECTOR_ADD_ALLOWED_NOTE_SCRIPT,
                note_root.as_word(),
            ),
            (
                NetworkAccountConfig::RemoveAllowedNoteScript { script_root: note_root },
                NetworkAccountConfig::SELECTOR_REMOVE_ALLOWED_NOTE_SCRIPT,
                note_root.as_word(),
            ),
            (
                NetworkAccountConfig::AddAllowedTxScript { script_root: tx_root },
                NetworkAccountConfig::SELECTOR_ADD_ALLOWED_TX_SCRIPT,
                tx_root.as_word(),
            ),
            (
                NetworkAccountConfig::RemoveAllowedTxScript { script_root: tx_root },
                NetworkAccountConfig::SELECTOR_REMOVE_ALLOWED_TX_SCRIPT,
                tx_root.as_word(),
            ),
            (
                NetworkAccountConfig::AddAllowedFeePolicy { policy_root },
                NetworkAccountConfig::SELECTOR_ADD_ALLOWED_FEE_POLICY,
                policy_root.as_word(),
            ),
            (
                NetworkAccountConfig::RemoveAllowedFeePolicy { policy_root },
                NetworkAccountConfig::SELECTOR_REMOVE_ALLOWED_FEE_POLICY,
                policy_root.as_word(),
            ),
        ];

        for (action, selector, root_word) in cases {
            let storage = NoteStorage::from(action);
            let mut expected = Vec::from(root_word.as_elements());
            expected.push(Felt::from(selector));
            assert_eq!(storage.items(), expected.as_slice());
            assert_eq!(storage.items().len(), NetworkAccountConfigNote::NUM_STORAGE_ITEMS);
        }
    }

    /// The action-note script root is registered in the [`StandardNote`](crate::note::StandardNote)
    /// reverse lookup.
    #[test]
    fn script_root_is_registered_standard_note() {
        use crate::note::StandardNote;

        let standard = StandardNote::from_script_root(NetworkAccountConfigNote::script_root())
            .expect("config note script root should be a registered standard note");
        assert_eq!(standard.name(), "NETWORK_ACCOUNT_CONFIG");
    }
}
