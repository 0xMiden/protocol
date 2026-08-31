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
use crate::note::NetworkAccountTarget;
use crate::note::costs::{BLOCKLIST_CONFIG_CONSUMPTION_CYCLES, NoteConsumptionCost};

// NOTE SCRIPT
// ================================================================================================

/// Path to the BLOCKLIST_CONFIG note script procedure in the standards library.
const BLOCKLIST_CONFIG_SCRIPT_PATH: &str = "::miden::standards::notes::blocklist_config::main";

// Initialize the BLOCKLIST_CONFIG note script only once.
static BLOCKLIST_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(BLOCKLIST_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains BLOCKLIST_CONFIG note script procedure")
});

// BLOCKLIST CONFIG
// ================================================================================================

/// A management action of the
/// [`BlocklistManager`](crate::account::policies::BlocklistManager) component that a
/// [`BlocklistConfigNote`] triggers on the account that consumes it.
///
/// The action, together with its argument, is encoded into the note's storage (see [`NoteStorage`]
/// conversion below) and is fixed at note creation, bound into the note commitment. The consuming
/// account's `BlocklistManager` procedures authorize the action through the account-wide
/// [`Authority`](crate::account::access::Authority) component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistConfig {
    /// Add `account` to the blocklist. Blocking an already blocked account is a noop.
    BlockAccount { account: AccountId },
    /// Remove `account` from the blocklist. Unblocking an account that is not blocked is a noop.
    UnblockAccount { account: AccountId },
}

impl BlocklistConfig {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Config note selectors stored in the first storage item. Keep in sync with
    // `blocklist_config.masm`.
    const SELECTOR_BLOCK_ACCOUNT: u8 = 0;
    const SELECTOR_UNBLOCK_ACCOUNT: u8 = 1;

    /// Returns the selector encoding this action in the first storage item.
    const fn selector(self) -> u8 {
        match self {
            BlocklistConfig::BlockAccount { .. } => Self::SELECTOR_BLOCK_ACCOUNT,
            BlocklistConfig::UnblockAccount { .. } => Self::SELECTOR_UNBLOCK_ACCOUNT,
        }
    }

    /// Returns the account the action operates on.
    const fn target(self) -> AccountId {
        match self {
            BlocklistConfig::BlockAccount { account }
            | BlocklistConfig::UnblockAccount { account } => account,
        }
    }

    /// Returns the note storage values encoding this action, laid out as `[selector,
    /// account_suffix, account_prefix]`.
    fn to_storage_values(self) -> Vec<Felt> {
        let account = self.target();
        vec![Felt::from(self.selector()), account.suffix(), account.prefix().as_felt()]
    }
}

impl From<BlocklistConfig> for NoteStorage {
    fn from(config: BlocklistConfig) -> Self {
        NoteStorage::new(config.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// BLOCKLIST CONFIG NOTE
// ================================================================================================

/// A BlocklistConfig note: triggers a
/// [`BlocklistManager`](crate::account::policies::BlocklistManager) admin action on the account
/// that consumes it.
///
/// A single note script dispatches on a selector in the note's storage to one of the component's
/// admin procedures (`block_account`, `unblock_account`). Authorization is enforced by those
/// procedures through the account-wide [`Authority`](crate::account::access::Authority) component,
/// so the note carries no assets.
///
/// The note is always public and tagged for `target` — the account carrying the
/// `BlocklistManager` component whose blocklist is being managed.
///
/// The note is bound to `target` by a
/// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) attachment: the script asserts
/// that the consuming account matches that target before dispatching, so the note cannot be
/// consumed by a third-party account that merely accepts its sender.
///
/// The builder always produces a [`NoteType::Public`] note, and network execution requires one:
/// [`AccountTargetNetworkNote`](crate::note::AccountTargetNetworkNote) rejects a non-public note.
/// The note script itself does not read the note type, so a hand-crafted private note carrying
/// the same script and storage dispatches the same action when it is consumed in a local
/// transaction. Authorization is unaffected either way: the called procedures authorize the note
/// sender, which the kernel pins to the account that created the note.
///
/// Construct one with the [builder](BlocklistConfigNote::builder); convert it into a protocol
/// [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct BlocklistConfigNote {
    sender: AccountId,
    target: AccountId,
    config: BlocklistConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl BlocklistConfigNote {
    /// Builds a new [`BlocklistConfigNote`] that applies `config` to `target`.
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
        config: BlocklistConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // The note script asserts that the consuming account matches this target before
        // dispatching.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source(
                "failed to bind the BlocklistConfig note to its target account",
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

impl BlocklistConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a BlocklistConfig note: a selector followed by the account ID
    /// the action operates on.
    ///
    /// Both actions carry the same arguments, so the layout is fixed at `[selector,
    /// account_suffix, account_prefix]`.
    pub const NUM_STORAGE_ITEMS: usize = 3;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the BlocklistConfig note.
    pub fn script() -> NoteScript {
        BLOCKLIST_CONFIG_SCRIPT.clone()
    }

    /// Returns the BlocklistConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        BLOCKLIST_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the authorizing party under an owner- or
    /// role-controlled `Authority`).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed account (the account the note is tagged for).
    pub fn target(&self) -> AccountId {
        self.target
    }

    /// Returns the admin action carried by the note.
    pub fn config(&self) -> BlocklistConfig {
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

impl<S: blocklist_config_note_builder::State> BlocklistConfigNoteBuilder<S> {
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

impl<S: blocklist_config_note_builder::State> BlocklistConfigNoteBuilder<S>
where
    S::SerialNumber: blocklist_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> BlocklistConfigNoteBuilder<blocklist_config_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<BlocklistConfigNote> for Note {
    fn from(note: BlocklistConfigNote) -> Self {
        // BlocklistConfig notes carry no assets and are always public for network execution; the
        // action and its argument live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            BlocklistConfigNote::script(),
            NoteStorage::from(note.config),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for BlocklistConfigNote {
    fn consumption_cycles() -> u32 {
        BLOCKLIST_CONFIG_CONSUMPTION_CYCLES
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
    fn builder_builds_blocklist_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);
        let owner = account_id(2);
        let blocked = account_id(3);

        let note = BlocklistConfigNote::builder()
            .sender(owner)
            .target(managed)
            .config(BlocklistConfig::BlockAccount { account: blocked })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), owner);
        assert_eq!(note.target(), managed);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(managed));
        assert_eq!(note.assets().num_assets(), 0);
    }

    /// `BlockAccount` storage is `[selector, account_suffix, account_prefix]`.
    #[test]
    fn block_account_storage_layout() {
        let blocked = account_id(3);
        let storage = NoteStorage::from(BlocklistConfig::BlockAccount { account: blocked });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(BlocklistConfig::SELECTOR_BLOCK_ACCOUNT),
                blocked.suffix(),
                blocked.prefix().as_felt(),
            ]
        );
    }

    /// `UnblockAccount` storage is `[selector, account_suffix, account_prefix]`.
    #[test]
    fn unblock_account_storage_layout() {
        let blocked = account_id(3);
        let storage = NoteStorage::from(BlocklistConfig::UnblockAccount { account: blocked });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(BlocklistConfig::SELECTOR_UNBLOCK_ACCOUNT),
                blocked.suffix(),
                blocked.prefix().as_felt(),
            ]
        );
    }
}
