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
use crate::note::costs::{ALLOWLIST_CONFIG_CONSUMPTION_CYCLES, NoteConsumptionCost};

// NOTE SCRIPT
// ================================================================================================

/// Path to the ALLOWLIST_CONFIG note script procedure in the standards library.
const ALLOWLIST_CONFIG_SCRIPT_PATH: &str = "::miden::standards::notes::allowlist_config::main";

// Initialize the ALLOWLIST_CONFIG note script only once.
static ALLOWLIST_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(ALLOWLIST_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains ALLOWLIST_CONFIG note script procedure")
});

// ALLOWLIST CONFIG
// ================================================================================================

/// A management action of the
/// [`AllowlistManager`](crate::account::policies::AllowlistManager) component that an
/// [`AllowlistConfigNote`] triggers on the account that consumes it.
///
/// The action, together with its argument, is encoded into the note's storage (see [`NoteStorage`]
/// conversion below). Because the storage is fixed at note creation and bound into the note
/// commitment, the authorized party is the note sender: the consuming account's `AllowlistManager`
/// procedures authorize the sender through the account-wide `Authority` component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowlistConfig {
    /// Add `account` to the allowlist. Allowing an already allowed account is a noop.
    AllowAccount { account: AccountId },
    /// Remove `account` from the allowlist. Disallowing an account that is not allowed is a noop.
    DisallowAccount { account: AccountId },
}

impl AllowlistConfig {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Config note selectors stored in the first storage item. Keep in sync with
    // `allowlist_config.masm`.
    const SELECTOR_ALLOW_ACCOUNT: u8 = 0;
    const SELECTOR_DISALLOW_ACCOUNT: u8 = 1;

    /// Returns the selector encoding this action in the first storage item.
    const fn selector(self) -> u8 {
        match self {
            AllowlistConfig::AllowAccount { .. } => Self::SELECTOR_ALLOW_ACCOUNT,
            AllowlistConfig::DisallowAccount { .. } => Self::SELECTOR_DISALLOW_ACCOUNT,
        }
    }

    /// Returns the account the action operates on.
    const fn target(self) -> AccountId {
        match self {
            AllowlistConfig::AllowAccount { account }
            | AllowlistConfig::DisallowAccount { account } => account,
        }
    }

    /// Returns the note storage values encoding this action, laid out as `[selector,
    /// account_suffix, account_prefix]`.
    fn to_storage_values(self) -> Vec<Felt> {
        let account = self.target();
        vec![Felt::from(self.selector()), account.suffix(), account.prefix().as_felt()]
    }
}

impl From<AllowlistConfig> for NoteStorage {
    fn from(config: AllowlistConfig) -> Self {
        NoteStorage::new(config.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// ALLOWLIST CONFIG NOTE
// ================================================================================================

/// An AllowlistConfig note: triggers an
/// [`AllowlistManager`](crate::account::policies::AllowlistManager) admin action on the account
/// that consumes it.
///
/// A single note script dispatches on a selector in the note's storage to one of the component's
/// admin procedures (`allow_account`, `disallow_account`). Authorization is enforced by those
/// procedures through the account-wide `Authority` component against the note sender, so the note
/// carries no assets and its authorization is bound to `sender` at creation time.
///
/// The note is always public and tagged for `target` — the account carrying the
/// `AllowlistManager` component whose allowlist is being managed. The `sender` is the account
/// authorized for the action per the target's `Authority` configuration (the owner under
/// `Authority::OwnerControlled`, or a role member under `Authority::RbacControlled`).
///
/// Construct one with the [builder](AllowlistConfigNote::builder); convert it into a protocol
/// [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct AllowlistConfigNote {
    sender: AccountId,
    target: AccountId,
    config: AllowlistConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl AllowlistConfigNote {
    /// Builds a new [`AllowlistConfigNote`] that applies `config` to `target`.
    ///
    /// # Errors
    ///
    /// Returns an error if the attachments exceed their protocol limit (see
    /// [`NoteAttachments::new`]).
    #[builder]
    pub fn new(
        #[builder(field)] attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        config: AllowlistConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
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

impl AllowlistConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of an AllowlistConfig note: a selector followed by the account ID
    /// the action operates on.
    ///
    /// Both actions carry the same arguments, so the layout is fixed at `[selector,
    /// account_suffix, account_prefix]`.
    pub const NUM_STORAGE_ITEMS: usize = 3;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the AllowlistConfig note.
    pub fn script() -> NoteScript {
        ALLOWLIST_CONFIG_SCRIPT.clone()
    }

    /// Returns the AllowlistConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        ALLOWLIST_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed account (the account the note is tagged for).
    pub fn target(&self) -> AccountId {
        self.target
    }

    /// Returns the admin action carried by the note.
    pub fn config(&self) -> AllowlistConfig {
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

impl<S: allowlist_config_note_builder::State> AllowlistConfigNoteBuilder<S> {
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

impl<S: allowlist_config_note_builder::State> AllowlistConfigNoteBuilder<S>
where
    S::SerialNumber: allowlist_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> AllowlistConfigNoteBuilder<allowlist_config_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<AllowlistConfigNote> for Note {
    fn from(note: AllowlistConfigNote) -> Self {
        // AllowlistConfig notes carry no assets and are always public for network execution; the
        // action and its argument live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            AllowlistConfigNote::script(),
            NoteStorage::from(note.config),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for AllowlistConfigNote {
    fn consumption_cycles() -> u32 {
        ALLOWLIST_CONFIG_CONSUMPTION_CYCLES
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
    fn builder_builds_allowlist_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);
        let owner = account_id(2);
        let allowed = account_id(3);

        let note = AllowlistConfigNote::builder()
            .sender(owner)
            .target(managed)
            .config(AllowlistConfig::AllowAccount { account: allowed })
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

    /// `AllowAccount` storage is `[selector, account_suffix, account_prefix]`.
    #[test]
    fn allow_account_storage_layout() {
        let allowed = account_id(3);
        let storage = NoteStorage::from(AllowlistConfig::AllowAccount { account: allowed });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(AllowlistConfig::SELECTOR_ALLOW_ACCOUNT),
                allowed.suffix(),
                allowed.prefix().as_felt(),
            ]
        );
    }

    /// `DisallowAccount` storage is `[selector, account_suffix, account_prefix]`.
    #[test]
    fn disallow_account_storage_layout() {
        let allowed = account_id(3);
        let storage = NoteStorage::from(AllowlistConfig::DisallowAccount { account: allowed });

        assert_eq!(
            storage.items(),
            &[
                Felt::from(AllowlistConfig::SELECTOR_DISALLOW_ACCOUNT),
                allowed.suffix(),
                allowed.prefix().as_felt(),
            ]
        );
    }
}
