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
use crate::note::costs::{NoteConsumptionCost, PAUSE_CONFIG_CONSUMPTION_CYCLES};

// NOTE SCRIPT
// ================================================================================================

/// Path to the PAUSE_CONFIG note script procedure in the standards library.
const PAUSE_CONFIG_SCRIPT_PATH: &str = "::miden::standards::notes::pause_config::main";

// Initialize the PAUSE_CONFIG note script only once.
static PAUSE_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(PAUSE_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains PAUSE_CONFIG note script procedure")
});

// PAUSE CONFIG
// ================================================================================================

/// A management action of the
/// [`PausableManager`](crate::account::access::pausable::PausableManager) component that a
/// [`PauseConfigNote`] triggers on the account that consumes it.
///
/// The action is encoded into the note's storage (see [`NoteStorage`] conversion below) and is
/// fixed at note creation, bound into the note commitment. The consuming account's
/// `PausableManager` procedures authorize the action through the account-wide
/// [`Authority`](crate::account::access::Authority) component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseConfig {
    /// Pause the account, blocking pause-gated procedures until a matching unpause.
    Pause,
    /// Unpause the account.
    Unpause,
}

impl PauseConfig {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Config note selectors stored in the first storage item. Keep in sync with
    // `pause_config.masm`.
    const SELECTOR_PAUSE: u8 = 0;
    const SELECTOR_UNPAUSE: u8 = 1;

    /// Returns the note storage values encoding this action, laid out as `[selector]`.
    fn to_storage_values(self) -> Vec<Felt> {
        match self {
            PauseConfig::Pause => vec![Felt::from(Self::SELECTOR_PAUSE)],
            PauseConfig::Unpause => vec![Felt::from(Self::SELECTOR_UNPAUSE)],
        }
    }
}

impl From<PauseConfig> for NoteStorage {
    fn from(config: PauseConfig) -> Self {
        NoteStorage::new(config.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// PAUSE CONFIG NOTE
// ================================================================================================

/// A PauseConfig note: triggers a
/// [`PausableManager`](crate::account::access::pausable::PausableManager) admin action on the
/// account that consumes it.
///
/// A single note script dispatches on a selector in the note's storage to one of the component's
/// admin procedures (`pause`, `unpause`). Authorization is enforced by those procedures through
/// the account-wide [`Authority`](crate::account::access::Authority) component, so the note carries
/// no assets.
///
/// The note is always public (for network execution) and tagged for `account` — the account
/// carrying the `PausableManager` component whose pause state is being managed.
///
/// The note is bound to the target `account` by a
/// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) attachment: the script asserts
/// that the consuming account matches that target before dispatching, so the note cannot be
/// consumed by a third-party account that merely accepts its sender.
///
/// The note must be public: the script rejects a non-public note, so the action cannot be
/// hidden from the chain by a hand-crafted private note with the same script and storage.
///
/// Construct one with the [builder](PauseConfigNote::builder); convert it into a protocol [`Note`]
/// infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct PauseConfigNote {
    sender: AccountId,
    target: AccountId,
    config: PauseConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl PauseConfigNote {
    /// Builds a new [`PauseConfigNote`] that applies `config` to `account`.
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
        config: PauseConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // The note script asserts that the consuming account matches this target before
        // dispatching.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source(
                "failed to bind the PauseConfig note to its target account",
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

impl PauseConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a PauseConfig note: a single selector.
    pub const NUM_STORAGE_ITEMS: usize = 1;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the PauseConfig note.
    pub fn script() -> NoteScript {
        PAUSE_CONFIG_SCRIPT.clone()
    }

    /// Returns the PauseConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        PAUSE_CONFIG_SCRIPT.root()
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
    pub fn config(&self) -> PauseConfig {
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

impl<S: pause_config_note_builder::State> PauseConfigNoteBuilder<S> {
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

impl<S: pause_config_note_builder::State> PauseConfigNoteBuilder<S>
where
    S::SerialNumber: pause_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> PauseConfigNoteBuilder<pause_config_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<PauseConfigNote> for Note {
    fn from(note: PauseConfigNote) -> Self {
        // PauseConfig notes carry no assets and are always public for network execution; the action
        // lives in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            PauseConfigNote::script(),
            NoteStorage::from(note.config),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for PauseConfigNote {
    fn consumption_cycles() -> u32 {
        PAUSE_CONFIG_CONSUMPTION_CYCLES
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
    fn builder_builds_pause_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let managed = account_id(1);
        let sender = account_id(2);

        let note = PauseConfigNote::builder()
            .sender(sender)
            .target(managed)
            .config(PauseConfig::Pause)
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender);
        assert_eq!(note.target(), managed);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(managed));
        assert_eq!(note.assets().num_assets(), 0);
    }

    /// `Pause` / `Unpause` storage is a single selector item.
    #[test]
    fn action_storage_layout() {
        let pause = NoteStorage::from(PauseConfig::Pause);
        assert_eq!(pause.items(), &[Felt::from(PauseConfig::SELECTOR_PAUSE)]);

        let unpause = NoteStorage::from(PauseConfig::Unpause);
        assert_eq!(unpause.items(), &[Felt::from(PauseConfig::SELECTOR_UNPAUSE)]);
    }
}
