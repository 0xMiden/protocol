use alloc::vec::Vec;

use miden_protocol::Word;
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

use crate::StandardsLib;
use crate::note::NetworkAccountTarget;

// NOTE SCRIPT
// ================================================================================================

/// Path to the POLICY_MANAGER_V2_MIGRATION note script procedure in the standards library.
const POLICY_MANAGER_V2_MIGRATION_SCRIPT_PATH: &str =
    "::miden::standards::notes::policy_manager_v2_migration::main";

// Initialize the POLICY_MANAGER_V2_MIGRATION note script only once.
static POLICY_MANAGER_V2_MIGRATION_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(POLICY_MANAGER_V2_MIGRATION_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains POLICY_MANAGER_V2_MIGRATION note script procedure")
});

// TOKEN POLICY MANAGER V2 MIGRATION NOTE
// ================================================================================================

/// A note that points the asset callback slots of the consuming faucet at the
/// [`TokenPolicyManagerV2`](crate::account::policies::TokenPolicyManagerV2) transfer callbacks.
///
/// See [`TokenPolicyManagerV2`](crate::account::policies::TokenPolicyManagerV2) for when a faucet
/// needs it. The called procedure authorizes the note sender through the account-wide
/// [`Authority`](crate::account::access::Authority) component, so the note carries no assets.
///
/// The note is always public (for network execution) and bound to the target faucet by a
/// [`NetworkAccountTarget`] attachment.
///
/// Construct one with the [builder](TokenPolicyManagerV2MigrationNote::builder); convert it into a
/// protocol [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct TokenPolicyManagerV2MigrationNote {
    sender: AccountId,
    target: AccountId,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl TokenPolicyManagerV2MigrationNote {
    /// Builds a new [`TokenPolicyManagerV2MigrationNote`] for the `target` faucet.
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
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source(
                "failed to bind the policy manager v2 migration note to its target account",
                err,
            )
        })?;

        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            target,
            serial_number,
            attachments,
        })
    }
}

impl TokenPolicyManagerV2MigrationNote {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the note.
    pub fn script() -> NoteScript {
        POLICY_MANAGER_V2_MIGRATION_SCRIPT.clone()
    }

    /// Returns the script root of the note.
    pub fn script_root() -> NoteScriptRoot {
        POLICY_MANAGER_V2_MIGRATION_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the authorizing party).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the faucet the note is bound to.
    pub fn target(&self) -> AccountId {
        self.target
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

impl<S: token_policy_manager_v2_migration_note_builder::State>
    TokenPolicyManagerV2MigrationNoteBuilder<S>
{
    /// Adds a single attachment to the note.
    pub fn attachment(mut self, attachment: impl Into<NoteAttachment>) -> Self {
        self.attachments.push(attachment.into());
        self
    }
}

impl<S: token_policy_manager_v2_migration_note_builder::State>
    TokenPolicyManagerV2MigrationNoteBuilder<S>
where
    S::SerialNumber: token_policy_manager_v2_migration_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> TokenPolicyManagerV2MigrationNoteBuilder<
        token_policy_manager_v2_migration_note_builder::SetSerialNumber<S>,
    > {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<TokenPolicyManagerV2MigrationNote> for Note {
    fn from(note: TokenPolicyManagerV2MigrationNote) -> Self {
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            TokenPolicyManagerV2MigrationNote::script(),
            NoteStorage::default(),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}
