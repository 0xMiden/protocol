use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::{AccountCode, AccountCodeUpgrade, AccountId};
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
use crate::note::costs::{NoteConsumptionCost, UPGRADE_CONSUMPTION_CYCLES};
use crate::note::{AccountCodeUpgradeAttachment, NetworkAccountTarget};

// NOTE SCRIPT
// ================================================================================================

/// Path to the UPGRADE note script procedure in the standards library.
const UPGRADE_SCRIPT_PATH: &str = "::miden::standards::notes::upgrade::main";

// Initialize the UPGRADE note script only once.
static UPGRADE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(UPGRADE_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains UPGRADE note script procedure")
});

// UPGRADE NOTE
// ================================================================================================

/// An Upgrade note: upgrades the code of the network account that consumes it by calling the
/// `upgrade` procedure of its [`UpgradeManager`](crate::account::upgrade::UpgradeManager)
/// component.
///
/// The commitment to the new code is carried in the note's storage as `[NEW_CODE_COMMITMENT]`.
/// The called `upgrade` procedure authorizes the sender through the account-wide
/// [`Authority`](crate::account::access::Authority) component.
///
/// The new code itself is carried in an [`AccountCodeUpgradeAttachment`], from which the
/// transaction host provides it to the kernel. The note script does not require the attachment:
/// the kernel validates the provided code against the commitment either way. The code must fit
/// into the note's [`NoteAttachments`]; a larger upgrade must provide the code through the advice
/// map instead (see [`AccountCodeUpgrade`]).
///
/// The note is always public (for network execution) and bound to the `target` account by a
/// [`NetworkAccountTarget`] attachment. The script asserts both before calling `upgrade`.
#[derive(Debug, Clone)]
pub struct UpgradeNote {
    sender: AccountId,
    target: AccountId,
    new_code_commitment: Word,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl UpgradeNote {
    /// Builds a new [`UpgradeNote`] that upgrades the code of `target` to `code`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the attachments carry an [`AccountCodeUpgradeAttachment`] that does not decode or carries
    ///   code other than `code`.
    /// - `target` is not a public account (the note is bound to it via a `NetworkAccountTarget`,
    ///   which requires a public target).
    /// - the attachments carry a `NetworkAccountTarget` for an account other than `target`.
    /// - the attachments exceed their protocol limit (see [`NoteAttachments::new`]); the code and
    ///   target attachments occupy some of the available words and slots.
    #[builder]
    pub fn new(
        #[builder(field)] mut attachments: Vec<NoteAttachment>,
        sender: AccountId,
        target: AccountId,
        code: AccountCode,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        let code_upgrade = AccountCodeUpgrade::new(code);
        let new_code_commitment = code_upgrade.commitment();
        AccountCodeUpgradeAttachment::ensure_presence(&mut attachments, code_upgrade)?;

        // Bind the note to `target`.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source(
                "failed to bind the upgrade note to its target account",
                err,
            )
        })?;

        let attachments = NoteAttachments::new(attachments)?;

        Ok(Self {
            sender,
            target,
            new_code_commitment,
            serial_number,
            attachments,
        })
    }
}

impl UpgradeNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of an Upgrade note: the new code commitment.
    ///
    /// Must be kept in sync with `NUM_STORAGE_ITEMS` in the note script.
    pub const NUM_STORAGE_ITEMS: usize = Word::NUM_ELEMENTS;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the Upgrade note.
    pub fn script() -> NoteScript {
        UPGRADE_SCRIPT.clone()
    }

    /// Returns the script root of the Upgrade note.
    pub fn script_root() -> NoteScriptRoot {
        UPGRADE_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the upgrade).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the upgraded account; the target of the note.
    pub fn target(&self) -> AccountId {
        self.target
    }

    /// Returns the commitment to the code the note upgrades the target account to.
    pub fn new_code_commitment(&self) -> Word {
        self.new_code_commitment
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

impl<S: upgrade_note_builder::State> UpgradeNoteBuilder<S> {
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

impl<S: upgrade_note_builder::State> UpgradeNoteBuilder<S>
where
    S::SerialNumber: upgrade_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> UpgradeNoteBuilder<upgrade_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<UpgradeNote> for Note {
    fn from(note: UpgradeNote) -> Self {
        // Upgrade notes carry no assets and are always public for network execution; the new code
        // commitment lives in the note storage and the new code in an attachment.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let storage = NoteStorage::new(note.new_code_commitment.as_elements().to_vec())
            .expect("number of storage items should not exceed max storage items");
        let recipient = NoteRecipient::new(note.serial_number, UpgradeNote::script(), storage);

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for UpgradeNote {
    fn consumption_cycles() -> u32 {
        UPGRADE_CONSUMPTION_CYCLES
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::rand::RandomCoin;

    use super::*;
    use crate::testing::account_component::{IncrNonceAuthComponent, MockProceduresComponent};

    fn account_id(seed: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([seed; 32])
    }

    fn build_upgrade_note(target: AccountId, code: AccountCode) -> Result<UpgradeNote, NoteError> {
        UpgradeNote::builder()
            .sender(account_id(2))
            .target(target)
            .code(code)
            .serial_number(Word::empty())
            .build()
    }

    /// Returns account code with `num_procedures` procedures next to its auth procedure.
    fn code_with_procedures(num_procedures: usize) -> anyhow::Result<AccountCode> {
        Ok(AccountCode::from_components(&[
            IncrNonceAuthComponent.into(),
            MockProceduresComponent::new(num_procedures).into(),
        ])?)
    }

    /// The builder produces a public, asset-less note tagged for the upgraded account, whose
    /// storage is the commitment to the new code.
    #[test]
    fn builder_builds_upgrade_note() -> anyhow::Result<()> {
        let mut rng = RandomCoin::new(Word::empty());
        let target = account_id(1);
        let sender = account_id(2);
        let code = AccountCode::mock();

        let note = UpgradeNote::builder()
            .sender(sender)
            .target(target)
            .code(code.clone())
            .generate_serial_number(&mut rng)
            .build()?;

        assert_eq!(note.sender(), sender);
        assert_eq!(note.target(), target);
        assert_eq!(note.new_code_commitment(), code.commitment());

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(target));
        assert_eq!(note.assets().num_assets(), 0);
        assert_eq!(note.storage().items(), code.commitment().as_elements());
        assert_eq!(note.storage().items().len(), UpgradeNote::NUM_STORAGE_ITEMS);

        Ok(())
    }

    /// The built note carries a `NetworkAccountTarget` attachment bound to the upgraded account and
    /// the new code in `AccountCodeUpgradeAttachment` chunks.
    #[rstest::rstest]
    #[case::single_chunk(1)]
    #[case::two_chunks(200)]
    fn note_carries_target_and_code_attachments(
        #[case] num_procedures: usize,
    ) -> anyhow::Result<()> {
        let target = account_id(1);
        let code = code_with_procedures(num_procedures)?;
        let note = Note::from(build_upgrade_note(target, code.clone())?);

        let network_target = NetworkAccountTarget::try_from(note.attachments())?;
        assert_eq!(network_target.target_id(), target);

        let code_upgrade = AccountCodeUpgradeAttachment::try_from_attachments(note.attachments())?;
        assert_eq!(code_upgrade.code_upgrade().code(), &code);

        Ok(())
    }

    /// Code that does not fit into the note attachments is rejected.
    #[test]
    fn too_large_code_is_rejected() -> anyhow::Result<()> {
        let code = code_with_procedures(AccountCode::MAX_NUM_PROCEDURES - 1)?;
        let result = build_upgrade_note(account_id(1), code);

        assert_matches!(result, Err(NoteError::NoteAttachmentsTooManyWords(_)));

        Ok(())
    }
}
