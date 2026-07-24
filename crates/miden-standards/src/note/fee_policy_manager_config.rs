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
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::StandardsLib;

// NOTE SCRIPT
// ================================================================================================

/// Path to the FEE_POLICY_MANAGER_CONFIG note script procedure in the standards library.
const FEE_POLICY_MANAGER_CONFIG_SCRIPT_PATH: &str =
    "::miden::standards::notes::fee_policy_manager_config::main";

// Initialize the FEE_POLICY_MANAGER_CONFIG note script only once.
static FEE_POLICY_MANAGER_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(FEE_POLICY_MANAGER_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains FEE_POLICY_MANAGER_CONFIG note script procedure")
});

// FEE POLICY MANAGER CONFIG
// ================================================================================================

/// An allowed-policies map mutation of the
/// [`FeePolicyManager`](crate::account::fees::FeePolicyManager) that a
/// [`FeePolicyManagerConfigNote`] triggers on the account that consumes it.
///
/// Each variant adds or removes one fee policy root from the allowed fee policy roots map. Adding a
/// root authorizes `set_fee_policy` to activate it; the root must additionally be a procedure of
/// the account for `set_fee_policy` to accept it.
///
/// The action is encoded into the note's storage (see [`NoteStorage`] conversion below). Because
/// the storage is fixed at note creation and bound into the note commitment, the authorized party
/// is the note sender: the consuming account's fee policy procedures authorize the sender through
/// the account-wide `Authority` component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeePolicyManagerConfig {
    /// Adds `policy_root` to the allowed fee policy roots map.
    AddAllowedFeePolicy { policy_root: AccountProcedureRoot },
    /// Removes `policy_root` from the allowed fee policy roots map.
    RemoveAllowedFeePolicy { policy_root: AccountProcedureRoot },
}

impl FeePolicyManagerConfig {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Action selectors stored in the last storage item. Keep in sync with
    // `fee_policy_manager_config.masm`.
    const SELECTOR_ADD_ALLOWED_FEE_POLICY: u8 = 0;
    const SELECTOR_REMOVE_ALLOWED_FEE_POLICY: u8 = 1;

    /// Returns the selector and the affected fee policy root of this action.
    fn parts(self) -> (u8, Word) {
        match self {
            FeePolicyManagerConfig::AddAllowedFeePolicy { policy_root } => {
                (Self::SELECTOR_ADD_ALLOWED_FEE_POLICY, policy_root.as_word())
            },
            FeePolicyManagerConfig::RemoveAllowedFeePolicy { policy_root } => {
                (Self::SELECTOR_REMOVE_ALLOWED_FEE_POLICY, policy_root.as_word())
            },
        }
    }

    /// Returns the note storage values encoding this action, laid out as `[POLICY_ROOT, selector]`.
    fn to_storage_values(self) -> Vec<Felt> {
        let (selector, policy_root) = self.parts();
        let mut values = Vec::with_capacity(FeePolicyManagerConfigNote::NUM_STORAGE_ITEMS);
        values.extend_from_slice(policy_root.as_elements());
        values.push(Felt::from(selector));
        values
    }
}

impl From<FeePolicyManagerConfig> for NoteStorage {
    fn from(action: FeePolicyManagerConfig) -> Self {
        NoteStorage::new(action.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// FEE POLICY MANAGER CONFIG NOTE
// ================================================================================================

/// A FeePolicyManagerConfig note: adds or removes a fee policy root from an account's allowed fee
/// policy roots map.
///
/// A single note script dispatches on a selector in the note's storage to one of the
/// [`FeePolicyManager`](crate::account::fees::FeePolicyManager) allowlist-mutation procedures
/// (exposed by the `AuthNetworkAccount` component). Authorization is enforced by those procedures
/// through the account-wide `Authority` component against the note sender.
///
/// Construct one with the [builder](FeePolicyManagerConfigNote::builder); convert it into a
/// protocol [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct FeePolicyManagerConfigNote {
    sender: AccountId,
    account: AccountId,
    action: FeePolicyManagerConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl FeePolicyManagerConfigNote {
    /// Builds a new [`FeePolicyManagerConfigNote`] that triggers `action` on `account`.
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
        action: FeePolicyManagerConfig,
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

impl FeePolicyManagerConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a FeePolicyManagerConfig note: a selector plus the fee policy
    /// root word.
    pub const NUM_STORAGE_ITEMS: usize = 5;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the FeePolicyManagerConfig note.
    pub fn script() -> NoteScript {
        FEE_POLICY_MANAGER_CONFIG_SCRIPT.clone()
    }

    /// Returns the FeePolicyManagerConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        FEE_POLICY_MANAGER_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed account (the account the note is tagged for).
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the allowlist-mutation action carried by the note.
    pub fn action(&self) -> FeePolicyManagerConfig {
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

impl<S: fee_policy_manager_config_note_builder::State> FeePolicyManagerConfigNoteBuilder<S> {
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

impl<S: fee_policy_manager_config_note_builder::State> FeePolicyManagerConfigNoteBuilder<S>
where
    S::SerialNumber: fee_policy_manager_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> FeePolicyManagerConfigNoteBuilder<fee_policy_manager_config_note_builder::SetSerialNumber<S>>
    {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<FeePolicyManagerConfigNote> for Note {
    fn from(note: FeePolicyManagerConfigNote) -> Self {
        // FeePolicyManagerConfig notes carry no assets and are always public for network execution;
        // the action and its fee policy root live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.account));
        let recipient = NoteRecipient::new(
            note.serial_number,
            FeePolicyManagerConfigNote::script(),
            NoteStorage::from(note.action),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
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

    fn policy_root(seed: u32) -> AccountProcedureRoot {
        AccountProcedureRoot::from_raw(Word::from([seed, seed + 1, seed + 2, seed + 3]))
    }

    /// The builder produces a public, asset-less note tagged for the managed account.
    #[test]
    fn builder_builds_allowlist_action_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let account = account_id(1);
        let sender = account_id(2);

        let note = FeePolicyManagerConfigNote::builder()
            .sender(sender)
            .account(account)
            .action(FeePolicyManagerConfig::AddAllowedFeePolicy { policy_root: policy_root(10) })
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

    /// Storage is `[POLICY_ROOT, selector]` with the selector matching the action kind.
    #[test]
    fn storage_layout() {
        let root = policy_root(10);

        let cases = [
            (
                FeePolicyManagerConfig::AddAllowedFeePolicy { policy_root: root },
                FeePolicyManagerConfig::SELECTOR_ADD_ALLOWED_FEE_POLICY,
            ),
            (
                FeePolicyManagerConfig::RemoveAllowedFeePolicy { policy_root: root },
                FeePolicyManagerConfig::SELECTOR_REMOVE_ALLOWED_FEE_POLICY,
            ),
        ];

        for (action, selector) in cases {
            let storage = NoteStorage::from(action);
            let mut expected = Vec::from(root.as_word().as_elements());
            expected.push(Felt::from(selector));
            assert_eq!(storage.items(), expected.as_slice());
            assert_eq!(storage.items().len(), FeePolicyManagerConfigNote::NUM_STORAGE_ITEMS);
        }
    }

    /// The config-note script root is registered in the [`StandardNote`](crate::note::StandardNote)
    /// reverse lookup.
    #[test]
    fn script_root_is_registered_standard_note() {
        use crate::note::StandardNote;

        let standard = StandardNote::from_script_root(FeePolicyManagerConfigNote::script_root())
            .expect("config note script root should be a registered standard note");
        assert_eq!(standard.name(), "FEE_POLICY_MANAGER_CONFIG");
    }
}
