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

/// Path to the FAUCET_POLICY_ACTION note script procedure in the standards library.
const FAUCET_POLICY_ACTION_SCRIPT_PATH: &str =
    "::miden::standards::notes::faucet_policy_action::main";

// Initialize the FAUCET_POLICY_ACTION note script only once.
static FAUCET_POLICY_ACTION_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(FAUCET_POLICY_ACTION_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains FAUCET_POLICY_ACTION note script procedure")
});

// FAUCET POLICY ACTION
// ================================================================================================

/// A policy-switch action of the
/// [`TokenPolicyManager`](crate::account::policies::TokenPolicyManager) component that a
/// [`FaucetPolicyActionNote`] triggers on the faucet that consumes it.
///
/// Each variant switches the active policy of one kind to `policy_root`, which must be a root that
/// the manager registered as an allowed alternative for that kind (otherwise the corresponding
/// `set_*_policy` procedure aborts). Obtain a root from a policy type, e.g.
/// `MintPolicy::owner_only().root()` or `MintOwnerOnly::root()`.
///
/// The action is encoded into the note's storage (see [`NoteStorage`] conversion below). Because
/// the storage is fixed at note creation and bound into the note commitment, the authorized party
/// is the note sender: the consuming faucet's `TokenPolicyManager` procedures authorize the sender
/// through the account-wide `Authority` component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaucetPolicyAction {
    /// Switch the active mint policy to `policy_root`.
    SetMintPolicy { policy_root: AccountProcedureRoot },
    /// Switch the active burn policy to `policy_root`.
    SetBurnPolicy { policy_root: AccountProcedureRoot },
    /// Switch the active send (outgoing transfer) policy to `policy_root`.
    SetSendPolicy { policy_root: AccountProcedureRoot },
    /// Switch the active receive (incoming transfer) policy to `policy_root`.
    SetReceivePolicy { policy_root: AccountProcedureRoot },
}

impl FaucetPolicyAction {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Action selectors stored in the storage item after the policy root. Keep in sync with
    // `faucet_policy_action.masm`.
    const SELECTOR_SET_MINT_POLICY: u8 = 0;
    const SELECTOR_SET_BURN_POLICY: u8 = 1;
    const SELECTOR_SET_SEND_POLICY: u8 = 2;
    const SELECTOR_SET_RECEIVE_POLICY: u8 = 3;

    /// Returns the selector and policy root of this action.
    fn parts(self) -> (u8, AccountProcedureRoot) {
        match self {
            FaucetPolicyAction::SetMintPolicy { policy_root } => {
                (Self::SELECTOR_SET_MINT_POLICY, policy_root)
            },
            FaucetPolicyAction::SetBurnPolicy { policy_root } => {
                (Self::SELECTOR_SET_BURN_POLICY, policy_root)
            },
            FaucetPolicyAction::SetSendPolicy { policy_root } => {
                (Self::SELECTOR_SET_SEND_POLICY, policy_root)
            },
            FaucetPolicyAction::SetReceivePolicy { policy_root } => {
                (Self::SELECTOR_SET_RECEIVE_POLICY, policy_root)
            },
        }
    }

    /// Returns the note storage values encoding this action, laid out as `[POLICY_ROOT, selector]`.
    fn to_storage_values(self) -> Vec<Felt> {
        let (selector, policy_root) = self.parts();
        let mut values = Vec::with_capacity(FaucetPolicyActionNote::NUM_STORAGE_ITEMS);
        values.extend_from_slice(policy_root.as_word().as_elements());
        values.push(Felt::from(selector));
        values
    }
}

impl From<FaucetPolicyAction> for NoteStorage {
    fn from(action: FaucetPolicyAction) -> Self {
        NoteStorage::new(action.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// FAUCET POLICY ACTION NOTE
// ================================================================================================

/// A FaucetPolicyAction note: triggers a
/// [`TokenPolicyManager`](crate::account::policies::TokenPolicyManager) policy switch on the
/// faucet that consumes it.
///
/// A single note script dispatches on a selector in the note's storage to one of the component's
/// setters (`set_mint_policy`, `set_burn_policy`, `set_send_policy`, `set_receive_policy`).
/// Authorization is enforced by those procedures through the account-wide `Authority` component
/// against the note sender, so the note carries no assets and its authorization is bound to
/// `sender` at creation time.
///
/// The note is always public (for network execution) and tagged for `account` — the faucet
/// carrying the `TokenPolicyManager` component whose policy is being switched. The `sender` is the
/// account authorized for the action per the faucet's `Authority` configuration (the owner under
/// `Authority::OwnerControlled`, or a role member under `Authority::RbacControlled`).
///
/// Construct one with the [builder](FaucetPolicyActionNote::builder); convert it into a protocol
/// [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct FaucetPolicyActionNote {
    sender: AccountId,
    account: AccountId,
    action: FaucetPolicyAction,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl FaucetPolicyActionNote {
    /// Builds a new [`FaucetPolicyActionNote`] that triggers `action` on `account`.
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
        action: FaucetPolicyAction,
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

impl FaucetPolicyActionNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a FaucetPolicyAction note: a selector plus the policy root word.
    pub const NUM_STORAGE_ITEMS: usize = 5;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the FaucetPolicyAction note.
    pub fn script() -> NoteScript {
        FAUCET_POLICY_ACTION_SCRIPT.clone()
    }

    /// Returns the FaucetPolicyAction note script root.
    pub fn script_root() -> NoteScriptRoot {
        FAUCET_POLICY_ACTION_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the account authorized for the action).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed faucet (the account the note is tagged for).
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the policy-switch action carried by the note.
    pub fn action(&self) -> FaucetPolicyAction {
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

impl<S: faucet_policy_action_note_builder::State> FaucetPolicyActionNoteBuilder<S> {
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

impl<S: faucet_policy_action_note_builder::State> FaucetPolicyActionNoteBuilder<S>
where
    S::SerialNumber: faucet_policy_action_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> FaucetPolicyActionNoteBuilder<faucet_policy_action_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<FaucetPolicyActionNote> for Note {
    fn from(note: FaucetPolicyActionNote) -> Self {
        // FaucetPolicyAction notes carry no assets and are always public for network execution; the
        // action and its policy root live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.account));
        let recipient = NoteRecipient::new(
            note.serial_number,
            FaucetPolicyActionNote::script(),
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

    fn policy_root(seed: u32) -> AccountProcedureRoot {
        AccountProcedureRoot::from_raw(Word::from([seed, seed + 1, seed + 2, seed + 3]))
    }

    /// The builder produces a public, asset-less note tagged for the managed faucet.
    #[test]
    fn builder_builds_faucet_policy_action_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let faucet = account_id(1);
        let sender = account_id(2);

        let note = FaucetPolicyActionNote::builder()
            .sender(sender)
            .account(faucet)
            .action(FaucetPolicyAction::SetMintPolicy { policy_root: policy_root(10) })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender);
        assert_eq!(note.account(), faucet);

        let note = Note::from(note);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.metadata().tag(), NoteTag::with_account_target(faucet));
        assert_eq!(note.assets().num_assets(), 0);
    }

    /// Storage is `[POLICY_ROOT, selector]` with the selector matching the action kind.
    #[test]
    fn storage_layout() {
        let root = policy_root(10);

        let cases = [
            (
                FaucetPolicyAction::SetMintPolicy { policy_root: root },
                FaucetPolicyAction::SELECTOR_SET_MINT_POLICY,
            ),
            (
                FaucetPolicyAction::SetBurnPolicy { policy_root: root },
                FaucetPolicyAction::SELECTOR_SET_BURN_POLICY,
            ),
            (
                FaucetPolicyAction::SetSendPolicy { policy_root: root },
                FaucetPolicyAction::SELECTOR_SET_SEND_POLICY,
            ),
            (
                FaucetPolicyAction::SetReceivePolicy { policy_root: root },
                FaucetPolicyAction::SELECTOR_SET_RECEIVE_POLICY,
            ),
        ];

        for (action, selector) in cases {
            let storage = NoteStorage::from(action);
            let mut expected = Vec::from(root.as_word().as_elements());
            expected.push(Felt::from(selector));
            assert_eq!(storage.items(), expected.as_slice());
            assert_eq!(storage.items().len(), FaucetPolicyActionNote::NUM_STORAGE_ITEMS);
        }
    }
}
