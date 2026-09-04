use alloc::vec::Vec;

use miden_protocol::account::{AccountId, AccountProcedureRoot};
use miden_protocol::assembly::Path;
use miden_protocol::block::BlockNumber;
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
use crate::note::costs::{FAUCET_POLICY_CONFIG_CONSUMPTION_CYCLES, NoteConsumptionCost};

// NOTE SCRIPT
// ================================================================================================

/// Path to the FAUCET_POLICY_CONFIG note script procedure in the standards library.
const FAUCET_POLICY_CONFIG_SCRIPT_PATH: &str =
    "::miden::standards::notes::faucet_policy_config::main";

// Initialize the FAUCET_POLICY_CONFIG note script only once.
static FAUCET_POLICY_CONFIG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(FAUCET_POLICY_CONFIG_SCRIPT_PATH);
    NoteScript::from_package_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains FAUCET_POLICY_CONFIG note script procedure")
});

// FAUCET POLICY CONFIG
// ================================================================================================

/// A policy-switch action of the
/// [`TokenPolicyManager`](crate::account::policies::TokenPolicyManager) component that a
/// [`FaucetPolicyConfigNote`] triggers on the faucet that consumes it.
///
/// Each variant switches the active policy of one kind to `policy_root`, which must be a root that
/// the manager registered as an allowed alternative for that kind (otherwise the corresponding
/// `set_*_policy` procedure aborts). Obtain a root from a policy type, e.g.
/// `MintPolicy::owner_only().root()` or `MintOwnerOnly::root()`.
///
/// The action is encoded into the note's storage (see [`NoteStorage`] conversion below) and is
/// fixed at note creation, bound into the note commitment. The consuming faucet's
/// `TokenPolicyManager` procedures authorize the action through the account-wide
/// [`Authority`](crate::account::access::Authority) component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaucetPolicyConfig {
    /// Switch the active mint policy to `policy_root`.
    SetMintPolicy { policy_root: AccountProcedureRoot },
    /// Switch the active burn policy to `policy_root`.
    SetBurnPolicy { policy_root: AccountProcedureRoot },
    /// Switch the active send (outgoing transfer) policy to `policy_root`.
    SetSendPolicy { policy_root: AccountProcedureRoot },
    /// Switch the active receive (incoming transfer) policy to `policy_root`.
    SetReceivePolicy { policy_root: AccountProcedureRoot },
}

impl FaucetPolicyConfig {
    // SELECTORS
    // --------------------------------------------------------------------------------------------

    // Config note selectors stored in the storage item after the policy root. Keep in sync with
    // `faucet_policy_config.masm`.
    const SELECTOR_SET_MINT_POLICY: u8 = 0;
    const SELECTOR_SET_BURN_POLICY: u8 = 1;
    const SELECTOR_SET_SEND_POLICY: u8 = 2;
    const SELECTOR_SET_RECEIVE_POLICY: u8 = 3;

    /// Returns the selector and policy root of this action.
    fn parts(self) -> (u8, AccountProcedureRoot) {
        match self {
            FaucetPolicyConfig::SetMintPolicy { policy_root } => {
                (Self::SELECTOR_SET_MINT_POLICY, policy_root)
            },
            FaucetPolicyConfig::SetBurnPolicy { policy_root } => {
                (Self::SELECTOR_SET_BURN_POLICY, policy_root)
            },
            FaucetPolicyConfig::SetSendPolicy { policy_root } => {
                (Self::SELECTOR_SET_SEND_POLICY, policy_root)
            },
            FaucetPolicyConfig::SetReceivePolicy { policy_root } => {
                (Self::SELECTOR_SET_RECEIVE_POLICY, policy_root)
            },
        }
    }

    /// Returns the note storage values encoding this action, laid out as `[POLICY_ROOT, selector]`.
    fn to_storage_values(self) -> Vec<Felt> {
        let (selector, policy_root) = self.parts();
        let mut values = Vec::with_capacity(FaucetPolicyConfigNote::NUM_STORAGE_ITEMS);
        values.extend_from_slice(policy_root.as_word().as_elements());
        values.push(Felt::from(selector));
        values
    }
}

impl From<FaucetPolicyConfig> for NoteStorage {
    fn from(config: FaucetPolicyConfig) -> Self {
        NoteStorage::new(config.to_storage_values())
            .expect("number of storage items should not exceed max storage items")
    }
}

// FAUCET POLICY CONFIG NOTE
// ================================================================================================

/// A FaucetPolicyConfig note: triggers a
/// [`TokenPolicyManager`](crate::account::policies::TokenPolicyManager) policy switch on the
/// faucet that consumes it.
///
/// A single note script dispatches on a selector in the note's storage to one of the component's
/// setters (`set_mint_policy`, `set_burn_policy`, `set_send_policy`, `set_receive_policy`).
/// Authorization is enforced by those procedures through the account-wide
/// [`Authority`](crate::account::access::Authority) component, so the note carries no assets.
///
/// The note is always public (for network execution) and tagged for `account` — the faucet
/// carrying the `TokenPolicyManager` component whose policy is being switched.
///
/// The note is bound to the target `account` by a
/// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) attachment: the script asserts
/// that the consuming account matches that target before dispatching, so the note cannot be
/// consumed by a third-party account that merely accepts its sender.
///
/// The note must be public: the script rejects a non-public note. See
/// [the module docs](crate::note::config#note-type) for the layers that enforce it.
///
/// Construct one with the [builder](FaucetPolicyConfigNote::builder); convert it into a protocol
/// [`Note`] infallibly via `Note::from`.
#[derive(Debug, Clone)]
pub struct FaucetPolicyConfigNote {
    sender: AccountId,
    target: AccountId,
    config: FaucetPolicyConfig,
    serial_number: Word,
    attachments: NoteAttachments,
}

#[bon::bon]
impl FaucetPolicyConfigNote {
    /// Builds a new [`FaucetPolicyConfigNote`] that applies `config` to `account`.
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
        expiration_block_num: Option<BlockNumber>,
        config: FaucetPolicyConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // The note script asserts that the consuming account matches this target before
        // dispatching.
        NetworkAccountTarget::ensure_presence(&mut attachments, target, expiration_block_num)
            .map_err(|err| {
                NoteError::other_with_source(
                    "failed to bind the FaucetPolicyConfig note to its target account",
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

impl FaucetPolicyConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage items of a FaucetPolicyConfig note: a selector plus the policy root word.
    pub const NUM_STORAGE_ITEMS: usize = 5;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the FaucetPolicyConfig note.
    pub fn script() -> NoteScript {
        FAUCET_POLICY_CONFIG_SCRIPT.clone()
    }

    /// Returns the FaucetPolicyConfig note script root.
    pub fn script_root() -> NoteScriptRoot {
        FAUCET_POLICY_CONFIG_SCRIPT.root()
    }

    /// Returns the account ID of the note's sender (the authorizing party under an owner- or
    /// role-controlled `Authority`).
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the account ID of the managed faucet (the account the note is tagged for).
    pub fn target(&self) -> AccountId {
        self.target
    }

    /// Returns the policy-switch action carried by the note.
    pub fn config(&self) -> FaucetPolicyConfig {
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

impl<S: faucet_policy_config_note_builder::State> FaucetPolicyConfigNoteBuilder<S> {
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

impl<S: faucet_policy_config_note_builder::State> FaucetPolicyConfigNoteBuilder<S>
where
    S::SerialNumber: faucet_policy_config_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> FaucetPolicyConfigNoteBuilder<faucet_policy_config_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<FaucetPolicyConfigNote> for Note {
    fn from(note: FaucetPolicyConfigNote) -> Self {
        // FaucetPolicyConfig notes carry no assets and are always public for network execution; the
        // action and its policy root live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient = NoteRecipient::new(
            note.serial_number,
            FaucetPolicyConfigNote::script(),
            NoteStorage::from(note.config),
        );

        Note::with_attachments(NoteAssets::default(), metadata, recipient, note.attachments)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for FaucetPolicyConfigNote {
    fn consumption_cycles() -> u32 {
        FAUCET_POLICY_CONFIG_CONSUMPTION_CYCLES
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
    fn builder_builds_faucet_policy_config_note() {
        let mut rng = RandomCoin::new(Word::empty());
        let faucet = account_id(1);
        let sender = account_id(2);

        let note = FaucetPolicyConfigNote::builder()
            .sender(sender)
            .target(faucet)
            .config(FaucetPolicyConfig::SetMintPolicy { policy_root: policy_root(10) })
            .generate_serial_number(&mut rng)
            .build()
            .unwrap();

        assert_eq!(note.sender(), sender);
        assert_eq!(note.target(), faucet);

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
                FaucetPolicyConfig::SetMintPolicy { policy_root: root },
                FaucetPolicyConfig::SELECTOR_SET_MINT_POLICY,
            ),
            (
                FaucetPolicyConfig::SetBurnPolicy { policy_root: root },
                FaucetPolicyConfig::SELECTOR_SET_BURN_POLICY,
            ),
            (
                FaucetPolicyConfig::SetSendPolicy { policy_root: root },
                FaucetPolicyConfig::SELECTOR_SET_SEND_POLICY,
            ),
            (
                FaucetPolicyConfig::SetReceivePolicy { policy_root: root },
                FaucetPolicyConfig::SELECTOR_SET_RECEIVE_POLICY,
            ),
        ];

        for (action, selector) in cases {
            let storage = NoteStorage::from(action);
            let mut expected = Vec::from(root.as_word().as_elements());
            expected.push(Felt::from(selector));
            assert_eq!(storage.items(), expected.as_slice());
            assert_eq!(storage.items().len(), FaucetPolicyConfigNote::NUM_STORAGE_ITEMS);
        }
    }
}
