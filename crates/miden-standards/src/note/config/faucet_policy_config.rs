use alloc::vec::Vec;
use core::slice;

use miden_protocol::account::{AccountId, AccountProcedureRoot};
use miden_protocol::assembly::Path;
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
use rand::{Rng, RngExt};

use crate::StandardsLib;
use crate::account::policies::TokenPolicyManager;
use crate::note::costs::{FAUCET_POLICY_CONFIG_CONSUMPTION_CYCLES, NoteConsumptionCost};
use crate::note::{NetworkAccountTarget, NumStorageItems};

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
/// Each variant switches the active policy of one kind to the given root or roots, which must be
/// registered by the manager as allowed alternatives for that kind (otherwise the corresponding
/// setter procedure aborts). Obtain the roots from a policy type, e.g.
/// `MintPolicy::owner_only().root()` or `SendPolicy::allow_all().root()`.
///
/// The action is encoded into the note's storage (see [`NoteStorage`] conversion below) and is
/// fixed at note creation, bound into the note commitment. The consuming faucet's
/// `TokenPolicyManager` procedures authorize the action through the account-wide
/// [`Authority`](crate::account::access::Authority) component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaucetPolicyConfig {
    /// Switch the active mint policy to `policy_root`.
    SetMintPolicy { policy_root: AccountProcedureRoot },
    /// Switch the active burn policy to `policy_root`.
    SetBurnPolicy { policy_root: AccountProcedureRoot },
    /// Switch the active send (outgoing transfer) policies to `policy_roots`.
    SetSendPolicyRoots { policy_roots: Vec<AccountProcedureRoot> },
    /// Switch the active receive (incoming transfer) policies to `policy_roots`.
    SetReceivePolicyRoots { policy_roots: Vec<AccountProcedureRoot> },
}

impl FaucetPolicyConfig {
    // VARIANTS
    // --------------------------------------------------------------------------------------------

    // Config note variants stored in the first storage item. Keep in sync with
    // `faucet_policy_config.masm`.
    const VARIANT_SET_MINT_POLICY: u8 = 0;
    const VARIANT_SET_BURN_POLICY: u8 = 1;
    const VARIANT_SET_SEND_POLICY_ROOTS: u8 = 2;
    const VARIANT_SET_RECEIVE_POLICY_ROOTS: u8 = 3;

    /// Returns the variant and policy roots of this action.
    fn parts(&self) -> (u8, &[AccountProcedureRoot]) {
        match self {
            FaucetPolicyConfig::SetMintPolicy { policy_root } => {
                (Self::VARIANT_SET_MINT_POLICY, slice::from_ref(policy_root))
            },
            FaucetPolicyConfig::SetBurnPolicy { policy_root } => {
                (Self::VARIANT_SET_BURN_POLICY, slice::from_ref(policy_root))
            },
            FaucetPolicyConfig::SetSendPolicyRoots { policy_roots } => {
                (Self::VARIANT_SET_SEND_POLICY_ROOTS, policy_roots)
            },
            FaucetPolicyConfig::SetReceivePolicyRoots { policy_roots } => {
                (Self::VARIANT_SET_RECEIVE_POLICY_ROOTS, policy_roots)
            },
        }
    }
}

impl TryFrom<&FaucetPolicyConfig> for NoteStorage {
    type Error = NoteError;

    /// Encodes the action as its variant, padded to a word so that the policy roots are
    /// word-aligned, followed by its policy roots.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the list of policy roots is empty.
    /// - the list of policy roots exceeds [`TokenPolicyManager::MAX_NUM_ACTIVE_TRANSFER_POLICIES`].
    fn try_from(config: &FaucetPolicyConfig) -> Result<Self, Self::Error> {
        let (variant, policy_roots) = config.parts();
        if policy_roots.is_empty() {
            return Err(NoteError::other("faucet policy config must contain a policy root"));
        }
        if policy_roots.len() > TokenPolicyManager::MAX_NUM_ACTIVE_TRANSFER_POLICIES {
            return Err(NoteError::other(format!(
                "faucet policy config contains {} policy roots but the maximum is {}",
                policy_roots.len(),
                TokenPolicyManager::MAX_NUM_ACTIVE_TRANSFER_POLICIES
            )));
        }

        let variant = [Felt::from(variant), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let values = variant
            .into_iter()
            .chain(policy_roots.iter().flat_map(|root| root.as_word().into_elements()))
            .collect();
        NoteStorage::new(values)
    }
}

// FAUCET POLICY CONFIG NOTE
// ================================================================================================

/// A FaucetPolicyConfig note: triggers a
/// [`TokenPolicyManager`](crate::account::policies::TokenPolicyManager) policy switch on the
/// faucet that consumes it.
///
/// A single note script dispatches on the note variant in its storage to one of the component's
/// setters (`set_mint_policy`, `set_burn_policy`, `set_send_policy_roots_commitment`,
/// `set_receive_policy_roots_commitment`). Authorization is enforced by those procedures through
/// the account-wide [`Authority`](crate::account::access::Authority) component, so the note carries
/// no assets.
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
    storage: NoteStorage,
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
    /// - the number of policy roots in `config` is zero or exceeds
    ///   [`TokenPolicyManager::MAX_NUM_ACTIVE_TRANSFER_POLICIES`].
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
        config: FaucetPolicyConfig,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        // The note script asserts that the consuming account matches this target before
        // dispatching.
        NetworkAccountTarget::ensure_presence(&mut attachments, target).map_err(|err| {
            NoteError::other_with_source(
                "failed to bind the FaucetPolicyConfig note to its target account",
                err,
            )
        })?;

        let attachments = NoteAttachments::new(attachments)?;
        let storage = NoteStorage::try_from(&config)?;

        Ok(Self {
            sender,
            target,
            config,
            storage,
            serial_number,
            attachments,
        })
    }
}

impl FaucetPolicyConfigNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The numbers of storage items the FaucetPolicyConfig note script accepts: a variant word plus
    /// a non-empty list of policy root words.
    pub const NUM_STORAGE_ITEMS: NumStorageItems = NumStorageItems::AnyOf(&{
        let mut num_items =
            [NumStorageItems::Exact(0); TokenPolicyManager::MAX_NUM_ACTIVE_TRANSFER_POLICIES];
        let mut index = 0;
        while index < num_items.len() {
            num_items[index] =
                NumStorageItems::Exact(Word::NUM_ELEMENTS + (index + 1) * Word::NUM_ELEMENTS);
            index += 1;
        }
        num_items
    });

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
    pub fn config(&self) -> &FaucetPolicyConfig {
        &self.config
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
        rng: &mut impl Rng,
    ) -> FaucetPolicyConfigNoteBuilder<faucet_policy_config_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.random())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<FaucetPolicyConfigNote> for Note {
    fn from(note: FaucetPolicyConfigNote) -> Self {
        // FaucetPolicyConfig notes carry no assets and are always public for network execution; the
        // action and its policy roots live in the note storage.
        let metadata = PartialNoteMetadata::new(note.sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(note.target));
        let recipient =
            NoteRecipient::new(note.serial_number, FaucetPolicyConfigNote::script(), note.storage);

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
    use assert_matches::assert_matches;
    use miden_protocol::account::AccountType;
    use miden_protocol::crypto::rand::EidosRandomCoin;

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
        let mut rng = EidosRandomCoin::new(Word::empty());
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

    /// The padded variant matching the action kind precedes the policy roots.
    #[rstest::rstest]
    #[case::mint(
        FaucetPolicyConfig::SetMintPolicy { policy_root: policy_root(10) },
        FaucetPolicyConfig::VARIANT_SET_MINT_POLICY,
        &[policy_root(10)],
    )]
    #[case::burn(
        FaucetPolicyConfig::SetBurnPolicy { policy_root: policy_root(10) },
        FaucetPolicyConfig::VARIANT_SET_BURN_POLICY,
        &[policy_root(10)],
    )]
    #[case::send_single(
        FaucetPolicyConfig::SetSendPolicyRoots { policy_roots: vec![policy_root(10)] },
        FaucetPolicyConfig::VARIANT_SET_SEND_POLICY_ROOTS,
        &[policy_root(10)],
    )]
    #[case::send_multiple(
        FaucetPolicyConfig::SetSendPolicyRoots {
            policy_roots: vec![policy_root(10), policy_root(20)],
        },
        FaucetPolicyConfig::VARIANT_SET_SEND_POLICY_ROOTS,
        &[policy_root(10), policy_root(20)],
    )]
    #[case::receive_multiple(
        FaucetPolicyConfig::SetReceivePolicyRoots {
            policy_roots: vec![policy_root(10), policy_root(20)],
        },
        FaucetPolicyConfig::VARIANT_SET_RECEIVE_POLICY_ROOTS,
        &[policy_root(10), policy_root(20)],
    )]
    fn storage_layout(
        #[case] config: FaucetPolicyConfig,
        #[case] variant: u8,
        #[case] policy_roots: &[AccountProcedureRoot],
    ) -> anyhow::Result<()> {
        let storage = NoteStorage::try_from(&config)?;

        let mut expected = vec![Felt::from(variant), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        for root in policy_roots {
            expected.extend_from_slice(root.as_word().as_elements());
        }
        assert_eq!(storage.items(), expected.as_slice());
        assert!(FaucetPolicyConfigNote::NUM_STORAGE_ITEMS.accepts(storage.items().len()));

        Ok(())
    }

    /// The builder rejects an empty list of policy roots and one that exceeds the maximum length.
    #[rstest::rstest]
    #[case::empty(0, "must contain a policy root")]
    #[case::too_many(
        TokenPolicyManager::MAX_NUM_ACTIVE_TRANSFER_POLICIES + 1,
        "contains 17 policy roots but the maximum is 16"
    )]
    fn builder_rejects_invalid_number_of_policy_roots(
        #[case] num_roots: usize,
        #[case] expected_error: &str,
    ) {
        let result = FaucetPolicyConfigNote::builder()
            .sender(account_id(2))
            .target(account_id(1))
            .config(FaucetPolicyConfig::SetSendPolicyRoots {
                policy_roots: vec![policy_root(10); num_roots],
            })
            .serial_number(Word::empty())
            .build();

        assert_matches!(result, Err(NoteError::Other { error_msg, .. }) => {
            assert!(error_msg.contains(expected_error));
        });
    }
}
