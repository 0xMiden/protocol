//! Unified token policy manager.
//!
//! [`TokenPolicyManager`] owns the policy state for fungible faucets. Mint and burn have a single
//! active policy each, while send and receive have a list of active policies each. All four kinds
//! use an `allowed_*_policies` map slot for validating policy-switching at set time. Mint and burn
//! are dispatched by `exec`-invoked
//! `execute_*_policy` wrappers from the faucet flow. Send and receive are dispatched by
//! `invoke_send_policy` / `invoke_receive_policy` wrappers whose roots live in the
//! protocol-reserved callback slots
//! (`miden::protocol::faucet::callback::on_before_asset_added_to_account` and
//! `miden::protocol::faucet::callback::on_before_note_sealed`); the kernel `dyncall`s the wrapper,
//! which limits the transaction's expiration, applies the account-wide pause check and then
//! dispatches to the active policy roots.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::iter;

use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
    ValueSlotSchema,
    WordSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountComponentName,
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::AssetCallbacks;
use miden_protocol::utils::sync::LazyLock;

use super::burn::BurnPolicy;
use super::mint::MintPolicy;
use super::transfer::{ReceivePolicy, SendPolicy, TransferPolicyError};
use crate::account::{account_component_package, metadata_without_slots};
use crate::procedure_root;

account_component_package!(
    POLICY_MANAGER_PACKAGE,
    "miden-standards-faucets-policies-policy-manager.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`TokenPolicyManager::NAME`], which mirrors the standards-side MASM module path.
const POLICY_MANAGER_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::policy_manager";

procedure_root!(
    POLICY_MANAGER_SET_MINT_POLICY,
    POLICY_MANAGER_LIBRARY_PATH,
    TokenPolicyManager::SET_MINT_POLICY_PROC_NAME,
    TokenPolicyManager::code()
);

procedure_root!(
    POLICY_MANAGER_SET_BURN_POLICY,
    POLICY_MANAGER_LIBRARY_PATH,
    TokenPolicyManager::SET_BURN_POLICY_PROC_NAME,
    TokenPolicyManager::code()
);

procedure_root!(
    POLICY_MANAGER_SET_SEND_POLICY_ROOTS_COMMITMENT,
    POLICY_MANAGER_LIBRARY_PATH,
    TokenPolicyManager::SET_SEND_POLICY_ROOTS_COMMITMENT_PROC_NAME,
    TokenPolicyManager::code()
);

procedure_root!(
    POLICY_MANAGER_SET_RECEIVE_POLICY_ROOTS_COMMITMENT,
    POLICY_MANAGER_LIBRARY_PATH,
    TokenPolicyManager::SET_RECEIVE_POLICY_ROOTS_COMMITMENT_PROC_NAME,
    TokenPolicyManager::code()
);

procedure_root!(
    POLICY_MANAGER_INVOKE_SEND_POLICY,
    POLICY_MANAGER_LIBRARY_PATH,
    TokenPolicyManager::INVOKE_SEND_POLICY_PROC_NAME,
    TokenPolicyManager::code()
);

procedure_root!(
    POLICY_MANAGER_INVOKE_RECEIVE_POLICY,
    POLICY_MANAGER_LIBRARY_PATH,
    TokenPolicyManager::INVOKE_RECEIVE_POLICY_PROC_NAME,
    TokenPolicyManager::code()
);

// STORAGE SLOT NAMES
// ================================================================================================

static ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::active_mint_policy_proc_root",
    )
    .expect("storage slot name should be valid")
});

static ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::active_burn_policy_proc_root",
    )
    .expect("storage slot name should be valid")
});

static ACTIVE_SEND_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::active_send_policy_proc_roots",
    )
    .expect("storage slot name should be valid")
});

static ACTIVE_RECEIVE_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> =
    LazyLock::new(|| {
        StorageSlotName::new(
            "miden::standards::faucets::policies::policy_manager::active_receive_policy_proc_roots",
        )
        .expect("storage slot name should be valid")
    });

static NUM_ACTIVE_TRANSFER_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(
    || {
        StorageSlotName::new(
            "miden::standards::faucets::policies::policy_manager::num_active_transfer_policy_proc_roots",
        )
        .expect("storage slot name should be valid")
    },
);

static ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::allowed_mint_policy_proc_roots",
    )
    .expect("storage slot name should be valid")
});

static ALLOWED_BURN_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::allowed_burn_policy_proc_roots",
    )
    .expect("storage slot name should be valid")
});

static ALLOWED_SEND_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::allowed_send_policy_proc_roots",
    )
    .expect("storage slot name should be valid")
});

static ALLOWED_RECEIVE_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> =
    LazyLock::new(|| {
        StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::allowed_receive_policy_proc_roots",
    )
    .expect("storage slot name should be valid")
    });

// POLICY KIND
// ================================================================================================

/// Identifies which faucet operation a policy gates.
///
/// Used internally by [`TokenPolicyManager`] to record which `allowed_*_policies` storage maps a
/// policy procedure root should be registered in. The same procedure root may belong to more
/// than one kind (for example a custom procedure registered as both the send and the receive
/// policy, which then must not read its inputs, since the two kinds take different inputs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PolicyKind {
    Mint,
    Burn,
    Send,
    Receive,
}

// TOKEN POLICY MANAGER
// ================================================================================================

/// An [`AccountComponent`] that owns the policy-manager storage slots and the manager
/// procedures for the four policy kinds (mint, burn, send, receive).
///
/// The component exposes setters and getters for each kind, `execute_*_policy` for mint / burn, and
/// `invoke_send_policy` / `invoke_receive_policy` for the transfer kinds. The transfer wrappers
/// double as the protocol-level `on_before_note_sealed` / `on_before_asset_added_to_account` asset
/// callbacks: the kernel `dyncall`s the wrapper, which limits the transaction's expiration to the
/// standards default delta, applies the account-wide pause check and then dispatches to the active
/// send / receive policies, all of which must accept the transfer.
/// Authorization for switching the active policies is delegated to the account-wide
/// [`Authority`][crate::account::access::Authority] component, which must be installed alongside
/// this manager.
///
/// Construct via [`Self::builder`]. The builder requires the active mint and burn policy
/// ([`TokenPolicyManagerBuilder::active_mint_policy`] /
/// [`TokenPolicyManagerBuilder::active_burn_policy`]). Send / receive policies are optional and may
/// be registered as active ([`TokenPolicyManagerBuilder::active_send_policy`] /
/// [`TokenPolicyManagerBuilder::active_receive_policy`]) and/or as reserved alternatives
/// ([`TokenPolicyManagerBuilder::allowed_send_policy`] /
/// [`TokenPolicyManagerBuilder::allowed_receive_policy`]) for runtime switching. The
/// protocol-reserved asset-callback slots (see the storage layout below) are installed whenever at
/// least one send or receive policy of either kind is registered - active or reserved - even when
/// only reserved policies exist and no policy is active yet (see [`Self::has_transfer_policy`]).
/// Installing those slots is what makes the faucet's account ID carry
/// [`AssetCallbackFlag::Enabled`][miden_protocol::account::AssetCallbackFlag::Enabled]. Because
/// the flag is an immutable property of the account ID, it applies for the faucet's entire
/// lifetime, so promoting a reserved policy later via `set_send_policy_roots_commitment` /
/// `set_receive_policy_roots_commitment` enforces it against the whole circulating supply rather
/// than only assets minted after the switch. The callbacks also limit every transfer's expiration
/// and apply the pause check before reading the active roots, so transfers anchored to a block
/// before the activation are bounded too. A faucet created as
/// [`AccountType::Private`][miden_protocol::account::AccountType::Private] publishes only its
/// commitment, so its holders have to obtain the state each of their transactions needs out of
/// band. The account type is immutable, so that is settled at creation.
///
/// The slots are omitted only when no send or receive policy of any kind is registered, in which
/// case the faucet's account ID is created with
/// [`AssetCallbackFlag::Disabled`][miden_protocol::account::AssetCallbackFlag::Disabled], no
/// transfer policy can ever be enforced for that faucet, and the protocol-reserved slots are left
/// free for a separate callback component. Such a faucet also avoids the cost the flag imposes:
/// with callbacks enabled, the tx kernel starts a foreign context against the faucet on every
/// movement of its assets, so every holder's transaction must supply the faucet's account state. A
/// faucet that wants to keep the option of a transfer policy open without registering one yet can
/// enable the flag explicitly with
/// [`AccountBuilder::enable_asset_callbacks`][miden_protocol::account::AccountBuilder::enable_asset_callbacks].
///
/// ## Storage layout
///
/// - [`Self::active_mint_policy_slot`]: procedure root of the active mint policy.
/// - [`Self::active_burn_policy_slot`]: procedure root of the active burn policy.
/// - [`Self::active_send_policies_slot`]: list of the procedure roots of the active send policies.
/// - [`Self::active_receive_policies_slot`]: list of the procedure roots of the active receive
///   policies.
/// - [`Self::num_active_transfer_policies_slot`]: lengths of the active send and receive lists. A
///   length of zero means that no policy of that kind is active and the transfer is accepted.
/// - [`Self::allowed_mint_policies_slot`]: map of allowed mint policy roots.
/// - [`Self::allowed_burn_policies_slot`]: map of allowed burn policy roots.
/// - [`Self::allowed_send_policies_slot`]: map of allowed send policy roots.
/// - [`Self::allowed_receive_policies_slot`]: map of allowed receive policy roots.
/// - Asset-callback storage slots (registered via [`AssetCallbacks`]) hold the fixed
///   `invoke_send_policy` / `invoke_receive_policy` wrapper roots, so the kernel dispatches to the
///   wrapper (which then dispatches to the active policies in the slots above). They are installed
///   only when at least one transfer policy is configured, which is also what makes the faucet's
///   account ID carry
///   [`AssetCallbackFlag::Enabled`][miden_protocol::account::AssetCallbackFlag::Enabled], and
///   future policy switches via `set_send_policy_roots_commitment` /
///   `set_receive_policy_roots_commitment` apply to the entire circulating supply rather than only
///   to assets minted after the switch.
#[derive(Debug, Clone)]
pub struct TokenPolicyManager {
    active_mint_policy_root: AccountProcedureRoot,
    active_burn_policy_root: AccountProcedureRoot,
    active_send_policy_roots: Vec<AccountProcedureRoot>,
    active_receive_policy_roots: Vec<AccountProcedureRoot>,
    /// The kinds under which each policy procedure root is registered.
    policies: BTreeMap<AccountProcedureRoot, BTreeSet<PolicyKind>>,
    /// The deduplicated companion components of all registered policies.
    components: Vec<AccountComponent>,
}

#[bon::bon]
impl TokenPolicyManager {
    /// Builder constructor for [`TokenPolicyManager`].
    ///
    /// The active mint and burn policies are required. Any number of active send and receive
    /// policies can be added, up to the limit below. Each `allowed_*_policy` setter registers an
    /// additional reserved alternative for runtime switching via the matching setter procedure.
    ///
    /// # Errors
    ///
    /// Returns an error if, for either transfer policy kind:
    /// - the active policies contain the same procedure root more than once.
    /// - the active policies contain more than [`Self::MAX_NUM_ACTIVE_TRANSFER_POLICIES`] procedure
    ///   roots.
    #[builder]
    pub fn new(
        #[builder(field)] allowed_mint_policies: BTreeMap<AccountProcedureRoot, MintPolicy>,
        #[builder(field)] allowed_burn_policies: BTreeMap<AccountProcedureRoot, BurnPolicy>,
        #[builder(field)] active_send_policies: Vec<SendPolicy>,
        #[builder(field)] active_receive_policies: Vec<ReceivePolicy>,
        #[builder(field)] allowed_send_policies: Vec<SendPolicy>,
        #[builder(field)] allowed_receive_policies: Vec<ReceivePolicy>,
        active_mint_policy: MintPolicy,
        active_burn_policy: BurnPolicy,
    ) -> Result<Self, TransferPolicyError> {
        let active_mint_policy_root = active_mint_policy.root();
        let active_burn_policy_root = active_burn_policy.root();
        let active_send_policy_roots =
            collect_active_transfer_roots(active_send_policies.iter().map(SendPolicy::root))?;
        let active_receive_policy_roots =
            collect_active_transfer_roots(active_receive_policies.iter().map(ReceivePolicy::root))?;

        let mut manager = Self {
            active_mint_policy_root,
            active_burn_policy_root,
            active_send_policy_roots,
            active_receive_policy_roots,
            policies: BTreeMap::new(),
            components: Vec::new(),
        };

        for policy in iter::once(active_mint_policy).chain(allowed_mint_policies.into_values()) {
            manager.register_policy(PolicyKind::Mint, policy.root(), policy);
        }
        for policy in iter::once(active_burn_policy).chain(allowed_burn_policies.into_values()) {
            manager.register_policy(PolicyKind::Burn, policy.root(), policy);
        }
        for policy in active_send_policies.into_iter().chain(allowed_send_policies) {
            manager.register_policy(PolicyKind::Send, policy.root(), policy);
        }
        for policy in active_receive_policies.into_iter().chain(allowed_receive_policies) {
            manager.register_policy(PolicyKind::Receive, policy.root(), policy);
        }

        Ok(manager)
    }
}

impl<S: token_policy_manager_builder::State> TokenPolicyManagerBuilder<S> {
    /// Registers a reserved mint policy in the `allowed_mint_policy_proc_roots` map. May be
    /// activated at runtime via `set_mint_policy`. Allowed entries are deduplicated by
    /// procedure root.
    pub fn allowed_mint_policy(mut self, policy: MintPolicy) -> Self {
        self.allowed_mint_policies.insert(policy.root(), policy);
        self
    }

    /// Registers a reserved burn policy in the `allowed_burn_policy_proc_roots` map. May be
    /// activated at runtime via `set_burn_policy`. Allowed entries are deduplicated by
    /// procedure root.
    pub fn allowed_burn_policy(mut self, policy: BurnPolicy) -> Self {
        self.allowed_burn_policies.insert(policy.root(), policy);
        self
    }

    /// Adds an active send policy. A transfer must be accepted by all active send policies, which
    /// are invoked in the order in which they were added.
    pub fn active_send_policy(mut self, policy: SendPolicy) -> Self {
        self.active_send_policies.push(policy);
        self
    }

    /// Adds an active receive policy. A transfer must be accepted by all active receive policies,
    /// which are invoked in the order in which they were added.
    pub fn active_receive_policy(mut self, policy: ReceivePolicy) -> Self {
        self.active_receive_policies.push(policy);
        self
    }

    /// Registers a reserved send policy in the `allowed_send_policy_proc_roots` map.
    /// Any combination of the registered roots may be activated at runtime via
    /// `set_send_policy_roots_commitment`.
    pub fn allowed_send_policy(mut self, policy: SendPolicy) -> Self {
        self.allowed_send_policies.push(policy);
        self
    }

    /// Registers a reserved receive policy in the `allowed_receive_policy_proc_roots`
    /// map. Any combination of the registered roots may be activated at runtime via
    /// `set_receive_policy_roots_commitment`.
    pub fn allowed_receive_policy(mut self, policy: ReceivePolicy) -> Self {
        self.allowed_receive_policies.push(policy);
        self
    }
}

impl TokenPolicyManager {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component (used in metadata).
    pub const NAME: &'static str = "miden::standards::faucets::policies::policy_manager";

    /// Component description used in [`AccountComponentMetadata`].
    pub const DESCRIPTION: &'static str = "Token policy manager for fungible faucets";

    /// The maximum number of active policies per transfer policy kind. Keep in sync with
    /// `policy_manager.masm`.
    pub const MAX_NUM_ACTIVE_TRANSFER_POLICIES: usize = 16;

    const SET_MINT_POLICY_PROC_NAME: &'static str = "set_mint_policy";
    const SET_BURN_POLICY_PROC_NAME: &'static str = "set_burn_policy";
    const SET_SEND_POLICY_ROOTS_COMMITMENT_PROC_NAME: &'static str =
        "set_send_policy_roots_commitment";
    const SET_RECEIVE_POLICY_ROOTS_COMMITMENT_PROC_NAME: &'static str =
        "set_receive_policy_roots_commitment";
    const INVOKE_SEND_POLICY_PROC_NAME: &'static str = "invoke_send_policy";
    const INVOKE_RECEIVE_POLICY_PROC_NAME: &'static str = "invoke_receive_policy";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the active mint policy procedure root.
    pub fn active_mint_policy(&self) -> AccountProcedureRoot {
        self.active_mint_policy_root
    }

    /// Returns the active burn policy procedure root.
    pub fn active_burn_policy(&self) -> AccountProcedureRoot {
        self.active_burn_policy_root
    }

    /// Returns the active send policy procedure roots in invocation order. The list is empty if no
    /// send policy is active.
    pub fn active_send_policies(&self) -> &[AccountProcedureRoot] {
        &self.active_send_policy_roots
    }

    /// Returns the active receive policy procedure roots in invocation order. The list is empty if
    /// no receive policy is active.
    pub fn active_receive_policies(&self) -> &[AccountProcedureRoot] {
        &self.active_receive_policy_roots
    }

    /// Returns all allowed mint policy procedure roots (active + reserved).
    pub fn allowed_mint_policies(&self) -> Vec<AccountProcedureRoot> {
        self.roots_of_kind(PolicyKind::Mint)
    }

    /// Returns all allowed burn policy procedure roots (active + reserved).
    pub fn allowed_burn_policies(&self) -> Vec<AccountProcedureRoot> {
        self.roots_of_kind(PolicyKind::Burn)
    }

    /// Returns all allowed send policy procedure roots (active + reserved).
    pub fn allowed_send_policies(&self) -> Vec<AccountProcedureRoot> {
        self.roots_of_kind(PolicyKind::Send)
    }

    /// Returns all allowed receive policy procedure roots (active + reserved).
    pub fn allowed_receive_policies(&self) -> Vec<AccountProcedureRoot> {
        self.roots_of_kind(PolicyKind::Receive)
    }

    fn roots_of_kind(&self, kind: PolicyKind) -> Vec<AccountProcedureRoot> {
        self.policies
            .iter()
            .filter(|(_, kinds)| kinds.contains(&kind))
            .map(|(root, _)| *root)
            .collect()
    }

    /// Returns the procedure root of the `set_mint_policy` account procedure.
    pub fn set_mint_policy_root() -> AccountProcedureRoot {
        *POLICY_MANAGER_SET_MINT_POLICY
    }

    /// Returns the procedure root of the `set_burn_policy` account procedure.
    pub fn set_burn_policy_root() -> AccountProcedureRoot {
        *POLICY_MANAGER_SET_BURN_POLICY
    }

    /// Returns the procedure root of the `set_send_policy_roots_commitment` account procedure.
    pub fn set_send_policy_roots_commitment_root() -> AccountProcedureRoot {
        *POLICY_MANAGER_SET_SEND_POLICY_ROOTS_COMMITMENT
    }

    /// Returns the procedure root of the `set_receive_policy_roots_commitment` account procedure.
    pub fn set_receive_policy_roots_commitment_root() -> AccountProcedureRoot {
        *POLICY_MANAGER_SET_RECEIVE_POLICY_ROOTS_COMMITMENT
    }

    /// Returns the [`StorageSlotName`] where the active mint policy procedure root is stored.
    pub fn active_mint_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the active burn policy procedure root is stored.
    pub fn active_burn_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the active send policy procedure roots are stored.
    pub fn active_send_policies_slot() -> &'static StorageSlotName {
        &ACTIVE_SEND_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the active receive policy procedure roots are stored.
    pub fn active_receive_policies_slot() -> &'static StorageSlotName {
        &ACTIVE_RECEIVE_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the numbers of active send and receive policy
    /// procedure roots are stored.
    pub fn num_active_transfer_policies_slot() -> &'static StorageSlotName {
        &NUM_ACTIVE_TRANSFER_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the procedure root of the `invoke_send_policy` wrapper stored in the
    /// `on_before_note_sealed` callback slot.
    pub fn invoke_send_policy_root() -> AccountProcedureRoot {
        *POLICY_MANAGER_INVOKE_SEND_POLICY
    }

    /// Returns the procedure root of the `invoke_receive_policy` wrapper stored in the
    /// `on_before_asset_added_to_account` callback slot.
    pub fn invoke_receive_policy_root() -> AccountProcedureRoot {
        *POLICY_MANAGER_INVOKE_RECEIVE_POLICY
    }

    /// Returns the [`StorageSlotName`] where allowed mint policy roots are stored.
    pub fn allowed_mint_policies_slot() -> &'static StorageSlotName {
        &ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where allowed burn policy roots are stored.
    pub fn allowed_burn_policies_slot() -> &'static StorageSlotName {
        &ALLOWED_BURN_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where allowed send policy roots are stored.
    pub fn allowed_send_policies_slot() -> &'static StorageSlotName {
        &ALLOWED_SEND_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where allowed receive policy roots are stored.
    pub fn allowed_receive_policies_slot() -> &'static StorageSlotName {
        &ALLOWED_RECEIVE_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &POLICY_MANAGER_PACKAGE.code
    }

    /// Returns the [`AccountComponentMetadata`] for this configuration.
    ///
    /// The returned schema might not be the exact schema defined in the component manifest: the
    /// asset-callback slots are only installed when at least one send or receive policy is
    /// configured, and when installed they default to the `invoke_*_policy` wrapper roots, which
    /// are only known once the component code is compiled and so cannot be declared in the
    /// manifest.
    pub fn component_metadata(&self) -> AccountComponentMetadata {
        let metadata = POLICY_MANAGER_PACKAGE.metadata.clone();
        if !self.has_transfer_policy() {
            return metadata_without_slots(
                metadata,
                &[
                    AssetCallbacks::on_before_asset_added_to_account_slot(),
                    AssetCallbacks::on_before_note_sealed_slot(),
                ],
            );
        }

        let callback_defaults = [
            (
                AssetCallbacks::on_before_asset_added_to_account_slot(),
                Self::invoke_receive_policy_root(),
            ),
            (AssetCallbacks::on_before_note_sealed_slot(), Self::invoke_send_policy_root()),
        ];
        let slots = metadata.storage_schema().iter().map(|(slot_name, schema)| {
            let schema = match callback_defaults.iter().find(|(name, _)| *name == slot_name) {
                Some((_, root)) => {
                    let description = match schema {
                        StorageSlotSchema::Value(value) => value.description().cloned(),
                        StorageSlotSchema::Map(_) => None,
                    };
                    StorageSlotSchema::Value(ValueSlotSchema::new(
                        description,
                        WordSchema::new_simple_with_default(
                            SchemaType::native_word(),
                            root.as_word(),
                        ),
                    ))
                },
                None => schema.clone(),
            };
            (slot_name.clone(), schema)
        });
        let storage_schema =
            StorageSchema::new(slots).expect("adding defaults keeps a valid schema valid");

        metadata.with_storage_schema(storage_schema)
    }

    /// Returns `true` if at least one send or receive policy is configured, in which case the
    /// faucet registers the protocol callback slots and therefore its account ID is created with
    /// [`AssetCallbackFlag::Enabled`](miden_protocol::account::AssetCallbackFlag::Enabled).
    pub fn has_transfer_policy(&self) -> bool {
        self.policies
            .values()
            .any(|kinds| kinds.contains(&PolicyKind::Send) || kinds.contains(&PolicyKind::Receive))
    }

    fn manager_storage_slots(&self) -> Vec<StorageSlot> {
        let mut slots = vec![
            StorageSlot::with_value(
                ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.active_mint_policy_root.as_word(),
            ),
            StorageSlot::with_value(
                ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.active_burn_policy_root.as_word(),
            ),
            StorageSlot::with_map(
                ACTIVE_SEND_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                build_active_map(&self.active_send_policy_roots),
            ),
            StorageSlot::with_map(
                ACTIVE_RECEIVE_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                build_active_map(&self.active_receive_policy_roots),
            ),
            StorageSlot::with_value(
                NUM_ACTIVE_TRANSFER_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                num_active_transfer_policies(
                    &self.active_send_policy_roots,
                    &self.active_receive_policy_roots,
                ),
            ),
            StorageSlot::with_map(
                ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                self.build_allowed_map(PolicyKind::Mint),
            ),
            StorageSlot::with_map(
                ALLOWED_BURN_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                self.build_allowed_map(PolicyKind::Burn),
            ),
            StorageSlot::with_map(
                ALLOWED_SEND_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                self.build_allowed_map(PolicyKind::Send),
            ),
            StorageSlot::with_map(
                ALLOWED_RECEIVE_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                self.build_allowed_map(PolicyKind::Receive),
            ),
        ];

        // Register the protocol-reserved asset-callback slots only when at least one transfer
        // policy is configured, leaving them free for a separate callback component otherwise. The
        // slots hold the fixed `invoke_*_policy` procedure roots, which the kernel calls
        // dynamically: the wrapper limits the expiration, applies the pause check and then invokes
        // the active policies from the slots above, accepting the transfer when there are none.
        // This indirection lets `set_send_policy_roots_commitment` /
        // `set_receive_policy_roots_commitment` switch the active policies for the entire
        // circulating supply without touching the callback slots.
        //
        // The slots are what make the account ID carry an enabled asset callback flag, and that
        // flag is immutable, so a faucet created without a transfer policy can never enforce one
        // later. That is deliberate: an enabled flag makes the tx kernel start a foreign context
        // against the faucet on every movement of its assets, so every holder's transaction has to
        // supply the faucet's account state. A faucet that wants to keep the option open without
        // registering a policy yet can enable the flag explicitly with
        // `AccountBuilder::enable_asset_callbacks`.
        if self.has_transfer_policy() {
            let callback_slots = AssetCallbacks::new()
                .on_before_asset_added_to_account(Self::invoke_receive_policy_root().as_word())
                .on_before_note_sealed(Self::invoke_send_policy_root().as_word())
                .into_storage_slots();
            slots.extend(callback_slots);
        }
        slots
    }

    /// Builds the `allowed_*_policies` storage map for the given kind by filtering the
    /// unified `policies` map. Each entry maps the policy procedure root to a non-zero flag,
    /// so the runtime validation of the setters can confirm the root is allowed before activating
    /// it.
    fn build_allowed_map(&self, kind: PolicyKind) -> StorageMap {
        let allowed_flag = Word::from([1u32, 0, 0, 0]);
        let entries: Vec<_> = self
            .policies
            .iter()
            .filter(|(_, kinds)| kinds.contains(&kind))
            .map(|(root, _)| (StorageMapKey::new(root.as_word()), allowed_flag))
            .collect();
        StorageMap::with_entries(entries).expect("allowed policy roots should have unique keys")
    }

    /// Registers the policy's root under the given kind and adds its companion components.
    ///
    /// A companion component that was already added with the same code and storage is not added
    /// again, which installs a component once when it exports the roots of several policies (e.g.
    /// the send and receive procedures of a transfer policy). A component with the same code but
    /// different storage is kept, so the conflict fails the account build.
    fn register_policy(
        &mut self,
        kind: PolicyKind,
        root: AccountProcedureRoot,
        components: impl IntoIterator<Item = AccountComponent>,
    ) {
        self.policies.entry(root).or_default().insert(kind);

        for component in components {
            let is_installed = self.components.iter().any(|installed| {
                installed.component_code() == component.component_code()
                    && installed.storage_slots() == component.storage_slots()
            });
            if !is_installed {
                self.components.push(component);
            }
        }
    }

    fn to_manager_component(&self) -> AccountComponent {
        let storage_slots = self.manager_storage_slots();
        AccountComponent::new(
            Self::code().clone(),
            storage_slots,
            self.component_metadata(),
        )
        .expect(
            "token policy manager component should satisfy the requirements of a valid account component",
        )
    }
}

/// Collects the roots of the active transfer policies of one kind.
///
/// # Errors
///
/// Returns an error if:
/// - the roots contain duplicates.
/// - there are more than [`TokenPolicyManager::MAX_NUM_ACTIVE_TRANSFER_POLICIES`] roots.
fn collect_active_transfer_roots(
    policy_roots: impl Iterator<Item = AccountProcedureRoot>,
) -> Result<Vec<AccountProcedureRoot>, TransferPolicyError> {
    let mut roots = Vec::new();
    for root in policy_roots {
        if roots.contains(&root) {
            return Err(TransferPolicyError::DuplicateRoot(root));
        }
        roots.push(root);
    }

    if roots.len() > TokenPolicyManager::MAX_NUM_ACTIVE_TRANSFER_POLICIES {
        return Err(TransferPolicyError::TooManyRoots(roots.len()));
    }

    Ok(roots)
}

/// Builds the storage map holding the active policy roots, keyed by their position in the list as
/// expected by the MASM `array` module.
fn build_active_map(roots: &[AccountProcedureRoot]) -> StorageMap {
    let entries: Vec<_> = (0u32..)
        .zip(roots)
        .map(|(index, root)| (StorageMapKey::from_array([0, 0, 0, index]), root.as_word()))
        .collect();
    StorageMap::with_entries(entries).expect("active policy root indices should be unique")
}

/// Builds the storage value holding the numbers of active send and receive policy roots.
fn num_active_transfer_policies(
    send_roots: &[AccountProcedureRoot],
    receive_roots: &[AccountProcedureRoot],
) -> Word {
    let num_roots = |roots: &[AccountProcedureRoot]| {
        u32::try_from(roots.len()).expect("number of policy roots should fit into a u32")
    };
    Word::from([num_roots(send_roots), num_roots(receive_roots), 0, 0])
}

impl IntoIterator for TokenPolicyManager {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s implementing this token policy configuration: the
    /// manager itself first, then the companion components contributed by every registered
    /// policy. Each companion component is yielded once, even when several registered policy
    /// roots belong to it (e.g. the send and receive procedures of a transfer policy).
    fn into_iter(self) -> Self::IntoIter {
        let manager_component = self.to_manager_component();
        let mut components = vec![manager_component];
        components.extend(self.components);
        components.into_iter()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::component::{InitStorageData, StorageValueName};
    use miden_protocol::account::{AccountBuilder, AccountId, StorageSlotContent};
    use miden_protocol::asset::AssetCallbacks;
    use miden_protocol::errors::AccountError;
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;

    use super::*;
    use crate::account::auth::NoAuth;
    use crate::account::policies::{
        BasicBlocklist,
        BlocklistStorage,
        BurnAllowAll,
        MintAllowAll,
        TransferAllowAll,
    };

    /// Returns the manager component's storage slot for the given slot name, or `None` if the
    /// component does not register a slot with that name.
    fn find_slot<'a>(
        component: &'a AccountComponent,
        slot_name: &StorageSlotName,
    ) -> Option<&'a StorageSlot> {
        component.storage_slots().iter().find(|slot| slot.name() == slot_name)
    }

    /// Asserts that the component stores the given lists of active send and receive policy roots.
    fn assert_active_transfer_policies(
        component: &AccountComponent,
        send_roots: &[AccountProcedureRoot],
        receive_roots: &[AccountProcedureRoot],
    ) {
        for (slot_name, roots) in [
            (TokenPolicyManager::active_send_policies_slot(), send_roots),
            (TokenPolicyManager::active_receive_policies_slot(), receive_roots),
        ] {
            let slot = find_slot(component, slot_name).expect("active policies slot should exist");
            assert_matches!(slot.content(), StorageSlotContent::Map(map) => {
                assert_eq!(map.num_entries(), roots.len());
                for (index, root) in (0u32..).zip(roots) {
                    let key = StorageMapKey::from_array([0, 0, 0, index]);
                    assert_eq!(map.get(&key), root.as_word());
                }
            });
        }

        let num_roots_slot =
            find_slot(component, TokenPolicyManager::num_active_transfer_policies_slot())
                .expect("number of active policies slot should exist");
        assert_eq!(
            num_roots_slot.value(),
            Word::from([send_roots.len() as u32, receive_roots.len() as u32, 0, 0])
        );
    }

    /// Asserts the component's metadata schema declares exactly the slots the component installs.
    fn assert_schema_matches_storage(component: &AccountComponent) {
        let schema: BTreeSet<_> = component
            .metadata()
            .storage_schema()
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        let storage: BTreeSet<_> =
            component.storage_slots().iter().map(|slot| slot.name().clone()).collect();
        assert_eq!(schema, storage);
    }

    /// Checks that a manager configured with a transfer policy for both kinds registers the
    /// protocol-reserved asset-callback slots populated with the fixed `invoke_*_policy` wrapper
    /// roots (the active `TransferAllowAll` roots live in the active-policy slots instead).
    #[test]
    fn allow_all_transfer_policy_registers_protocol_callback_slots() -> anyhow::Result<()> {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(SendPolicy::allow_all())
            .active_receive_policy(ReceivePolicy::allow_all())
            .build()?;

        let manager_component = manager.to_manager_component();

        let on_account_slot =
            find_slot(&manager_component, AssetCallbacks::on_before_asset_added_to_account_slot())
                .expect(
                    "AllowAll receive policy must register the on_before_asset_added_to_account \
             protocol callback slot",
                );
        let on_note_slot =
            find_slot(&manager_component, AssetCallbacks::on_before_note_sealed_slot()).expect(
                "AllowAll send policy must register the on_before_note_sealed protocol \
             callback slot",
            );

        // The callback slots must hold the wrapper roots, not the active policy root.
        assert_eq!(
            on_account_slot.value(),
            TokenPolicyManager::invoke_receive_policy_root().as_word()
        );
        assert_eq!(on_note_slot.value(), TokenPolicyManager::invoke_send_policy_root().as_word());

        // The active TransferAllowAll roots live in the dedicated active-policy slots.
        assert_active_transfer_policies(
            &manager_component,
            &[TransferAllowAll::send_root()],
            &[TransferAllowAll::receive_root()],
        );

        assert_schema_matches_storage(&manager_component);

        Ok(())
    }

    /// Checks that a manager whose send / receive policies are registered only as reserved
    /// alternatives (no active transfer policy yet) still installs the protocol-reserved callback
    /// slots with the fixed `invoke_*_policy` wrapper roots, so `has_transfer_policy` is true from
    /// creation.
    #[test]
    fn reserved_only_transfer_policy_registers_protocol_callback_slots() -> anyhow::Result<()> {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .allowed_send_policy(SendPolicy::allow_all())
            .allowed_receive_policy(ReceivePolicy::allow_all())
            .build()?;

        let manager_component = manager.to_manager_component();

        // Both callback slots are installed even though no transfer policy is active yet.
        let on_account_slot =
            find_slot(&manager_component, AssetCallbacks::on_before_asset_added_to_account_slot())
                .expect(
                    "reserved receive policy must register the on_before_asset_added_to_account \
                     protocol callback slot",
                );
        let on_note_slot =
            find_slot(&manager_component, AssetCallbacks::on_before_note_sealed_slot()).expect(
                "reserved send policy must register the on_before_note_sealed protocol \
                     callback slot",
            );

        // They hold the fixed wrapper roots, identical to the active-policy case.
        assert_eq!(
            on_account_slot.value(),
            TokenPolicyManager::invoke_receive_policy_root().as_word()
        );
        assert_eq!(on_note_slot.value(), TokenPolicyManager::invoke_send_policy_root().as_word());

        // No policy has been activated yet, so the active-policy lists are still empty.
        assert_active_transfer_policies(&manager_component, &[], &[]);

        // The reserved roots are recorded in the allowed-roots maps so they can be promoted later.
        assert!(manager.allowed_send_policies().contains(&TransferAllowAll::send_root()));
        assert!(manager.allowed_receive_policies().contains(&TransferAllowAll::receive_root()));

        assert_schema_matches_storage(&manager_component);

        Ok(())
    }

    /// A manager configured without send / receive policies must NOT register the protocol
    /// callback slots, leaving them free for a separate callback component.
    #[test]
    fn manager_without_transfer_policies_omits_protocol_callback_slots() -> anyhow::Result<()> {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .build()?;

        let manager_component = manager.to_manager_component();

        assert!(
            find_slot(&manager_component, AssetCallbacks::on_before_asset_added_to_account_slot(),)
                .is_none(),
            "without a receive policy, the manager must leave the on_before_asset_added_to_account \
             slot to a separate component",
        );
        assert!(
            find_slot(&manager_component, AssetCallbacks::on_before_note_sealed_slot()).is_none(),
            "without a send policy, the manager must leave the on_before_note_sealed slot \
             to a separate component",
        );

        assert_schema_matches_storage(&manager_component);

        Ok(())
    }

    /// The schema-driven construction path must produce the same storage layout as a manager
    /// configured with transfer policies, including the two protocol-reserved callback slots.
    #[test]
    fn storage_schema_covers_every_slot_of_a_transfer_policy_manager() -> anyhow::Result<()> {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(SendPolicy::allow_all())
            .active_receive_policy(ReceivePolicy::allow_all())
            .build()?;

        let manager_component = manager.to_manager_component();

        // The active mint and burn policy roots and the numbers of active transfer policies are the
        // only values the schema requires; everything else either defaults (the callback roots) or
        // starts empty (the maps).
        let mut init_storage_data = InitStorageData::default();
        for (slot_name, root) in [
            (TokenPolicyManager::active_mint_policy_slot(), MintPolicy::allow_all().root()),
            (TokenPolicyManager::active_burn_policy_slot(), BurnPolicy::allow_all().root()),
        ] {
            init_storage_data
                .set_value(StorageValueName::from_slot_name(slot_name), root.as_word())
                .expect("active policy root should be a valid init value");
        }
        for field in ["num_send_roots", "num_receive_roots"] {
            let value_name = StorageValueName::from_slot_name_with_suffix(
                TokenPolicyManager::num_active_transfer_policies_slot(),
                field,
            )
            .expect("field name should be valid");
            init_storage_data
                .set_value(value_name, 0u32)
                .expect("number of active policies should be a valid init value");
        }

        let schema_slots = manager
            .component_metadata()
            .storage_schema()
            .build_storage_slots(&init_storage_data)
            .expect("schema should build the manager's storage slots");

        let schema_slot_names: BTreeSet<_> =
            schema_slots.iter().map(|slot| slot.name().clone()).collect();
        let component_slot_names: BTreeSet<_> = manager_component
            .storage_slots()
            .iter()
            .map(|slot| slot.name().clone())
            .collect();
        assert_eq!(
            schema_slot_names, component_slot_names,
            "the storage schema must declare exactly the slots the component installs",
        );

        // The schema-built callback slots must hold the wrapper roots the kernel dispatches to, and
        // the active-policy slots the roots taken from the initialization data.
        let find_schema_slot = |slot_name: &StorageSlotName| {
            schema_slots
                .iter()
                .find(|slot| slot.name() == slot_name)
                .expect("schema should build this slot")
                .value()
        };
        assert_eq!(
            find_schema_slot(AssetCallbacks::on_before_asset_added_to_account_slot()),
            TokenPolicyManager::invoke_receive_policy_root().as_word(),
        );
        assert_eq!(
            find_schema_slot(AssetCallbacks::on_before_note_sealed_slot()),
            TokenPolicyManager::invoke_send_policy_root().as_word(),
        );
        assert_eq!(
            find_schema_slot(TokenPolicyManager::active_mint_policy_slot()),
            MintPolicy::allow_all().root().as_word()
        );
        assert_eq!(
            find_schema_slot(TokenPolicyManager::active_burn_policy_slot()),
            BurnPolicy::allow_all().root().as_word()
        );

        Ok(())
    }

    /// Allowed entries registered via the builder land in the `allowed_*_policies` storage map
    /// alongside the active one.
    #[test]
    fn allowed_burn_policy_is_registered_in_allowed_map() -> anyhow::Result<()> {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::owner_only())
            .active_burn_policy(BurnPolicy::owner_only())
            .allowed_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(SendPolicy::allow_all())
            .active_receive_policy(ReceivePolicy::allow_all())
            .build()?;

        let allowed = manager.allowed_burn_policies();
        assert!(allowed.contains(&BurnPolicy::owner_only().root()));
        assert!(allowed.contains(&BurnPolicy::allow_all().root()));

        Ok(())
    }

    /// The send and receive procedures of a list policy belong to one component with one list.
    /// When both policies start from the same list, the component is installed once and the
    /// account builds. When the lists differ, the account build fails on the duplicate list slot,
    /// so neither list is dropped silently.
    #[rstest::rstest]
    #[case::same_initial_list(true)]
    #[case::different_initial_lists(false)]
    fn send_and_receive_blocklists_must_start_from_the_same_list(
        #[case] same_initial_list: bool,
    ) -> anyhow::Result<()> {
        let blocked_account =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let receive_policy = if same_initial_list {
            ReceivePolicy::with_basic_blocklist([blocked_account])
        } else {
            ReceivePolicy::empty_basic_blocklist()
        };
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(SendPolicy::with_basic_blocklist([blocked_account]))
            .active_receive_policy(receive_policy)
            .build()?;

        let account = manager
            .into_iter()
            .fold(
                AccountBuilder::new([1; 32]).with_component(NoAuth),
                AccountBuilder::with_component,
            )
            .build_existing();

        if same_initial_list {
            account.expect("account with one blocklist should build");
        } else {
            assert_matches!(account, Err(AccountError::BuildError(_, Some(source))) => {
                assert_matches!(*source, AccountError::DuplicateStorageSlotName(name) => {
                    assert_eq!(&name, BlocklistStorage::blocked_accounts_slot());
                });
            });
        }

        Ok(())
    }

    /// Components with different code are all installed, even when their names collide.
    #[test]
    fn components_with_different_code_are_installed() -> anyhow::Result<()> {
        let metadata = AccountComponentMetadata::new("tests::same_name");
        let mint_component =
            AccountComponent::new(MintAllowAll::code().clone(), vec![], metadata.clone()).unwrap();
        let burn_component =
            AccountComponent::new(BurnAllowAll::code().clone(), vec![], metadata).unwrap();

        let components: Vec<AccountComponent> = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::custom(MintAllowAll::root(), [mint_component]).unwrap())
            .active_burn_policy(BurnPolicy::custom(BurnAllowAll::root(), [burn_component]).unwrap())
            .build()?
            .into_iter()
            .collect();

        assert!(components.iter().any(|component| component.has_procedure(MintAllowAll::root())));
        assert!(components.iter().any(|component| component.has_procedure(BurnAllowAll::root())));

        Ok(())
    }

    /// The allow-all burn and receive policies have the same procedure root, since both only drop
    /// an asset. The manager registers the root under both kinds and the procedure is installed.
    #[test]
    fn policies_of_different_kinds_can_share_a_root() -> anyhow::Result<()> {
        assert_eq!(BurnAllowAll::root(), TransferAllowAll::receive_root());

        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::owner_only())
            .active_burn_policy(BurnPolicy::allow_all())
            .active_receive_policy(ReceivePolicy::allow_all())
            .build()?;

        assert_eq!(manager.active_burn_policy(), BurnAllowAll::root());
        assert_eq!(manager.active_receive_policies(), &[TransferAllowAll::receive_root()]);
        assert!(manager.allowed_burn_policies().contains(&BurnAllowAll::root()));
        assert!(manager.allowed_receive_policies().contains(&TransferAllowAll::receive_root()));

        let components: Vec<AccountComponent> = manager.into_iter().collect();
        assert!(components.iter().any(|component| component.has_procedure(BurnAllowAll::root())));

        Ok(())
    }

    /// Multiple active policies are stored as lists, each with its own length, every active root is
    /// allowed, and a component shared by several policies is installed once.
    #[test]
    fn active_transfer_policies_are_stored_as_lists() -> anyhow::Result<()> {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(SendPolicy::empty_basic_blocklist())
            .active_send_policy(SendPolicy::allow_all())
            .active_receive_policy(ReceivePolicy::empty_basic_blocklist())
            .build()?;

        let send_roots = [BasicBlocklist::send_root(), TransferAllowAll::send_root()];
        let receive_roots = [BasicBlocklist::receive_root()];
        assert_eq!(manager.active_send_policies(), &send_roots);
        assert_eq!(manager.active_receive_policies(), &receive_roots);
        for root in send_roots {
            assert!(manager.allowed_send_policies().contains(&root));
        }
        assert_eq!(manager.allowed_receive_policies(), &receive_roots);

        let manager_component = manager.to_manager_component();
        assert_active_transfer_policies(&manager_component, &send_roots, &receive_roots);
        assert_schema_matches_storage(&manager_component);

        let num_blocklists = manager
            .into_iter()
            .filter(|component| component.has_procedure(BasicBlocklist::send_root()))
            .count();
        assert_eq!(num_blocklists, 1);

        Ok(())
    }

    /// The builder rejects active policies of one kind that contain the same root more than once.
    #[test]
    fn duplicate_active_transfer_policies_are_rejected() {
        let builder = || {
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
        };

        let result = builder()
            .active_send_policy(SendPolicy::allow_all())
            .active_send_policy(SendPolicy::allow_all())
            .build();
        assert_matches!(result, Err(TransferPolicyError::DuplicateRoot(root)) => {
            assert_eq!(root, TransferAllowAll::send_root());
        });

        let result = builder()
            .active_receive_policy(ReceivePolicy::allow_all())
            .active_receive_policy(ReceivePolicy::allow_all())
            .build();
        assert_matches!(result, Err(TransferPolicyError::DuplicateRoot(root)) => {
            assert_eq!(root, TransferAllowAll::receive_root());
        });
    }

    /// The number of active policies of one kind is limited.
    #[test]
    fn number_of_active_transfer_policies_is_limited() -> anyhow::Result<()> {
        let max_num_roots = TokenPolicyManager::MAX_NUM_ACTIVE_TRANSFER_POLICIES;
        let roots: Vec<_> = (0u32..)
            .take(max_num_roots + 1)
            .map(|index| AccountProcedureRoot::from_raw(Word::from([index, 0, 0, 1])))
            .collect();

        let collected = collect_active_transfer_roots(roots.iter().copied().take(max_num_roots))?;
        assert_eq!(collected, &roots[..max_num_roots]);

        assert_matches!(
            collect_active_transfer_roots(roots.into_iter()),
            Err(TransferPolicyError::TooManyRoots(num_roots)) => {
                assert_eq!(num_roots, max_num_roots + 1);
            }
        );

        Ok(())
    }
}
