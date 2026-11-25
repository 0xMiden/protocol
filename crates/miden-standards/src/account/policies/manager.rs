//! Unified token policy manager.
//!
//! [`TokenPolicyManager`] owns the policy state for fungible faucets. All four kinds use one
//! `active_*_policy_proc_root` slot each plus an `allowed_*_policies` map slot for validating
//! policy-switching at set time. Mint and burn are dispatched by `exec`-invoked
//! `execute_*_policy` wrappers from the faucet flow. Send and receive are dispatched by
//! `invoke_send_policy` / `invoke_receive_policy` wrappers whose roots live in the
//! protocol-reserved callback slots
//! (`miden::protocol::faucet::callback::on_before_asset_added_to_account` and
//! `miden::protocol::faucet::callback::on_before_note_sealed`); the kernel `dyncall`s the wrapper,
//! which limits the transaction's expiration, applies the account-wide pause check and then
//! dispatches to the active policy root.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

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
use super::transfer::{ReceivePolicy, SendPolicy};
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
    POLICY_MANAGER_SET_SEND_POLICY,
    POLICY_MANAGER_LIBRARY_PATH,
    TokenPolicyManager::SET_SEND_POLICY_PROC_NAME,
    TokenPolicyManager::code()
);

procedure_root!(
    POLICY_MANAGER_SET_RECEIVE_POLICY,
    POLICY_MANAGER_LIBRARY_PATH,
    TokenPolicyManager::SET_RECEIVE_POLICY_PROC_NAME,
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

static ACTIVE_SEND_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::active_send_policy_proc_root",
    )
    .expect("storage slot name should be valid")
});

static ACTIVE_RECEIVE_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::active_receive_policy_proc_root",
    )
    .expect("storage slot name should be valid")
});

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
/// Used internally by [`PolicyConfig`] to record which `allowed_*_policies` storage maps a
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

// POLICY CONFIG
// ================================================================================================

/// Internal entry stored inside [`TokenPolicyManager::policies`] for every registered policy
/// procedure root. Captures the companion components the policy needs installed on the
/// account and the set of policy kinds the root is registered under (the same root may serve
/// more than one kind, e.g. a custom procedure registered as both the send and the receive policy).
#[derive(Debug, Clone)]
struct PolicyConfig {
    components: Vec<AccountComponent>,
    kinds: BTreeSet<PolicyKind>,
}

// TOKEN POLICY MANAGER
// ================================================================================================

/// An [`AccountComponent`] that owns the policy-manager storage slots and the manager
/// procedures for the four policy kinds (mint, burn, send, receive).
///
/// The component exposes `set_*_policy` and `get_*_policy` for each kind, `execute_*_policy` for
/// mint / burn, and `invoke_send_policy` / `invoke_receive_policy` for the transfer kinds. The
/// transfer wrappers double as the protocol-level `on_before_note_sealed` /
/// `on_before_asset_added_to_account` asset callbacks: the kernel `dyncall`s the wrapper, which
/// limits the transaction's expiration to the standards default delta, applies the account-wide
/// pause check and then dispatches to the active send / receive policy.
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
/// only reserved policies exist and no active root is set yet (see [`Self::has_transfer_policy`]).
/// Installing those slots is what makes the faucet's account ID carry
/// [`AssetCallbackFlag::Enabled`][miden_protocol::account::AssetCallbackFlag::Enabled]. Because
/// the flag is an immutable property of the account ID, it applies for the faucet's entire
/// lifetime, so promoting a reserved policy later via `set_send_policy` / `set_receive_policy`
/// enforces it against the whole circulating supply rather than only assets minted after the
/// switch. The callbacks also limit every transfer's expiration and apply the pause check before
/// reading the active root, so transfers anchored to a block before the activation are bounded
/// too. A faucet created as
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
/// - [`Self::active_send_policy_slot`]: procedure root of the active send policy.
/// - [`Self::active_receive_policy_slot`]: procedure root of the active receive policy.
/// - [`Self::allowed_mint_policies_slot`]: map of allowed mint policy roots.
/// - [`Self::allowed_burn_policies_slot`]: map of allowed burn policy roots.
/// - [`Self::allowed_send_policies_slot`]: map of allowed send policy roots.
/// - [`Self::allowed_receive_policies_slot`]: map of allowed receive policy roots.
/// - Asset-callback storage slots (registered via [`AssetCallbacks`]) hold the fixed
///   `invoke_send_policy` / `invoke_receive_policy` wrapper roots, so the kernel dispatches to the
///   wrapper (which then dispatches to the active policy in the slot above). They are installed
///   only when at least one transfer policy is configured, which is also what makes the faucet's
///   account ID carry
///   [`AssetCallbackFlag::Enabled`][miden_protocol::account::AssetCallbackFlag::Enabled], and
///   future policy switches via `set_send_policy` / `set_receive_policy` apply to the entire
///   circulating supply rather than only to assets minted after the switch.
#[derive(Debug, Clone)]
pub struct TokenPolicyManager {
    active_mint_policy_root: AccountProcedureRoot,
    active_burn_policy_root: AccountProcedureRoot,
    active_send_policy_root: AccountProcedureRoot,
    active_receive_policy_root: AccountProcedureRoot,
    policies: BTreeMap<AccountProcedureRoot, PolicyConfig>,
}

#[bon::bon]
impl TokenPolicyManager {
    /// Builder constructor for [`TokenPolicyManager`].
    ///
    /// Each `active_*_policy` setter is required and registers the policy as the active one
    /// for its kind. Each `allowed_*_policy` setter registers an additional reserved alternative
    /// for runtime switching via the matching `set_*_policy` procedure.
    #[builder]
    pub fn new(
        #[builder(field)] allowed_mint_policies: BTreeMap<AccountProcedureRoot, MintPolicy>,
        #[builder(field)] allowed_burn_policies: BTreeMap<AccountProcedureRoot, BurnPolicy>,
        #[builder(field)] allowed_send_policies: BTreeMap<AccountProcedureRoot, SendPolicy>,
        #[builder(field)] allowed_receive_policies: BTreeMap<AccountProcedureRoot, ReceivePolicy>,
        active_mint_policy: MintPolicy,
        active_burn_policy: BurnPolicy,
        active_send_policy: Option<SendPolicy>,
        active_receive_policy: Option<ReceivePolicy>,
    ) -> Self {
        let active_mint_policy_root = active_mint_policy.root();
        let active_burn_policy_root = active_burn_policy.root();
        let active_send_policy_root = active_send_policy
            .as_ref()
            .map(SendPolicy::root)
            .unwrap_or_else(|| AccountProcedureRoot::from_raw(Word::empty()));
        let active_receive_policy_root = active_receive_policy
            .as_ref()
            .map(ReceivePolicy::root)
            .unwrap_or_else(|| AccountProcedureRoot::from_raw(Word::empty()));

        let mut policies: BTreeMap<AccountProcedureRoot, PolicyConfig> = BTreeMap::new();

        insert_policy(
            &mut policies,
            active_mint_policy_root,
            active_mint_policy.into_iter().collect(),
            PolicyKind::Mint,
        );
        insert_policy(
            &mut policies,
            active_burn_policy_root,
            active_burn_policy.into_iter().collect(),
            PolicyKind::Burn,
        );
        if let Some(policy) = active_send_policy {
            insert_policy(
                &mut policies,
                active_send_policy_root,
                policy.into_iter().collect(),
                PolicyKind::Send,
            );
        }
        if let Some(policy) = active_receive_policy {
            insert_policy(
                &mut policies,
                active_receive_policy_root,
                policy.into_iter().collect(),
                PolicyKind::Receive,
            );
        }

        for (root, policy) in allowed_mint_policies {
            insert_policy(&mut policies, root, policy.into_iter().collect(), PolicyKind::Mint);
        }
        for (root, policy) in allowed_burn_policies {
            insert_policy(&mut policies, root, policy.into_iter().collect(), PolicyKind::Burn);
        }
        for (root, policy) in allowed_send_policies {
            insert_policy(&mut policies, root, policy.into_iter().collect(), PolicyKind::Send);
        }
        for (root, policy) in allowed_receive_policies {
            insert_policy(&mut policies, root, policy.into_iter().collect(), PolicyKind::Receive);
        }

        Self {
            active_mint_policy_root,
            active_burn_policy_root,
            active_send_policy_root,
            active_receive_policy_root,
            policies,
        }
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

    /// Registers a reserved send policy in the `allowed_send_policy_proc_roots` map. May be
    /// activated at runtime via `set_send_policy`. Allowed entries are deduplicated by
    /// procedure root.
    pub fn allowed_send_policy(mut self, policy: SendPolicy) -> Self {
        self.allowed_send_policies.insert(policy.root(), policy);
        self
    }

    /// Registers a reserved receive policy in the `allowed_receive_policy_proc_roots` map.
    /// May be activated at runtime via `set_receive_policy`. Allowed entries are deduplicated
    /// by procedure root.
    pub fn allowed_receive_policy(mut self, policy: ReceivePolicy) -> Self {
        self.allowed_receive_policies.insert(policy.root(), policy);
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

    const SET_MINT_POLICY_PROC_NAME: &'static str = "set_mint_policy";
    const SET_BURN_POLICY_PROC_NAME: &'static str = "set_burn_policy";
    const SET_SEND_POLICY_PROC_NAME: &'static str = "set_send_policy";
    const SET_RECEIVE_POLICY_PROC_NAME: &'static str = "set_receive_policy";
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

    /// Returns the active send policy procedure root, or [`None`] if no send policy was set.
    pub fn active_send_policy(&self) -> Option<AccountProcedureRoot> {
        (!self.active_send_policy_root.as_word().is_empty()).then_some(self.active_send_policy_root)
    }

    /// Returns the active receive policy procedure root, or [`None`] if no receive policy was
    /// set.
    pub fn active_receive_policy(&self) -> Option<AccountProcedureRoot> {
        (!self.active_receive_policy_root.as_word().is_empty())
            .then_some(self.active_receive_policy_root)
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
            .filter(|(_, cfg)| cfg.kinds.contains(&kind))
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

    /// Returns the procedure root of the `set_send_policy` account procedure.
    pub fn set_send_policy_root() -> AccountProcedureRoot {
        *POLICY_MANAGER_SET_SEND_POLICY
    }

    /// Returns the procedure root of the `set_receive_policy` account procedure.
    pub fn set_receive_policy_root() -> AccountProcedureRoot {
        *POLICY_MANAGER_SET_RECEIVE_POLICY
    }

    /// Returns the [`StorageSlotName`] where the active mint policy procedure root is stored.
    pub fn active_mint_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the active burn policy procedure root is stored.
    pub fn active_burn_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the active send policy procedure root is stored.
    pub fn active_send_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_SEND_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the active receive policy procedure root is stored.
    pub fn active_receive_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_RECEIVE_POLICY_PROC_ROOT_SLOT_NAME
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
        self.policies.iter().any(|(_, cfg)| {
            cfg.kinds.contains(&PolicyKind::Send) || cfg.kinds.contains(&PolicyKind::Receive)
        })
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
            StorageSlot::with_value(
                ACTIVE_SEND_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.active_send_policy_root.as_word(),
            ),
            StorageSlot::with_value(
                ACTIVE_RECEIVE_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.active_receive_policy_root.as_word(),
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
        // the active policy from the `active_*_policy` slot above, accepting the transfer when that
        // slot is empty. This indirection lets `set_send_policy` /
        // `set_receive_policy` switch the active policy for the entire circulating supply without
        // touching the callback slots.
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
    /// so runtime `set_*_policy` validation can confirm the root is allowed before activating
    /// it.
    fn build_allowed_map(&self, kind: PolicyKind) -> StorageMap {
        let allowed_flag = Word::from([1u32, 0, 0, 0]);
        let entries: Vec<_> = self
            .policies
            .iter()
            .filter(|(_, cfg)| cfg.kinds.contains(&kind))
            .map(|(root, _)| (StorageMapKey::new(root.as_word()), allowed_flag))
            .collect();
        StorageMap::with_entries(entries).expect("allowed policy roots should have unique keys")
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

/// Inserts a policy entry into the unified `policies` map. The new kind is appended to the
/// entry's kind set. A companion component that is already carried with the same code and storage
/// is not added again, which installs a component once when it exports the roots of several
/// policies (e.g. the send and receive procedures of a transfer policy). A component with
/// the same code but different storage is kept, so the conflict fails the account build.
fn insert_policy(
    policies: &mut BTreeMap<AccountProcedureRoot, PolicyConfig>,
    root: AccountProcedureRoot,
    components: Vec<AccountComponent>,
    kind: PolicyKind,
) {
    if let Some(cfg) = policies.get_mut(&root) {
        cfg.kinds.insert(kind);
        return;
    }

    let mut new_components: Vec<AccountComponent> = Vec::new();
    for component in components {
        let is_installed =
            policies.values().flat_map(|cfg| &cfg.components).chain(&new_components).any(
                |installed| {
                    installed.component_code() == component.component_code()
                        && installed.storage_slots() == component.storage_slots()
                },
            );
        if !is_installed {
            new_components.push(component);
        }
    }
    policies.insert(
        root,
        PolicyConfig {
            components: new_components,
            kinds: BTreeSet::from([kind]),
        },
    );
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
        for (_, policy) in self.policies {
            components.extend(policy.components);
        }
        components.into_iter()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::component::{InitStorageData, StorageValueName};
    use miden_protocol::account::{AccountBuilder, AccountId};
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
    /// roots (the active `TransferAllowAll` root lives in the `active_*_policy` slots instead).
    #[test]
    fn allow_all_transfer_policy_registers_protocol_callback_slots() {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(SendPolicy::allow_all())
            .active_receive_policy(ReceivePolicy::allow_all())
            .build();

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

        // The active TransferAllowAll root lives in the dedicated active-policy slots.
        let active_send_slot =
            find_slot(&manager_component, TokenPolicyManager::active_send_policy_slot())
                .expect("active send policy slot must be registered");
        let active_receive_slot =
            find_slot(&manager_component, TokenPolicyManager::active_receive_policy_slot())
                .expect("active receive policy slot must be registered");
        assert_eq!(active_send_slot.value(), TransferAllowAll::send_root().as_word());
        assert_eq!(active_receive_slot.value(), TransferAllowAll::receive_root().as_word());

        assert_schema_matches_storage(&manager_component);
    }

    /// Checks that a manager whose send / receive policies are registered only as reserved
    /// alternatives (no active transfer policy yet) still installs the protocol-reserved callback
    /// slots with the fixed `invoke_*_policy` wrapper roots, so `has_transfer_policy` is true from
    /// creation.
    #[test]
    fn reserved_only_transfer_policy_registers_protocol_callback_slots() {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .allowed_send_policy(SendPolicy::allow_all())
            .allowed_receive_policy(ReceivePolicy::allow_all())
            .build();

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

        // No policy has been activated yet, so the active-policy slots still hold the empty word.
        let active_send_slot =
            find_slot(&manager_component, TokenPolicyManager::active_send_policy_slot())
                .expect("active send policy slot must be registered");
        let active_receive_slot =
            find_slot(&manager_component, TokenPolicyManager::active_receive_policy_slot())
                .expect("active receive policy slot must be registered");
        assert_eq!(active_send_slot.value(), Word::empty());
        assert_eq!(active_receive_slot.value(), Word::empty());

        // The reserved roots are recorded in the allowed-roots maps so they can be promoted later.
        assert!(manager.allowed_send_policies().contains(&TransferAllowAll::send_root()));
        assert!(manager.allowed_receive_policies().contains(&TransferAllowAll::receive_root()));

        assert_schema_matches_storage(&manager_component);
    }

    /// A manager configured without send / receive policies must NOT register the protocol
    /// callback slots, leaving them free for a separate callback component.
    #[test]
    fn manager_without_transfer_policies_omits_protocol_callback_slots() {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .build();

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
    }

    /// The schema-driven construction path must produce the same storage layout as a manager
    /// configured with transfer policies, including the two protocol-reserved callback slots.
    #[test]
    fn storage_schema_covers_every_slot_of_a_transfer_policy_manager() {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(SendPolicy::allow_all())
            .active_receive_policy(ReceivePolicy::allow_all())
            .build();

        let manager_component = manager.to_manager_component();

        // The active-policy roots are the only values the schema requires; everything else either
        // defaults (the callback roots) or starts empty (the allowed-policy maps).
        let mut init_storage_data = InitStorageData::default();
        for (slot_name, root) in [
            (TokenPolicyManager::active_mint_policy_slot(), MintPolicy::allow_all().root()),
            (TokenPolicyManager::active_burn_policy_slot(), BurnPolicy::allow_all().root()),
            (TokenPolicyManager::active_send_policy_slot(), TransferAllowAll::send_root()),
            (
                TokenPolicyManager::active_receive_policy_slot(),
                TransferAllowAll::receive_root(),
            ),
        ] {
            init_storage_data
                .set_value(StorageValueName::from_slot_name(slot_name), root.as_word())
                .expect("active policy root should be a valid init value");
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
            find_schema_slot(TokenPolicyManager::active_send_policy_slot()),
            TransferAllowAll::send_root().as_word()
        );
        assert_eq!(
            find_schema_slot(TokenPolicyManager::active_receive_policy_slot()),
            TransferAllowAll::receive_root().as_word()
        );
    }

    /// Allowed entries registered via the builder land in the `allowed_*_policies` storage map
    /// alongside the active one.
    #[test]
    fn allowed_burn_policy_is_registered_in_allowed_map() {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::owner_only())
            .active_burn_policy(BurnPolicy::owner_only())
            .allowed_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(SendPolicy::allow_all())
            .active_receive_policy(ReceivePolicy::allow_all())
            .build();

        let allowed = manager.allowed_burn_policies();
        assert!(allowed.contains(&BurnPolicy::owner_only().root()));
        assert!(allowed.contains(&BurnPolicy::allow_all().root()));
    }

    /// The send and receive procedures of a list policy belong to one component with one list.
    /// When both policies start from the same list, the component is installed once and the
    /// account builds. When the lists differ, the account build fails on the duplicate list slot,
    /// so neither list is dropped silently.
    #[rstest::rstest]
    #[case::same_initial_list(true)]
    #[case::different_initial_lists(false)]
    fn send_and_receive_blocklists_must_start_from_the_same_list(#[case] same_initial_list: bool) {
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
            .build();

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
    }

    /// Merged policies that ship the same component install it once, and only the merged policy is
    /// allowed.
    #[test]
    fn merged_policies_can_share_a_component() -> anyhow::Result<()> {
        let blocklist_policy = SendPolicy::empty_basic_blocklist();
        let other_policy =
            SendPolicy::custom(BasicBlocklist::receive_root(), [BasicBlocklist::default()])?;
        let merged_policy = SendPolicy::merge([blocklist_policy, other_policy])?;
        let merged_root = merged_policy.root();
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(merged_policy)
            .build();

        assert_eq!(manager.active_send_policy(), Some(merged_root));
        assert_eq!(manager.allowed_send_policies(), [merged_root]);

        AccountBuilder::new([1; 32])
            .with_component(NoAuth)
            .with_components(manager)
            .build_existing()?;

        Ok(())
    }

    /// Components with different code are all installed, even when their names collide.
    #[test]
    fn components_with_different_code_are_installed() {
        let metadata = AccountComponentMetadata::new("tests::same_name");
        let mint_component =
            AccountComponent::new(MintAllowAll::code().clone(), vec![], metadata.clone()).unwrap();
        let burn_component =
            AccountComponent::new(BurnAllowAll::code().clone(), vec![], metadata).unwrap();

        let components: Vec<AccountComponent> = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::custom(MintAllowAll::root(), [mint_component]).unwrap())
            .active_burn_policy(BurnPolicy::custom(BurnAllowAll::root(), [burn_component]).unwrap())
            .build()
            .into_iter()
            .collect();

        assert!(components.iter().any(|component| component.has_procedure(MintAllowAll::root())));
        assert!(components.iter().any(|component| component.has_procedure(BurnAllowAll::root())));
    }

    /// The allow-all burn and receive policies have the same procedure root, since both only drop
    /// an asset. The manager registers the root under both kinds and the procedure is installed.
    #[test]
    fn policies_of_different_kinds_can_share_a_root() {
        assert_eq!(BurnAllowAll::root(), TransferAllowAll::receive_root());

        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::owner_only())
            .active_burn_policy(BurnPolicy::allow_all())
            .active_receive_policy(ReceivePolicy::allow_all())
            .build();

        assert_eq!(manager.active_burn_policy(), BurnAllowAll::root());
        assert_eq!(manager.active_receive_policy(), Some(TransferAllowAll::receive_root()));
        assert!(manager.allowed_burn_policies().contains(&BurnAllowAll::root()));
        assert!(manager.allowed_receive_policies().contains(&TransferAllowAll::receive_root()));

        let components: Vec<AccountComponent> = manager.into_iter().collect();
        assert!(components.iter().any(|component| component.has_procedure(BurnAllowAll::root())));
    }
}
