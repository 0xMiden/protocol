//! Unified token policy manager.
//!
//! [`TokenPolicyManager`] owns the policy state for fungible faucets. All four kinds use one
//! `active_*_policy_proc_root` slot each plus an `allowed_*_policies` map slot for validating
//! policy-switching at set time. Mint and burn are dispatched by `exec`-invoked
//! `execute_*_policy` wrappers from the faucet flow. Send and receive are dispatched by
//! `invoke_send_policy` / `invoke_receive_policy` wrappers whose roots live in the
//! protocol-reserved callback slots
//! (`miden::protocol::faucet::callback::on_before_asset_added_to_account` and `..._to_note`); the
//! kernel `dyncall`s the wrapper, which applies the account-wide pause check and then dispatches to
//! the active policy root.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
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
use super::transfer::TransferPolicy;
use crate::account::account_component_code;
use crate::procedure_root;

account_component_code!(POLICY_MANAGER_CODE, "faucets/policies/policy_manager.masl");

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
/// than one kind (for example a transfer policy used for both send and receive).
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
/// more than one kind, e.g. a transfer policy active for both send and receive).
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
/// transfer wrappers double as the protocol-level `on_before_asset_added_to_*` asset callbacks:
/// the kernel `dyncall`s the wrapper, which applies the account-wide pause check and then
/// dispatches to the active send / receive policy.
/// Authorization for switching the active policies is delegated to the account-wide
/// [`Authority`][crate::account::access::Authority] component, which must be installed alongside
/// this manager.
///
/// Construct via [`Self::builder`]. The builder requires the active mint and burn policy
/// ([`TokenPolicyManagerBuilder::active_mint_policy`] /
/// [`TokenPolicyManagerBuilder::active_burn_policy`]). Active send / receive policies
/// ([`TokenPolicyManagerBuilder::active_send_policy`] /
/// [`TokenPolicyManagerBuilder::active_receive_policy`]) are optional — when omitted, the
/// protocol-reserved asset-callback slots are not installed, so every minted asset carries
/// [`AssetCallbackFlag::Disabled`][miden_protocol::asset::AssetCallbackFlag::Disabled] and is
/// permanently exempt from any transfer policy installed later.
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
///   only when at least one transfer policy is configured, so a manager with transfer policies
///   mints assets carrying
///   [`AssetCallbackFlag::Enabled`][miden_protocol::asset::AssetCallbackFlag::Enabled] uniformly,
///   and future policy switches via `set_send_policy` / `set_receive_policy` apply to the entire
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
        #[builder(field)] allowed_send_policies: BTreeMap<AccountProcedureRoot, TransferPolicy>,
        #[builder(field)] allowed_receive_policies: BTreeMap<AccountProcedureRoot, TransferPolicy>,
        active_mint_policy: MintPolicy,
        active_burn_policy: BurnPolicy,
        active_send_policy: Option<TransferPolicy>,
        active_receive_policy: Option<TransferPolicy>,
    ) -> Self {
        let active_mint_policy_root = active_mint_policy.root();
        let active_burn_policy_root = active_burn_policy.root();
        let active_send_policy_root = active_send_policy
            .as_ref()
            .map(TransferPolicy::root)
            .unwrap_or_else(|| AccountProcedureRoot::from_raw(Word::empty()));
        let active_receive_policy_root = active_receive_policy
            .as_ref()
            .map(TransferPolicy::root)
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
    pub fn allowed_send_policy(mut self, policy: TransferPolicy) -> Self {
        self.allowed_send_policies.insert(policy.root(), policy);
        self
    }

    /// Registers a reserved receive policy in the `allowed_receive_policy_proc_roots` map.
    /// May be activated at runtime via `set_receive_policy`. Allowed entries are deduplicated
    /// by procedure root.
    pub fn allowed_receive_policy(mut self, policy: TransferPolicy) -> Self {
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
    /// `on_before_asset_added_to_note` callback slot.
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
        &POLICY_MANAGER_CODE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            (
                ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "Active mint policy procedure root",
                    SchemaType::native_word(),
                ),
            ),
            (
                ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "Active burn policy procedure root",
                    SchemaType::native_word(),
                ),
            ),
            (
                ACTIVE_SEND_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "Active send policy procedure root",
                    SchemaType::native_word(),
                ),
            ),
            (
                ACTIVE_RECEIVE_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "Active receive policy procedure root",
                    SchemaType::native_word(),
                ),
            ),
            (
                ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                StorageSlotSchema::map(
                    "Allowed mint policy procedure roots",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
            (
                ALLOWED_BURN_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                StorageSlotSchema::map(
                    "Allowed burn policy procedure roots",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
            (
                ALLOWED_SEND_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                StorageSlotSchema::map(
                    "Allowed send policy procedure roots",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
            (
                ALLOWED_RECEIVE_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                StorageSlotSchema::map(
                    "Allowed receive policy procedure roots",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(Self::DESCRIPTION)
            .with_storage_schema(storage_schema)
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
        // policy is configured. The slots hold the fixed `invoke_*_policy` wrapper roots (not the
        // active policy roots): the kernel `dyncall`s the wrapper, which applies the pause check
        // and then dispatches to whatever active root lives in the `active_*_policy` slot above.
        // This indirection lets `set_send_policy` / `set_receive_policy` switch the active policy
        // for the entire circulating supply without touching the callback slots.
        let has_transfer_policy = self.policies.iter().any(|(_, cfg)| {
            cfg.kinds.contains(&PolicyKind::Send) || cfg.kinds.contains(&PolicyKind::Receive)
        });
        if has_transfer_policy {
            let callback_slots = AssetCallbacks::new()
                .on_before_asset_added_to_account(Self::invoke_receive_policy_root().as_word())
                .on_before_asset_added_to_note(Self::invoke_send_policy_root().as_word())
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
            Self::component_metadata(),
        )
        .expect(
            "token policy manager component should satisfy the requirements of a valid account component",
        )
    }
}

/// Inserts a policy entry into the unified `policies` map. The new kind is appended to the
/// entry's kind set. The first call wins for the companion components, which guarantees a
/// given root's companion components are not duplicated across kinds.
fn insert_policy(
    policies: &mut BTreeMap<AccountProcedureRoot, PolicyConfig>,
    root: AccountProcedureRoot,
    components: Vec<AccountComponent>,
    kind: PolicyKind,
) {
    policies
        .entry(root)
        .and_modify(|cfg| {
            cfg.kinds.insert(kind);
        })
        .or_insert_with(|| {
            let mut kinds = BTreeSet::new();
            kinds.insert(kind);
            PolicyConfig { components, kinds }
        });
}

impl IntoIterator for TokenPolicyManager {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s implementing this token policy configuration: the
    /// manager itself first, then the companion components contributed by every registered
    /// policy. Deduplication by procedure root is implicit (the manager's internal `policies`
    /// map is keyed by root), so a policy installed under both send and receive only
    /// contributes its companion components once.
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
    use miden_protocol::asset::AssetCallbacks;

    use super::*;
    use crate::account::policies::transfer::TransferAllowAll;

    /// Returns the manager component's storage slot for the given slot name, or `None` if the
    /// component does not register a slot with that name.
    fn find_slot<'a>(
        component: &'a AccountComponent,
        slot_name: &StorageSlotName,
    ) -> Option<&'a StorageSlot> {
        component.storage_slots().iter().find(|slot| slot.name() == slot_name)
    }

    /// Checks that a manager configured with a transfer policy for both kinds registers the
    /// protocol-reserved asset-callback slots populated with the fixed `invoke_*_policy` wrapper
    /// roots (the active `TransferAllowAll` root lives in the `active_*_policy` slots instead).
    #[test]
    fn allow_all_transfer_policy_registers_protocol_callback_slots() {
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::allow_all())
            .active_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(TransferPolicy::allow_all())
            .active_receive_policy(TransferPolicy::allow_all())
            .build();

        let manager_component = manager.to_manager_component();

        let allow_all_root = TransferAllowAll::root().as_word();

        let on_account_slot =
            find_slot(&manager_component, AssetCallbacks::on_before_asset_added_to_account_slot())
                .expect(
                    "AllowAll receive policy must register the on_before_asset_added_to_account \
             protocol callback slot",
                );
        let on_note_slot =
            find_slot(&manager_component, AssetCallbacks::on_before_asset_added_to_note_slot())
                .expect(
                    "AllowAll send policy must register the on_before_asset_added_to_note protocol \
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
        assert_eq!(active_send_slot.value(), allow_all_root);
        assert_eq!(active_receive_slot.value(), allow_all_root);
    }

    /// A manager configured without send / receive policies must NOT register the
    /// protocol callback slots — otherwise it would always needlessly mint assets with
    /// callbacks enabled.
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
            find_slot(&manager_component, AssetCallbacks::on_before_asset_added_to_note_slot())
                .is_none(),
            "without a send policy, the manager must leave the on_before_asset_added_to_note slot \
             to a separate component",
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
            .active_send_policy(TransferPolicy::allow_all())
            .active_receive_policy(TransferPolicy::allow_all())
            .build();

        let allowed = manager.allowed_burn_policies();
        assert!(allowed.contains(&BurnPolicy::owner_only().root()));
        assert!(allowed.contains(&BurnPolicy::allow_all().root()));
    }
}
