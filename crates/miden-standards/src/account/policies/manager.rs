//! Unified token policy manager.
//!
//! [`TokenPolicyManager`] owns the policy state for fungible faucets. Mint and burn use one
//! `active_*_policy_proc_root` slot each plus an `allowed_*_policies` map slot; send and
//! receive are flattened — their active policy roots live directly in the protocol-reserved
//! callback slots (`miden::protocol::faucet::callback::on_before_asset_added_to_account` and
//! `..._to_note`) so the kernel dispatches to them via `call` without a manager-side wrapper.
//! Each kind also has an `allowed_*_policies` map slot for validating policy-switching at
//! set time.

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

use super::PolicyRegistration;
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
/// The component exposes `set_*_policy`, `get_*_policy`, and `execute_*_policy` procedures for
/// each kind, plus the protocol-level `on_before_asset_added_to_*` asset callbacks (which
/// dispatch to the active send / receive policy). Authorization for switching the active policies
/// is delegated to the account-wide [`Authority`][crate::account::access::Authority] component,
/// which must be installed alongside this manager.
///
/// Construct via [`Self::new`] and chain the per-kind builders ([`Self::with_mint_policy`] /
/// [`Self::with_burn_policy`] / [`Self::with_send_policy`] / [`Self::with_receive_policy`]).
/// Each accepts a typed policy descriptor plus a [`PolicyRegistration`] flag to register the
/// policy as either the active one or as a reserved alternative for runtime switching via the
/// matching `set_*_policy` procedure. If [`PolicyRegistration::Active`] is supplied more than
/// once for the same kind, the most recent registration wins for the active slot — earlier
/// `Active` calls of that kind become reserved entries.
///
/// Pass the manager directly to [`miden_protocol::account::AccountBuilder::with_components`]
/// (the type implements [`IntoIterator<Item = AccountComponent>`]). Iteration yields the
/// manager itself plus the companion components contributed by every registered policy
/// (deduplicated by procedure root — a policy installed under both send and receive only
/// contributes its companion components once). Descriptors built via
/// [`MintPolicy::custom`], [`BurnPolicy::custom`], or [`TransferPolicy::custom`] contribute no
/// companion components — the caller installs the matching components on the account
/// separately.
///
/// ## Storage layout
///
/// - [`Self::active_mint_policy_slot`]: procedure root of the active mint policy.
/// - [`Self::active_burn_policy_slot`]: procedure root of the active burn policy.
/// - [`Self::allowed_mint_policies_slot`]: map of allowed mint policy roots.
/// - [`Self::allowed_burn_policies_slot`]: map of allowed burn policy roots.
/// - [`Self::allowed_send_policies_slot`]: map of allowed send policy roots.
/// - [`Self::allowed_receive_policies_slot`]: map of allowed receive policy roots.
/// - Asset-callback storage slots (registered via [`AssetCallbacks`]) hold the active send and
///   receive policy procedure roots directly so the kernel dispatches to them via `call`. They are
///   installed whenever any transfer policy is registered with this manager — including `AllowAll`
///   — so that every minted asset carries
///   [`AssetCallbackFlag::Enabled`][miden_protocol::asset::AssetCallbackFlag::Enabled] uniformly
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

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns an empty token policy manager. Use the chained [`Self::with_mint_policy`] /
    /// [`Self::with_burn_policy`] / [`Self::with_send_policy`] / [`Self::with_receive_policy`]
    /// methods to register policies, then pass the manager directly to
    /// [`miden_protocol::account::AccountBuilder::with_components`].
    pub fn new() -> Self {
        Self::default()
    }

    // BUILDER METHODS
    // --------------------------------------------------------------------------------------------

    /// Registers a mint policy. The `registration` flag decides whether the policy becomes the
    /// active one (written to `active_mint_policy_proc_root`) or a reserved alternative (added
    /// to the `allowed_mint_policy_proc_roots` map for runtime switching via `set_mint_policy`).
    ///
    /// If [`PolicyRegistration::Active`] is supplied more than once for this kind, the most
    /// recent call wins — earlier active entries are demoted to reserved (they remain in the
    /// `allowed_*_policy_proc_roots` map).
    pub fn with_mint_policy(
        mut self,
        policy: MintPolicy,
        registration: PolicyRegistration,
    ) -> Self {
        let root = policy.root();
        if registration == PolicyRegistration::Active {
            self.active_mint_policy_root = root;
        }
        self.insert_policy(root, policy.into_components(), PolicyKind::Mint);
        self
    }

    /// Registers a burn policy. See [`Self::with_mint_policy`] for `registration` semantics.
    pub fn with_burn_policy(
        mut self,
        policy: BurnPolicy,
        registration: PolicyRegistration,
    ) -> Self {
        let root = policy.root();
        if registration == PolicyRegistration::Active {
            self.active_burn_policy_root = root;
        }
        self.insert_policy(root, policy.into_components(), PolicyKind::Burn);
        self
    }

    /// Registers a send policy (fired by the `on_before_asset_added_to_note` callback). See
    /// [`Self::with_mint_policy`] for `registration` semantics.
    pub fn with_send_policy(
        mut self,
        policy: TransferPolicy,
        registration: PolicyRegistration,
    ) -> Self {
        let root = policy.root();
        if registration == PolicyRegistration::Active {
            self.active_send_policy_root = root;
        }
        self.insert_policy(root, policy.into_components(), PolicyKind::Send);
        self
    }

    /// Registers a receive policy (fired by the `on_before_asset_added_to_account` callback).
    /// See [`Self::with_mint_policy`] for `registration` semantics.
    pub fn with_receive_policy(
        mut self,
        policy: TransferPolicy,
        registration: PolicyRegistration,
    ) -> Self {
        let root = policy.root();
        if registration == PolicyRegistration::Active {
            self.active_receive_policy_root = root;
        }
        self.insert_policy(root, policy.into_components(), PolicyKind::Receive);
        self
    }

    /// Inserts (or merges, if the root is already present) a policy entry into the unified
    /// `policies` map. The new kind is appended to the entry's kind set. The first call wins
    /// for the companion components, which guarantees a given root's companion components are
    /// not duplicated across kinds.
    fn insert_policy(
        &mut self,
        root: AccountProcedureRoot,
        components: Vec<AccountComponent>,
        kind: PolicyKind,
    ) {
        self.policies
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

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the active mint policy procedure root, or [`None`] if no active mint policy has
    /// been registered.
    pub fn active_mint_policy(&self) -> Option<AccountProcedureRoot> {
        (!self.active_mint_policy_root.as_word().is_empty()).then_some(self.active_mint_policy_root)
    }

    /// Returns the active burn policy procedure root, or [`None`] if no active burn policy has
    /// been registered.
    pub fn active_burn_policy(&self) -> Option<AccountProcedureRoot> {
        (!self.active_burn_policy_root.as_word().is_empty()).then_some(self.active_burn_policy_root)
    }

    /// Returns the active send policy procedure root, or [`None`] if no active send policy has
    /// been registered.
    pub fn active_send_policy(&self) -> Option<AccountProcedureRoot> {
        (!self.active_send_policy_root.as_word().is_empty()).then_some(self.active_send_policy_root)
    }

    /// Returns the active receive policy procedure root, or [`None`] if no active receive
    /// policy has been registered.
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
        // Raw active-root fields are written directly: an unset (default) root corresponds to
        // the zero word, which the MASM treats as "no policy installed" and will trap on at
        // first invocation. Callers that want a build-time check can inspect the
        // `active_*_policy()` accessors before passing the manager to `AccountBuilder`.
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

        // Register the protocol-reserved asset-callback slots whenever any transfer policy is
        // configured on this manager.
        //
        // Registering the slots whenever transfer policies are present stamps
        // `AssetCallbackFlag::Enabled` on every asset minted by this faucet. Without this, a
        // faucet that ships with `AllowAll` for transfer would mint callback-less assets that
        // are permanently exempt from any transfer policy installed later. This would fragment
        // the circulating supply into enforceable and exempt asset sets.
        //
        // When no transfer policy is set, the callback slots are not added, meaning all minted
        // assets have callbacks disabled.
        let has_transfer_policy = self.policies.iter().any(|(_, cfg)| {
            cfg.kinds.contains(&PolicyKind::Send) || cfg.kinds.contains(&PolicyKind::Receive)
        });
        if has_transfer_policy {
            let callback_slots = AssetCallbacks::new()
                .on_before_asset_added_to_account(self.active_receive_policy_root.as_word())
                .on_before_asset_added_to_note(self.active_send_policy_root.as_word())
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

impl IntoIterator for TokenPolicyManager {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s implementing this token policy configuration: the
    /// manager itself first, then the companion components contributed by every registered
    /// policy. Deduplication by procedure root is implicit (the manager's internal `policies`
    /// map is keyed by root), so a policy installed under both send and receive only
    /// contributes its companion components once. Descriptors built via [`MintPolicy::custom`],
    /// [`BurnPolicy::custom`], or [`TransferPolicy::custom`] contribute no companion components
    /// — the caller installs the matching components on the account separately.
    fn into_iter(self) -> Self::IntoIter {
        let manager_component = self.to_manager_component();
        let mut components = vec![manager_component];
        for (_, policy) in self.policies {
            components.extend(policy.components);
        }
        components.into_iter()
    }
}

impl Default for TokenPolicyManager {
    fn default() -> Self {
        Self {
            active_mint_policy_root: AccountProcedureRoot::from_raw(Word::empty()),
            active_burn_policy_root: AccountProcedureRoot::from_raw(Word::empty()),
            active_send_policy_root: AccountProcedureRoot::from_raw(Word::empty()),
            active_receive_policy_root: AccountProcedureRoot::from_raw(Word::empty()),
            policies: BTreeMap::new(),
        }
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

    /// Checks that a manager configured with `TransferAllowAll` for both transfer kinds
    /// registers the protocol-reserved asset-callback slots, populated with
    /// `TransferAllowAll`'s procedure root.
    #[test]
    fn allow_all_transfer_policy_registers_protocol_callback_slots() {
        let manager = TokenPolicyManager::new()
            .with_mint_policy(MintPolicy::allow_all(), PolicyRegistration::Active)
            .with_burn_policy(BurnPolicy::allow_all(), PolicyRegistration::Active)
            .with_send_policy(TransferPolicy::allow_all(), PolicyRegistration::Active)
            .with_receive_policy(TransferPolicy::allow_all(), PolicyRegistration::Active);

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

        // Both slots must hold the AllowAll procedure root (not zero).
        assert_eq!(on_account_slot.value(), allow_all_root);
        assert_eq!(on_note_slot.value(), allow_all_root);
    }

    /// A manager configured without any send / receive policy must NOT register the
    /// protocol callback slots — otherwise it would always needlessly mint assets with
    /// callbacks enabled.
    #[test]
    fn manager_without_transfer_policies_omits_protocol_callback_slots() {
        let manager = TokenPolicyManager::new()
            .with_mint_policy(MintPolicy::allow_all(), PolicyRegistration::Active)
            .with_burn_policy(BurnPolicy::allow_all(), PolicyRegistration::Active);

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

    /// When `Active` is supplied twice for the same kind the most recent call wins for the
    /// active slot, and the earlier root is retained as a reserved allowed entry.
    #[test]
    fn last_active_registration_wins_for_kind() {
        let manager = TokenPolicyManager::new()
            .with_mint_policy(MintPolicy::allow_all(), PolicyRegistration::Active)
            .with_mint_policy(MintPolicy::owner_only(), PolicyRegistration::Active);

        assert_eq!(manager.active_mint_policy(), Some(MintPolicy::owner_only().root()));

        let allowed = manager.allowed_mint_policies();
        assert!(allowed.contains(&MintPolicy::allow_all().root()));
        assert!(allowed.contains(&MintPolicy::owner_only().root()));
    }
}
