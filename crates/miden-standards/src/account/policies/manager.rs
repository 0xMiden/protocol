//! Unified token policy manager.
//!
//! [`TokenPolicyManager`] owns one `active_*_policy` slot and one `allowed_*_policies` map slot
//! per policy kind (mint, burn, send, receive) plus the asset-callback storage slots, and
//! exposes the management procedures via a single MASM library.

use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountType,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::AssetCallbacks;
use miden_protocol::utils::sync::LazyLock;

use super::burn::BurnPolicyConfig;
use super::mint::MintPolicyConfig;
use super::transfer::TransferPolicy;
use super::{PolicyAuthority, PolicyRegistration};
use crate::account::components::policy_manager_library;
use crate::procedure_digest;

// STORAGE SLOT NAMES
// ================================================================================================

static POLICY_AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::policies::policy_manager::policy_authority")
        .expect("storage slot name should be valid")
});

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

// CALLBACK PROCEDURE DIGESTS
// ================================================================================================

procedure_digest!(
    ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_DIGEST,
    TokenPolicyManager::COMPONENT_LIBRARY_NAME,
    TokenPolicyManager::ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_PROC_NAME,
    policy_manager_library
);

procedure_digest!(
    ON_BEFORE_ASSET_ADDED_TO_NOTE_DIGEST,
    TokenPolicyManager::COMPONENT_LIBRARY_NAME,
    TokenPolicyManager::ON_BEFORE_ASSET_ADDED_TO_NOTE_PROC_NAME,
    policy_manager_library
);

// POLICY CONFIG
// ================================================================================================

/// Internal entry stored inside [`TokenPolicyManager`] for every registered policy.
///
/// Captures the policy's procedure root, any companion components it depends on, and whether
/// it is currently active or a reserved alternative.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// The procedure root the manager writes into the `active_*_policy` slot (when
    /// [`PolicyRegistration::Active`]) and / or adds to the `allowed_*_policies` map.
    root: Word,
    /// Companion components the policy needs installed on the account (e.g. `Blocklist`
    /// storage for `IfNotBlocklisted`). Empty for `Custom` variants — the caller installs
    /// separately.
    components: Vec<AccountComponent>,
    /// Whether this entry is the active policy or a reserved alternative.
    registration: PolicyRegistration,
    /// Whether the policy needs the protocol's asset-callback slots populated. Currently only
    /// non-trivial transfer policies set this to `true`; mint and burn policies always leave
    /// it `false`.
    requires_callbacks: bool,
}

impl PolicyConfig {
    fn new(
        root: Word,
        components: Vec<AccountComponent>,
        registration: PolicyRegistration,
        requires_callbacks: bool,
    ) -> Self {
        Self {
            root,
            components,
            registration,
            requires_callbacks,
        }
    }

    /// Returns the procedure root of this policy.
    pub fn root(&self) -> Word {
        self.root
    }

    /// Returns whether this entry is registered as active or as a reserved alternative.
    pub fn registration(&self) -> PolicyRegistration {
        self.registration
    }
}

// TOKEN POLICY MANAGER
// ================================================================================================

/// An [`AccountComponent`] that owns the policy-manager storage slots and the manager
/// procedures for the four policy kinds (mint, burn, send, receive).
///
/// The component exposes `set_*_policy`, `get_*_policy`, and `execute_*_policy` procedures for
/// each kind, plus the protocol-level `on_before_asset_added_to_*` asset callbacks (which
/// dispatch to the active send / receive policy). The shared [`PolicyAuthority`] mode controls
/// who can change any policy:
/// - [`PolicyAuthority::AuthControlled`]: changes are gated by the account's authentication
///   component.
/// - [`PolicyAuthority::OwnerControlled`]: changes require the account owner (verified through the
///   `Ownable2Step` companion component).
///
/// Construct via [`Self::new`] and chain the per-kind builders
/// ([`Self::with_mint_policy`] / [`Self::with_burn_policy`] / [`Self::with_send_policy`] /
/// [`Self::with_receive_policy`]). Each accepts a typed config plus a [`PolicyRegistration`]
/// flag to register the policy as either the active one or as a reserved alternative for
/// runtime switching via the matching `set_*_policy` procedure.
///
/// Pass the manager directly to [`miden_protocol::account::AccountBuilder::with_components`]
/// (the type implements [`IntoIterator<Item = AccountComponent>`]). Iteration yields the
/// manager itself plus deduplicated companion components for every registered policy. `Custom`
/// variants on any kind contribute no built-in components — the caller installs the matching
/// components on the account separately.
///
/// ## Storage layout
///
/// - [`Self::policy_authority_slot`]: shared authority mode.
/// - [`Self::active_mint_policy_slot`]: procedure root of the active mint policy.
/// - [`Self::active_burn_policy_slot`]: procedure root of the active burn policy.
/// - [`Self::active_send_policy_slot`]: procedure root of the active send policy.
/// - [`Self::active_receive_policy_slot`]: procedure root of the active receive policy.
/// - [`Self::allowed_mint_policies_slot`]: map of allowed mint policy roots.
/// - [`Self::allowed_burn_policies_slot`]: map of allowed burn policy roots.
/// - [`Self::allowed_send_policies_slot`]: map of allowed send policy roots.
/// - [`Self::allowed_receive_policies_slot`]: map of allowed receive policy roots.
/// - Asset-callback storage slots (registered via [`AssetCallbacks`]) wiring the manager's
///   `on_before_asset_added_to_*` procedures into the protocol callback dispatch — installed only
///   when at least one of the send / receive policies needs callbacks (built-in `AllowAll` does
///   not).
#[derive(Debug, Clone)]
pub struct TokenPolicyManager {
    authority: PolicyAuthority,
    mint_policies: Vec<PolicyConfig>,
    burn_policies: Vec<PolicyConfig>,
    send_policies: Vec<PolicyConfig>,
    receive_policies: Vec<PolicyConfig>,
}

impl TokenPolicyManager {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component (used in metadata).
    pub const NAME: &'static str = "miden::standards::faucets::policies::policy_manager";

    /// The library namespace under which the component's MASM procedures are exported. Used to
    /// look up procedure roots via [`crate::procedure_digest!`].
    pub(crate) const COMPONENT_LIBRARY_NAME: &'static str =
        "miden::standards::components::faucets::policies::policy_manager";

    /// Component description used in [`AccountComponentMetadata`].
    pub const DESCRIPTION: &'static str = "Token policy manager for fungible faucets";

    pub(crate) const ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_PROC_NAME: &'static str =
        "on_before_asset_added_to_account";
    pub(crate) const ON_BEFORE_ASSET_ADDED_TO_NOTE_PROC_NAME: &'static str =
        "on_before_asset_added_to_note";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an empty token policy manager. Use the per-kind builders (`with_mint_policy`,
    /// `with_burn_policy`, `with_send_policy`, `with_receive_policy`) to register policies.
    ///
    /// Every kind must end up with exactly one [`PolicyRegistration::Active`] entry by the time
    /// the manager is converted into account components; missing kinds will panic on conversion.
    pub fn new(authority: PolicyAuthority) -> Self {
        Self {
            authority,
            mint_policies: Vec::new(),
            burn_policies: Vec::new(),
            send_policies: Vec::new(),
            receive_policies: Vec::new(),
        }
    }

    /// Registers a mint policy. The `registration` flag decides whether the policy becomes the
    /// active one (written to `active_mint_policy_proc_root`) or a reserved alternative (added
    /// to the `allowed_mint_policy_proc_roots` map for runtime switching via `set_mint_policy`).
    pub fn with_mint_policy(
        mut self,
        policy: MintPolicyConfig,
        registration: PolicyRegistration,
    ) -> Self {
        let entry = PolicyConfig::new(policy.root(), policy.into_components(), registration, false);
        push_unique(&mut self.mint_policies, entry);
        self
    }

    /// Registers a burn policy. See [`Self::with_mint_policy`] for `registration` semantics.
    pub fn with_burn_policy(
        mut self,
        policy: BurnPolicyConfig,
        registration: PolicyRegistration,
    ) -> Self {
        let entry = PolicyConfig::new(policy.root(), policy.into_components(), registration, false);
        push_unique(&mut self.burn_policies, entry);
        self
    }

    /// Registers a send policy (fired by the `on_before_asset_added_to_note` callback). See
    /// [`Self::with_mint_policy`] for `registration` semantics.
    pub fn with_send_policy(
        mut self,
        policy: TransferPolicy,
        registration: PolicyRegistration,
    ) -> Self {
        let entry = PolicyConfig::new(
            policy.root(),
            policy.into_components(),
            registration,
            policy.requires_callbacks(),
        );
        push_unique(&mut self.send_policies, entry);
        self
    }

    /// Registers a receive policy (fired by the `on_before_asset_added_to_account` callback).
    /// See [`Self::with_mint_policy`] for `registration` semantics.
    pub fn with_receive_policy(
        mut self,
        policy: TransferPolicy,
        registration: PolicyRegistration,
    ) -> Self {
        let entry = PolicyConfig::new(
            policy.root(),
            policy.into_components(),
            registration,
            policy.requires_callbacks(),
        );
        push_unique(&mut self.receive_policies, entry);
        self
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the authority used by this manager.
    pub fn authority(&self) -> PolicyAuthority {
        self.authority
    }

    /// Returns the active mint policy procedure root.
    pub fn active_mint_policy(&self) -> Word {
        active_root(&self.mint_policies, "mint")
    }

    /// Returns the active burn policy procedure root.
    pub fn active_burn_policy(&self) -> Word {
        active_root(&self.burn_policies, "burn")
    }

    /// Returns the active send policy procedure root.
    pub fn active_send_policy(&self) -> Word {
        active_root(&self.send_policies, "send")
    }

    /// Returns the active receive policy procedure root.
    pub fn active_receive_policy(&self) -> Word {
        active_root(&self.receive_policies, "receive")
    }

    /// Returns all allowed mint policy procedure roots (active + reserved).
    pub fn allowed_mint_policies(&self) -> Vec<Word> {
        all_roots(&self.mint_policies)
    }

    /// Returns all allowed burn policy procedure roots (active + reserved).
    pub fn allowed_burn_policies(&self) -> Vec<Word> {
        all_roots(&self.burn_policies)
    }

    /// Returns all allowed send policy procedure roots (active + reserved).
    pub fn allowed_send_policies(&self) -> Vec<Word> {
        all_roots(&self.send_policies)
    }

    /// Returns all allowed receive policy procedure roots (active + reserved).
    pub fn allowed_receive_policies(&self) -> Vec<Word> {
        all_roots(&self.receive_policies)
    }

    /// Returns the [`StorageSlotName`] containing the policy authority mode.
    pub fn policy_authority_slot() -> &'static StorageSlotName {
        &POLICY_AUTHORITY_SLOT_NAME
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

    /// Returns the procedure root of the manager's `on_before_asset_added_to_account` callback.
    pub fn on_before_asset_added_to_account_digest() -> Word {
        *ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_DIGEST
    }

    /// Returns the procedure root of the manager's `on_before_asset_added_to_note` callback.
    pub fn on_before_asset_added_to_note_digest() -> Word {
        *ON_BEFORE_ASSET_ADDED_TO_NOTE_DIGEST
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            (
                POLICY_AUTHORITY_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "Token policy authority",
                    [
                        FeltSchema::u8("policy_authority"),
                        FeltSchema::new_void(),
                        FeltSchema::new_void(),
                        FeltSchema::new_void(),
                    ],
                ),
            ),
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

        AccountComponentMetadata::new(Self::NAME, [AccountType::FungibleFaucet])
            .with_description(Self::DESCRIPTION)
            .with_storage_schema(storage_schema)
    }

    fn manager_storage_slots(&self) -> Vec<StorageSlot> {
        let mut slots = vec![
            StorageSlot::with_value(POLICY_AUTHORITY_SLOT_NAME.clone(), self.authority.into()),
            StorageSlot::with_value(
                ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.active_mint_policy(),
            ),
            StorageSlot::with_value(
                ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.active_burn_policy(),
            ),
            StorageSlot::with_value(
                ACTIVE_SEND_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.active_send_policy(),
            ),
            StorageSlot::with_value(
                ACTIVE_RECEIVE_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.active_receive_policy(),
            ),
            StorageSlot::with_map(
                ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                build_allowed_map(&self.mint_policies, "mint"),
            ),
            StorageSlot::with_map(
                ALLOWED_BURN_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                build_allowed_map(&self.burn_policies, "burn"),
            ),
            StorageSlot::with_map(
                ALLOWED_SEND_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                build_allowed_map(&self.send_policies, "send"),
            ),
            StorageSlot::with_map(
                ALLOWED_RECEIVE_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                build_allowed_map(&self.receive_policies, "receive"),
            ),
        ];

        // Only register the asset-callback slots when at least one of the send / receive
        // policies actually performs enforcement. Beyond saving slots and dispatch overhead
        // for no-op `AllowAll`, this also keeps the minted asset value word free of
        // `AssetCallbackFlag::Enabled` — `protocol::faucet::create_fungible_asset` reads the
        // callback slots and stamps the flag on every minted asset when they are populated.
        let needs_callbacks = self.send_policies.iter().any(|p| p.requires_callbacks)
            || self.receive_policies.iter().any(|p| p.requires_callbacks);
        if needs_callbacks {
            let callback_slots = AssetCallbacks::new()
                .on_before_asset_added_to_account(Self::on_before_asset_added_to_account_digest())
                .on_before_asset_added_to_note(Self::on_before_asset_added_to_note_digest())
                .into_storage_slots();
            slots.extend(callback_slots);
        }

        slots
    }

    fn into_manager_component(&self) -> AccountComponent {
        let storage_slots = self.manager_storage_slots();
        AccountComponent::new(
            policy_manager_library(),
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
    /// manager itself first, then companion components contributed by every registered policy
    /// across all four kinds, deduplicated by policy root (so a policy installed under both
    /// send and receive only contributes its companion components once). `Custom` variants on
    /// any kind contribute no built-in components — the caller installs the matching components
    /// on the account separately.
    ///
    /// Every kind must have exactly one [`PolicyRegistration::Active`] entry; otherwise the
    /// internal storage-slot construction panics.
    fn into_iter(self) -> Self::IntoIter {
        let manager_component = self.into_manager_component();
        let TokenPolicyManager {
            mint_policies,
            burn_policies,
            send_policies,
            receive_policies,
            ..
        } = self;

        let mut components = vec![manager_component];
        let mut installed_roots: Vec<Word> = Vec::new();
        for kind in [mint_policies, burn_policies, send_policies, receive_policies] {
            for entry in kind {
                if installed_roots.contains(&entry.root) {
                    continue;
                }
                installed_roots.push(entry.root);
                components.extend(entry.components);
            }
        }
        components.into_iter()
    }
}

// HELPERS
// ================================================================================================

/// Pushes `entry` into `vec` unless an entry with the same root is already present (in which
/// case the new entry is silently dropped — duplicate registrations are a no-op).
fn push_unique(vec: &mut Vec<PolicyConfig>, entry: PolicyConfig) {
    if !vec.iter().any(|existing| existing.root == entry.root) {
        vec.push(entry);
    }
}

/// Returns the procedure root of the unique [`PolicyRegistration::Active`] entry, panicking
/// with a descriptive message if none is registered or if more than one is registered.
fn active_root(entries: &[PolicyConfig], kind: &str) -> Word {
    let mut active = entries.iter().filter(|e| e.registration == PolicyRegistration::Active);
    let Some(first) = active.next() else {
        panic!("token policy manager: no active {kind} policy registered");
    };
    if active.next().is_some() {
        panic!("token policy manager: more than one active {kind} policy registered");
    }
    first.root
}

/// Returns every registered procedure root for the given kind (active + reserved).
fn all_roots(entries: &[PolicyConfig]) -> Vec<Word> {
    entries.iter().map(|e| e.root).collect()
}

/// Builds the `allowed_*_policies` storage map for a given kind. Includes both Active and
/// Reserved entries so runtime `set_*_policy` validation accepts swaps to either.
fn build_allowed_map(entries: &[PolicyConfig], kind: &str) -> StorageMap {
    let allowed_flag = Word::from([1u32, 0, 0, 0]);
    let map_entries: Vec<_> = entries
        .iter()
        .map(|e| (StorageMapKey::from_raw(e.root), allowed_flag))
        .collect();
    StorageMap::with_entries(map_entries)
        .unwrap_or_else(|_| panic!("allowed {kind} policy roots should have unique keys"))
}
