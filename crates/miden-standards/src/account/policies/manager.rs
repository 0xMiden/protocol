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
use crate::account::account_component_code;

account_component_code!(POLICY_MANAGER_CODE, "faucets/policies/policy_manager.masl");

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
/// account, whether the policy needs the protocol's asset-callback slots populated, and the
/// set of policy kinds the root is registered under (the same root may serve more than one
/// kind, e.g. a transfer policy active for both send and receive).
#[derive(Debug, Clone)]
struct PolicyConfig {
    components: Vec<AccountComponent>,
    requires_callbacks: bool,
    kinds: BTreeSet<PolicyKind>,
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
/// runtime switching via the matching `set_*_policy` procedure. Calling a `with_*_policy`
/// builder with [`PolicyRegistration::Active`] more than once for the same kind panics — at
/// most one active policy per kind is permitted.
///
/// Pass the manager directly to [`miden_protocol::account::AccountBuilder::with_components`]
/// (the type implements [`IntoIterator<Item = AccountComponent>`]). Iteration yields the
/// manager itself plus the companion components contributed by every registered policy
/// (deduplicated by procedure root — a policy installed under both send and receive only
/// contributes its companion components once). `Custom` variants on any kind contribute no
/// built-in components — the caller installs the matching components on the account
/// separately.
///
/// ## Storage layout
///
/// - [`Self::policy_authority_slot`]: shared authority mode.
/// - [`Self::active_mint_policy_slot`]: procedure root of the active mint policy.
/// - [`Self::active_burn_policy_slot`]: procedure root of the active burn policy.
/// - [`Self::allowed_mint_policies_slot`]: map of allowed mint policy roots.
/// - [`Self::allowed_burn_policies_slot`]: map of allowed burn policy roots.
/// - [`Self::allowed_send_policies_slot`]: map of allowed send policy roots.
/// - [`Self::allowed_receive_policies_slot`]: map of allowed receive policy roots.
/// - Asset-callback storage slots (registered via [`AssetCallbacks`]) hold the active send and
///   receive policy procedure roots directly so the kernel dispatches to them via `call`. They are
///   installed only when at least one of the send / receive policies needs callbacks (built-in
///   `AllowAll` does not).
#[derive(Debug, Clone)]
pub struct TokenPolicyManager {
    authority: PolicyAuthority,
    active_mint_policy_root: Word,
    active_burn_policy_root: Word,
    active_send_policy_root: Word,
    active_receive_policy_root: Word,
    policies: BTreeMap<Word, PolicyConfig>,
}

impl TokenPolicyManager {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component (used in metadata).
    pub const NAME: &'static str = "miden::standards::faucets::policies::policy_manager";

    /// Component description used in [`AccountComponentMetadata`].
    pub const DESCRIPTION: &'static str = "Token policy manager for fungible faucets";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an empty token policy manager. Use the per-kind builders (`with_mint_policy`,
    /// `with_burn_policy`, `with_send_policy`, `with_receive_policy`) to register policies.
    ///
    /// Every kind must end up with exactly one [`PolicyRegistration::Active`] entry by the time
    /// the manager is converted into account components; missing kinds panic at conversion.
    pub fn new(authority: PolicyAuthority) -> Self {
        Self {
            authority,
            active_mint_policy_root: Word::default(),
            active_burn_policy_root: Word::default(),
            active_send_policy_root: Word::default(),
            active_receive_policy_root: Word::default(),
            policies: BTreeMap::new(),
        }
    }

    /// Registers a mint policy. The `registration` flag decides whether the policy becomes the
    /// active one (written to `active_mint_policy_proc_root`) or a reserved alternative (added
    /// to the `allowed_mint_policy_proc_roots` map for runtime switching via `set_mint_policy`).
    ///
    /// Panics if `registration` is [`PolicyRegistration::Active`] and an active mint policy is
    /// already registered (at most one active policy per kind is permitted).
    pub fn with_mint_policy(
        mut self,
        policy: MintPolicyConfig,
        registration: PolicyRegistration,
    ) -> Self {
        let root = policy.root();
        if registration == PolicyRegistration::Active {
            assert!(
                self.active_mint_policy_root == Word::default(),
                "token policy manager: more than one active mint policy registered",
            );
            self.active_mint_policy_root = root;
        }
        self.insert_policy(root, policy.into_components(), false, PolicyKind::Mint);
        self
    }

    /// Registers a burn policy. See [`Self::with_mint_policy`] for `registration` semantics.
    ///
    /// Panics if `registration` is [`PolicyRegistration::Active`] and an active burn policy is
    /// already registered.
    pub fn with_burn_policy(
        mut self,
        policy: BurnPolicyConfig,
        registration: PolicyRegistration,
    ) -> Self {
        let root = policy.root();
        if registration == PolicyRegistration::Active {
            assert!(
                self.active_burn_policy_root == Word::default(),
                "token policy manager: more than one active burn policy registered",
            );
            self.active_burn_policy_root = root;
        }
        self.insert_policy(root, policy.into_components(), false, PolicyKind::Burn);
        self
    }

    /// Registers a send policy (fired by the `on_before_asset_added_to_note` callback). See
    /// [`Self::with_mint_policy`] for `registration` semantics.
    ///
    /// Panics if `registration` is [`PolicyRegistration::Active`] and an active send policy is
    /// already registered.
    pub fn with_send_policy(
        mut self,
        policy: TransferPolicy,
        registration: PolicyRegistration,
    ) -> Self {
        let root = policy.root();
        let requires_callbacks = policy.requires_callbacks();
        if registration == PolicyRegistration::Active {
            assert!(
                self.active_send_policy_root == Word::default(),
                "token policy manager: more than one active send policy registered",
            );
            self.active_send_policy_root = root;
        }
        self.insert_policy(root, policy.into_components(), requires_callbacks, PolicyKind::Send);
        self
    }

    /// Registers a receive policy (fired by the `on_before_asset_added_to_account` callback).
    /// See [`Self::with_mint_policy`] for `registration` semantics.
    ///
    /// Panics if `registration` is [`PolicyRegistration::Active`] and an active receive policy
    /// is already registered.
    pub fn with_receive_policy(
        mut self,
        policy: TransferPolicy,
        registration: PolicyRegistration,
    ) -> Self {
        let root = policy.root();
        let requires_callbacks = policy.requires_callbacks();
        if registration == PolicyRegistration::Active {
            assert!(
                self.active_receive_policy_root == Word::default(),
                "token policy manager: more than one active receive policy registered",
            );
            self.active_receive_policy_root = root;
        }
        self.insert_policy(root, policy.into_components(), requires_callbacks, PolicyKind::Receive);
        self
    }

    /// Inserts (or merges, if the root is already present) a policy entry into the unified
    /// `policies` map. The new kind is appended to the entry's kind set; the first call wins
    /// for the components and `requires_callbacks` flag, which guarantees a given root's
    /// companion components are not duplicated across kinds.
    fn insert_policy(
        &mut self,
        root: Word,
        components: Vec<AccountComponent>,
        requires_callbacks: bool,
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
                PolicyConfig { components, requires_callbacks, kinds }
            });
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the authority used by this manager.
    pub fn authority(&self) -> PolicyAuthority {
        self.authority
    }

    /// Returns the active mint policy procedure root. Panics if no active mint policy has been
    /// registered.
    pub fn active_mint_policy(&self) -> Word {
        assert!(
            self.active_mint_policy_root != Word::default(),
            "token policy manager: no active mint policy registered",
        );
        self.active_mint_policy_root
    }

    /// Returns the active burn policy procedure root. Panics if no active burn policy has
    /// been registered.
    pub fn active_burn_policy(&self) -> Word {
        assert!(
            self.active_burn_policy_root != Word::default(),
            "token policy manager: no active burn policy registered",
        );
        self.active_burn_policy_root
    }

    /// Returns the active send policy procedure root. Panics if no active send policy has
    /// been registered.
    pub fn active_send_policy(&self) -> Word {
        assert!(
            self.active_send_policy_root != Word::default(),
            "token policy manager: no active send policy registered",
        );
        self.active_send_policy_root
    }

    /// Returns the active receive policy procedure root. Panics if no active receive policy
    /// has been registered.
    pub fn active_receive_policy(&self) -> Word {
        assert!(
            self.active_receive_policy_root != Word::default(),
            "token policy manager: no active receive policy registered",
        );
        self.active_receive_policy_root
    }

    /// Returns all allowed mint policy procedure roots (active + reserved).
    pub fn allowed_mint_policies(&self) -> Vec<Word> {
        self.roots_of_kind(PolicyKind::Mint)
    }

    /// Returns all allowed burn policy procedure roots (active + reserved).
    pub fn allowed_burn_policies(&self) -> Vec<Word> {
        self.roots_of_kind(PolicyKind::Burn)
    }

    /// Returns all allowed send policy procedure roots (active + reserved).
    pub fn allowed_send_policies(&self) -> Vec<Word> {
        self.roots_of_kind(PolicyKind::Send)
    }

    /// Returns all allowed receive policy procedure roots (active + reserved).
    pub fn allowed_receive_policies(&self) -> Vec<Word> {
        self.roots_of_kind(PolicyKind::Receive)
    }

    fn roots_of_kind(&self, kind: PolicyKind) -> Vec<Word> {
        self.policies
            .iter()
            .filter(|(_, cfg)| cfg.kinds.contains(&kind))
            .map(|(root, _)| *root)
            .collect()
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

        // Only register the asset-callback slots when at least one of the send / receive
        // policies actually performs enforcement. Beyond saving slots and dispatch overhead
        // for no-op `AllowAll`, this also keeps the minted asset value word free of
        // `AssetCallbackFlag::Enabled` — `protocol::faucet::create_fungible_asset` reads the
        // callback slots and stamps the flag on every minted asset when they are populated.
        //
        // With the flattened policy dispatch, the protocol callback slots hold the active
        // policy proc root directly (no manager-side wrapper), so we initialize them to the
        // active send / receive policy roots.
        let needs_callbacks = self.policies.values().any(|cfg| {
            cfg.requires_callbacks
                && (cfg.kinds.contains(&PolicyKind::Send)
                    || cfg.kinds.contains(&PolicyKind::Receive))
        });
        if needs_callbacks {
            let callback_slots = AssetCallbacks::new()
                .on_before_asset_added_to_account(self.active_receive_policy())
                .on_before_asset_added_to_note(self.active_send_policy())
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
            .map(|(root, _)| (StorageMapKey::from_raw(*root), allowed_flag))
            .collect();
        StorageMap::with_entries(entries).expect("allowed policy roots should have unique keys")
    }

    fn to_manager_component(&self) -> AccountComponent {
        let storage_slots = self.manager_storage_slots();
        AccountComponent::new(
            POLICY_MANAGER_CODE.clone(),
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
    /// contributes its companion components once. `Custom` variants on any kind contribute no
    /// built-in components — the caller installs the matching components on the account
    /// separately.
    fn into_iter(self) -> Self::IntoIter {
        let manager_component = self.to_manager_component();
        let mut components = vec![manager_component];
        for (_, policy) in self.policies {
            components.extend(policy.components);
        }
        components.into_iter()
    }
}
