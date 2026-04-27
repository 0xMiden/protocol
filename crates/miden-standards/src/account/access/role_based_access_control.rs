use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountId,
    AccountType,
    RoleSymbol,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::access::Ownable2Step;
use crate::account::components::role_based_access_control_library;

static RBAC_STATE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::role_based_access_control::state")
        .expect("storage slot name should be valid")
});
static ACTIVE_ROLES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::role_based_access_control::active_roles")
        .expect("storage slot name should be valid")
});
static ROLE_CONFIGS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::role_based_access_control::role_config")
        .expect("storage slot name should be valid")
});
static ROLE_MEMBERS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::role_based_access_control::role_members")
        .expect("storage slot name should be valid")
});
static ROLE_MEMBER_INDEX_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::role_based_access_control::role_member_index")
        .expect("storage slot name should be valid")
});

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleInit {
    pub admin_role: Option<RoleSymbol>,
    pub members: BTreeSet<AccountId>,
}

/// Role-based access control (RBAC) for account components.
///
/// RBAC provides fine-grained access control on top of [`Ownable2Step`]. Instead of having
/// one account holding every privilege, privileges are split into named roles (for example
/// `MINTER`, `BURNER`, `PAUSER`), and each procedure is guarded against the caller's role
/// membership. It allows role assignment with domain isolation to minimize the scope of
/// damage from a compromised role.
///
/// Relation to [`Ownable2Step`].
///
/// RBAC is a superset of [`Ownable2Step`] and depends on it: the top-level authority
/// (previously called the "admin") is the [`Ownable2Step`] owner of the account. Use
/// `RoleBasedAccessControl::with_owner` to build the pair of components together; this
/// avoids duplicated state, duplicated 2-step transfer logic, and duplicated notes for
/// owner / admin transfers. If you only need single-account control, use [`Ownable2Step`]
/// alone.
///
/// Owner management.
///
/// The owner can grant and revoke any role, configure the delegated admin of any role via
/// `set_role_admin`, and transfer or renounce its own position. Owner transfer and
/// renouncement go through [`Ownable2Step`] (`transfer_ownership`, `accept_ownership`,
/// `renounce_ownership`).
///
/// Role hierarchy.
///
/// Every role may optionally have a delegated admin role. Accounts holding a role's admin
/// role are authorized to grant and revoke that role without going through the owner.
/// For example, accounts holding `MINTER_ADMIN` can manage the `MINTER` role but have no
/// authority over `BURNER` or `PAUSER`. This lets responsibilities be distributed so that
/// compromise of one domain does not spill into the others.
///
/// Combined with owner renouncement, this supports a fully decentralized configuration:
/// once every role has its own admin role populated, the owner can renounce and the
/// system continues to operate with each role managed only by its designated admin role.
///
/// The delegated admin of a role can itself be any role, including one that it admins.
/// Circular relationships are possible but should be designed with care, since each role
/// can then revoke the other.
///
/// Role semantics.
///
/// A role is considered to exist when it has at least one member. Granting the first
/// member creates the role; revoking the last member removes it. As a consequence,
/// `set_role_admin(A, B)` stores the admin relationship in storage but does not make role
/// `A` exist until a member is granted. Once the last member of `A` is revoked,
/// `role_exists(A)` returns `false`, though the admin configuration is retained and will
/// apply the next time a member is granted.
///
/// Role enumeration.
///
/// Three distinct lookup paths are maintained. `has_role(role, account)` is the primary
/// guard used by procedures that assert the caller's role membership.
/// `get_role_member(role, index)` iterates over all accounts currently holding a role and
/// serves on-chain consumers that need to walk a role's membership without relying on an
/// off-chain indexer. `get_active_role(index)` iterates over all roles that currently
/// have at least one member.
///
/// Role symbol format.
///
/// A role symbol is a [`RoleSymbol`], which encodes up to 12 uppercase ASCII characters
/// with underscores into a single field element using the same packing as the token
/// symbol type. Examples: `MINTER`, `MINTER_ADMIN`, `PAUSER`. The zero field element is
/// reserved and cannot be used as a role symbol; attempting to do so panics with
/// `ERR_ROLE_SYMBOL_ZERO`.
///
/// Guarding a procedure in MASM so that only members of `MINTER` can call it:
///
/// ```text
/// pub proc mint
///     push.MINTER_ROLE_SYMBOL
///     exec.::miden::standards::access::role_based_access_control::assert_sender_has_role
///     # add mint logic
/// end
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBasedAccessControl {
    roles: BTreeMap<RoleSymbol, RoleInit>,
}

impl RoleBasedAccessControl {
    pub const NAME: &'static str =
        "miden::standards::components::access::role_based_access_control";

    pub fn new() -> Self {
        Self { roles: BTreeMap::new() }
    }

    /// Returns the pair of components needed to use RBAC: an [`Ownable2Step`] component
    /// configured with `owner` (the top-level authority for the account) and the RBAC
    /// component itself.
    ///
    /// RBAC depends on [`Ownable2Step`] for owner management, so both components must be
    /// installed together. This is the recommended entry point for building an RBAC-enabled
    /// account.
    pub fn with_owner(owner: AccountId) -> Vec<AccountComponent> {
        vec![Ownable2Step::new(owner).into(), Self::new().into()]
    }

    pub fn roles(&self) -> &BTreeMap<RoleSymbol, RoleInit> {
        &self.roles
    }

    pub fn with_role(mut self, role: RoleSymbol) -> Self {
        self.roles.entry(role).or_default();
        self
    }

    pub fn with_role_admin(mut self, role: RoleSymbol, admin_role: Option<RoleSymbol>) -> Self {
        if let Some(admin_role) = admin_role.as_ref() {
            self.roles.entry(admin_role.clone()).or_default();
        }

        self.roles.entry(role).or_default().admin_role = admin_role;
        self
    }

    pub fn with_role_member(mut self, role: RoleSymbol, account_id: AccountId) -> Self {
        self.roles.entry(role).or_default().members.insert(account_id);
        self
    }

    pub fn state_slot() -> &'static StorageSlotName {
        &RBAC_STATE_SLOT_NAME
    }

    pub fn active_roles_slot() -> &'static StorageSlotName {
        &ACTIVE_ROLES_SLOT_NAME
    }

    pub fn role_configs_slot() -> &'static StorageSlotName {
        &ROLE_CONFIGS_SLOT_NAME
    }

    pub fn role_members_slot() -> &'static StorageSlotName {
        &ROLE_MEMBERS_SLOT_NAME
    }

    pub fn role_member_index_slot() -> &'static StorageSlotName {
        &ROLE_MEMBER_INDEX_SLOT_NAME
    }

    pub fn state_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::state_slot().clone(),
            StorageSlotSchema::value(
                "RBAC global state",
                [
                    FeltSchema::felt("active_role_count"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    pub fn active_roles_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::active_roles_slot().clone(),
            StorageSlotSchema::map(
                "Active roles indexed by active role position",
                SchemaType::native_felt(),
                SchemaType::role_symbol(),
            ),
        )
    }

    pub fn role_configs_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::role_configs_slot().clone(),
            StorageSlotSchema::map(
                "Per-role RBAC configuration",
                SchemaType::role_symbol(),
                SchemaType::native_word(),
            ),
        )
    }

    pub fn role_members_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::role_members_slot().clone(),
            StorageSlotSchema::map(
                "Role members indexed by role symbol and member index",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    pub fn role_member_index_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::role_member_index_slot().clone(),
            StorageSlotSchema::map(
                "Role member reverse index lookup",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            Self::state_slot_schema(),
            Self::active_roles_slot_schema(),
            Self::role_configs_slot_schema(),
            Self::role_members_slot_schema(),
            Self::role_member_index_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, AccountType::all())
            .with_description("Role-based access control component")
            .with_storage_schema(storage_schema)
    }
}

impl Default for RoleBasedAccessControl {
    fn default() -> Self {
        Self::new()
    }
}

impl From<RoleBasedAccessControl> for AccountComponent {
    fn from(rbac: RoleBasedAccessControl) -> Self {
        let mut active_role_entries = Vec::new();
        let mut role_config_entries = Vec::new();
        let mut role_member_entries = Vec::new();
        let mut role_member_index_entries = Vec::new();
        let mut active_role_count = 0u64;

        for (role_symbol, role_init) in &rbac.roles {
            let role_symbol_felt = Felt::from(role_symbol);
            let admin_role_felt =
                role_init.admin_role.as_ref().map(Felt::from).unwrap_or(Felt::ZERO);
            let member_count = role_init.members.len() as u64;
            let active_role_index = if member_count > 0 {
                let active_index = active_role_count;
                active_role_entries.push((
                    StorageMapKey::from_raw(Word::from([
                        Felt::ZERO,
                        Felt::ZERO,
                        Felt::ZERO,
                        Felt::new(active_index),
                    ])),
                    Word::from([role_symbol_felt, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
                ));
                active_role_count += 1;
                Felt::new(active_index)
            } else {
                Felt::ZERO
            };

            role_config_entries.push((
                StorageMapKey::from_raw(Word::from([
                    Felt::ZERO,
                    Felt::ZERO,
                    Felt::ZERO,
                    role_symbol_felt,
                ])),
                Word::from([
                    Felt::new(member_count),
                    admin_role_felt,
                    active_role_index,
                    Felt::ZERO,
                ]),
            ));

            for (member_index, member) in role_init.members.iter().enumerate() {
                role_member_entries.push((
                    StorageMapKey::from_raw(Word::from([
                        Felt::ZERO,
                        Felt::ZERO,
                        role_symbol_felt,
                        Felt::new(member_index as u64),
                    ])),
                    Word::from([
                        member.suffix(),
                        member.prefix().as_felt(),
                        Felt::ZERO,
                        Felt::ZERO,
                    ]),
                ));
                role_member_index_entries.push((
                    StorageMapKey::from_raw(Word::from([
                        Felt::ZERO,
                        role_symbol_felt,
                        member.suffix(),
                        member.prefix().as_felt(),
                    ])),
                    Word::from([
                        Felt::new(1),
                        Felt::new(member_index as u64),
                        Felt::ZERO,
                        Felt::ZERO,
                    ]),
                ));
            }
        }

        let state_slot = StorageSlot::with_value(
            RoleBasedAccessControl::state_slot().clone(),
            Word::from([Felt::new(active_role_count), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        );
        let active_roles_slot = StorageSlot::with_map(
            RoleBasedAccessControl::active_roles_slot().clone(),
            StorageMap::with_entries(active_role_entries)
                .expect("active role entries should be unique"),
        );
        let role_configs_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_configs_slot().clone(),
            StorageMap::with_entries(role_config_entries)
                .expect("role config entries should be unique"),
        );
        let role_members_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_members_slot().clone(),
            StorageMap::with_entries(role_member_entries)
                .expect("role member entries should be unique"),
        );
        let role_member_index_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_member_index_slot().clone(),
            StorageMap::with_entries(role_member_index_entries)
                .expect("role member index entries should be unique"),
        );

        AccountComponent::new(
            role_based_access_control_library(),
            vec![
                state_slot,
                active_roles_slot,
                role_configs_slot,
                role_members_slot,
                role_member_index_slot,
            ],
            RoleBasedAccessControl::component_metadata(),
        )
        .expect("RBAC component should satisfy the requirements of a valid account component")
    }
}
