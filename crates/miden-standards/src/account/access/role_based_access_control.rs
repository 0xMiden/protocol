use alloc::collections::{BTreeMap, BTreeSet};
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
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::RoleSymbol;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::components::role_based_access_control_library;

static ADMIN_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::role_based_access_control::admin_config")
        .expect("storage slot name should be valid")
});
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
static PENDING_ROLE_TRANSFERS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::access::role_based_access_control::pending_role_transfers",
    )
    .expect("storage slot name should be valid")
});

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleInit {
    pub admin_role: Option<RoleSymbol>,
    pub members: BTreeSet<AccountId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBasedAccessControl {
    admin: AccountId,
    roles: BTreeMap<RoleSymbol, RoleInit>,
}

impl RoleBasedAccessControl {
    pub const NAME: &'static str =
        "miden::standards::components::access::role_based_access_control";

    pub fn new(admin: AccountId) -> Self {
        Self { admin, roles: BTreeMap::new() }
    }

    pub fn admin(&self) -> AccountId {
        self.admin
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

    pub fn admin_config_slot() -> &'static StorageSlotName {
        &ADMIN_CONFIG_SLOT_NAME
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

    pub fn pending_role_transfers_slot() -> &'static StorageSlotName {
        &PENDING_ROLE_TRANSFERS_SLOT_NAME
    }

    pub fn admin_config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::admin_config_slot().clone(),
            StorageSlotSchema::value(
                "RBAC root admin and nominated admin",
                [
                    FeltSchema::felt("admin_suffix"),
                    FeltSchema::felt("admin_prefix"),
                    FeltSchema::felt("nominated_admin_suffix"),
                    FeltSchema::felt("nominated_admin_prefix"),
                ],
            ),
        )
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

    pub fn pending_role_transfers_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::pending_role_transfers_slot().clone(),
            StorageSlotSchema::map(
                "Pending role transfers keyed by role symbol and current holder",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            Self::admin_config_slot_schema(),
            Self::state_slot_schema(),
            Self::active_roles_slot_schema(),
            Self::role_configs_slot_schema(),
            Self::role_members_slot_schema(),
            Self::role_member_index_slot_schema(),
            Self::pending_role_transfers_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, AccountType::all())
            .with_description("Role-based access control component")
            .with_storage_schema(storage_schema)
    }
}

impl From<RoleBasedAccessControl> for AccountComponent {
    fn from(rbac: RoleBasedAccessControl) -> Self {
        let admin_config_slot = StorageSlot::with_value(
            RoleBasedAccessControl::admin_config_slot().clone(),
            Word::from([
                rbac.admin.suffix(),
                rbac.admin.prefix().as_felt(),
                Felt::ZERO,
                Felt::ZERO,
            ]),
        );

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
            let active_role_index_plus_one = if member_count > 0 {
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
                Felt::new(active_index + 1)
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
                    active_role_index_plus_one,
                    Felt::new(1),
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
                        Felt::new(member_index as u64 + 1),
                        Felt::ZERO,
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
            StorageMap::with_entries(active_role_entries.into_iter())
                .expect("active role entries should be unique"),
        );
        let role_configs_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_configs_slot().clone(),
            StorageMap::with_entries(role_config_entries.into_iter())
                .expect("role config entries should be unique"),
        );
        let role_members_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_members_slot().clone(),
            StorageMap::with_entries(role_member_entries.into_iter())
                .expect("role member entries should be unique"),
        );
        let role_member_index_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_member_index_slot().clone(),
            StorageMap::with_entries(role_member_index_entries.into_iter())
                .expect("role member index entries should be unique"),
        );
        let pending_role_transfers_slot = StorageSlot::with_map(
            RoleBasedAccessControl::pending_role_transfers_slot().clone(),
            StorageMap::default(),
        );

        AccountComponent::new(
            role_based_access_control_library(),
            vec![
                admin_config_slot,
                state_slot,
                active_roles_slot,
                role_configs_slot,
                role_members_slot,
                role_member_index_slot,
                pending_role_transfers_slot,
            ],
            RoleBasedAccessControl::component_metadata(),
        )
        .expect("RBAC component should satisfy the requirements of a valid account component")
    }
}
