use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::component::{
    AccountComponentMetadata,
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
use crate::account::components::rbac_library;

static ROLE_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::rbac::role_config")
        .expect("storage slot name should be valid")
});
static ROLE_MEMBERSHIP_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::rbac::role_membership")
        .expect("storage slot name should be valid")
});

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleConfig {
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
/// Membership lookup.
///
/// `has_role` procedure is the primary guard used by procedures that assert
/// the caller's role membership. `get_role_member_count` returns the number of
/// accounts holding a role
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
///     exec.::miden::standards::access::rbac::assert_sender_has_role
///     # add mint logic
/// end
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBasedAccessControl {
    roles: BTreeMap<RoleSymbol, RoleConfig>,
}

impl RoleBasedAccessControl {
    pub const NAME: &'static str = "miden::standards::components::access::rbac";

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

    pub fn roles(&self) -> &BTreeMap<RoleSymbol, RoleConfig> {
        &self.roles
    }

    pub fn with_role(mut self, role: RoleSymbol) -> Self {
        self.roles.entry(role).or_default();
        self
    }

    /// Sets `admin_role` as the delegated admin of `role`.
    ///
    /// Both `role` and `admin_role` are recorded in the role map; if either was not previously
    /// configured it is created with a default (empty) configuration. To clear a previously
    /// configured admin, use [`Self::without_role_admin`].
    pub fn with_role_admin(mut self, role: RoleSymbol, admin_role: RoleSymbol) -> Self {
        self.roles.entry(admin_role.clone()).or_default();
        self.roles.entry(role).or_default().admin_role = Some(admin_role);
        self
    }

    /// Clears the delegated admin of `role`, leaving the role owner-managed.
    ///
    /// The role itself remains configured; only its admin assignment is removed.
    pub fn without_role_admin(mut self, role: RoleSymbol) -> Self {
        self.roles.entry(role).or_default().admin_role = None;
        self
    }

    pub fn with_role_member(mut self, role: RoleSymbol, account_id: AccountId) -> Self {
        self.roles.entry(role).or_default().members.insert(account_id);
        self
    }

    pub fn role_config_slot() -> &'static StorageSlotName {
        &ROLE_CONFIG_SLOT_NAME
    }

    pub fn role_membership_slot() -> &'static StorageSlotName {
        &ROLE_MEMBERSHIP_SLOT_NAME
    }

    pub fn role_config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::role_config_slot().clone(),
            StorageSlotSchema::map(
                "Per-role RBAC configuration (member count and delegated admin role)",
                SchemaType::role_symbol(),
                SchemaType::native_word(),
            ),
        )
    }

    pub fn role_membership_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::role_membership_slot().clone(),
            StorageSlotSchema::map(
                "Role membership flag indexed by role symbol and account ID",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            Self::role_config_slot_schema(),
            Self::role_membership_slot_schema(),
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
        let mut role_config_entries = Vec::new();
        let mut role_membership_entries = Vec::new();

        for (role_symbol, role_config) in &rbac.roles {
            let role_symbol_felt = Felt::from(role_symbol);
            let admin_role_felt =
                role_config.admin_role.as_ref().map(Felt::from).unwrap_or(Felt::ZERO);
            let member_count = role_config.members.len() as u64;

            // ROLE_CONFIG: [member_count, admin_role_symbol, 0, 0]
            role_config_entries.push((
                StorageMapKey::from_raw(Word::from([
                    Felt::ZERO,
                    Felt::ZERO,
                    Felt::ZERO,
                    role_symbol_felt,
                ])),
                Word::from([Felt::new(member_count), admin_role_felt, Felt::ZERO, Felt::ZERO]),
            ));

            // ROLE_MEMBERSHIP: [is_member, 0, 0, 0]
            for member in &role_config.members {
                role_membership_entries.push((
                    StorageMapKey::from_raw(Word::from([
                        Felt::ZERO,
                        role_symbol_felt,
                        member.suffix(),
                        member.prefix().as_felt(),
                    ])),
                    Word::from([Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
                ));
            }
        }

        let role_config_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_config_slot().clone(),
            StorageMap::with_entries(role_config_entries)
                .expect("role config entries should be unique"),
        );
        let role_membership_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_membership_slot().clone(),
            StorageMap::with_entries(role_membership_entries)
                .expect("role membership entries should be unique"),
        );

        AccountComponent::new(
            rbac_library(),
            vec![role_config_slot, role_membership_slot],
            RoleBasedAccessControl::component_metadata(),
        )
        .expect("RBAC component should satisfy the requirements of a valid account component")
    }
}
