use alloc::vec;

use miden_protocol::account::component::{
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountType,
    StorageMap,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;

use crate::account::components::rbac_library;

static ROLE_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::rbac::role_config")
        .expect("storage slot name should be valid")
});
static ROLE_MEMBERSHIP_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::rbac::role_membership")
        .expect("storage slot name should be valid")
});

/// Role-based access control (RBAC) for account components.
///
/// RBAC provides fine-grained access control on top of [`Ownable2Step`]. Instead of having
/// one account holding every privilege, privileges are split into named roles (for example
/// `MINTER`, `BURNER`, `PAUSER`), and each procedure is guarded against the caller's role
/// membership. It allows role assignment with domain isolation to minimize the scope of
/// damage from a compromised role.
///
/// ## Relation to [`Ownable2Step`]
///
/// RBAC is a superset of [`Ownable2Step`] and depends on it: the top-level authority is
/// the [`Ownable2Step`] owner of the account. Build the pair via
/// [`AccessControl::Rbac`][crate::account::access::AccessControl::Rbac] passed to
/// [`AccountBuilder::with_components`][miden_protocol::account::AccountBuilder::with_components].
/// This avoids duplicated state, duplicated 2-step transfer logic, and duplicated notes
/// for owner transfers. If you only need single-account control, use [`Ownable2Step`]
/// alone.
///
/// [`Ownable2Step`]: crate::account::access::Ownable2Step
///
/// ## Owner management
///
/// The owner can grant and revoke any role, configure the delegated admin of any role via
/// `set_role_admin`, and transfer or renounce its own position. Owner transfer and
/// renouncement go through [`Ownable2Step`] (`transfer_ownership`, `accept_ownership`,
/// `renounce_ownership`).
///
/// ## Role hierarchy
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
/// ## Role semantics
///
/// A role is considered to exist when it has at least one member. Granting the first
/// member creates the role; revoking the last member removes it. As a consequence,
/// `set_role_admin(A, B)` stores the admin relationship in storage but does not make role
/// `A` exist until a member is granted. Once the last member of `A` is revoked,
/// `get_role_member_count(A)` returns `0`, though the admin configuration is retained and
/// will apply the next time a member is granted.
///
/// ## Membership lookup
///
/// `has_role` procedure is the primary guard used by procedures that assert the caller's
/// role membership. `get_role_member_count` returns the number of accounts holding a role.
///
/// ## Role symbol format
///
/// A [`RoleSymbol`] encodes up to 12 uppercase ASCII characters with underscores into a
/// single field element using the same packing as the token symbol type. Examples:
/// `MINTER`, `MINTER_ADMIN`, `PAUSER`. The zero field element is reserved and cannot be
/// used as a role symbol; attempting to do so panics with `ERR_ROLE_SYMBOL_ZERO`.
///
/// ## Usage
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
///
/// [`RoleSymbol`]: miden_protocol::account::RoleSymbol
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleBasedAccessControl;

impl RoleBasedAccessControl {
    pub const NAME: &'static str = "miden::standards::components::access::rbac";

    /// Returns an empty RBAC component. Roles are populated at runtime via the
    /// `grant_role`, `set_role_admin`, etc. procedures exposed by the component.
    pub fn empty() -> Self {
        Self
    }

    /// Returns the storage slot name for the per-role config map.
    pub fn role_config_slot() -> &'static StorageSlotName {
        &ROLE_CONFIG_SLOT_NAME
    }

    /// Returns the storage slot name for the per-role membership map.
    pub fn role_membership_slot() -> &'static StorageSlotName {
        &ROLE_MEMBERSHIP_SLOT_NAME
    }

    /// Returns the schema entry for the per-role config map.
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

    /// Returns the schema entry for the per-role membership map.
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

    /// Returns the [`AccountComponentMetadata`] describing this component.
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

impl From<RoleBasedAccessControl> for AccountComponent {
    fn from(_rbac: RoleBasedAccessControl) -> Self {
        let role_config_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_config_slot().clone(),
            StorageMap::with_entries(vec![]).expect("empty role config map should be valid"),
        );
        let role_membership_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_membership_slot().clone(),
            StorageMap::with_entries(vec![]).expect("empty role membership map should be valid"),
        );

        AccountComponent::new(
            rbac_library(),
            vec![role_config_slot, role_membership_slot],
            RoleBasedAccessControl::component_metadata(),
        )
        .expect("RBAC component should satisfy the requirements of a valid account component")
    }
}
