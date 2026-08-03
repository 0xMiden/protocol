use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

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
    AccountId,
    RoleSymbol,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::account_component_code;

account_component_code!(RBAC_CODE, "miden-standards-access-rbac.masp");

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
/// Instead of having one account holding every privilege, privileges are split into named
/// roles (for example `MINTER`, `BURNER`, `PAUSER`), and each procedure is guarded against
/// the caller's role membership. It allows role assignment with domain isolation to minimize
/// the scope of damage from a compromised role.
///
/// ## Security considerations
///
/// Access control is based on the note sender (the account ID that created the note), which
/// authenticates *which account* created a note but not the *code* that executed when it was
/// created. It is meaningful only when every account registered as a role member enforces
/// strong authentication. Registering a permissionless account (for example one using `no_auth`)
/// as a role member provides no access restriction: anyone can make such an account emit a
/// note with an arbitrary script root and that account's ID as sender, defeating the sender check.
///
/// ## Administration model
///
/// Role administration is fully role-based. Every role has an *effective admin role*:
/// its configured delegated admin when set, otherwise the built-in
/// [`ADMIN`][Self::ADMIN_ROLE] role. Only members of a role's effective admin role may grant,
/// revoke, or re-point (`set_role_admin`) that role.
///
/// The component is seeded at construction with one or more members of the `ADMIN` role (see
/// [`new`][Self::new]); this bootstraps administration. The `ADMIN` role administers itself, so
/// `ADMIN` membership can be granted, revoked, and renounced through the standard API.
///
/// ## Role hierarchy and exclusive delegation
///
/// Every role may have its admin delegated to another role via `set_role_admin`. Accounts
/// holding a role's admin role are authorized to grant and revoke that role. For example,
/// accounts holding `MINTER_ADMIN` can manage the `MINTER` role but have no authority over
/// `BURNER` or `PAUSER`.
///
/// Delegation is *exclusive* while the delegated admin role is populated: the `ADMIN` role then
/// has no authority over the delegated role (grant, revoke, and further `set_role_admin` are
/// gated on the delegated admin). This lets a sensitive role — say a token issuer — be placed
/// exclusively under a dedicated admin role and kept out of reach of the general
/// administrator. To hand authority back, the current delegated admin re-points the role
/// (passing `0` reverts it to the `ADMIN` role).
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBasedAccessControl {
    /// Accounts seeded as members of the built-in [`ADMIN`][Self::ADMIN_ROLE] role at
    /// construction. Bootstraps role administration; may be empty for an account that seeds
    /// `ADMIN` membership by other means, but such a component starts with no administrator.
    initial_admins: BTreeSet<AccountId>,
    /// Additional roles seeded at construction, keyed by role symbol. Each seeded role's
    /// delegated admin is left unset, so it is administered by the `ADMIN` role (see
    /// [`with_role_members`][Self::with_role_members]).
    initial_role_members: BTreeMap<RoleSymbol, BTreeSet<AccountId>>,
}

impl RoleBasedAccessControl {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::access::rbac";

    /// The built-in default admin role symbol. A role whose delegated admin is unset is
    /// administered by members of this role.
    ///
    /// Keep in sync with the `ADMIN_ROLE` constant in `asm/standards/access/rbac.masm`.
    pub const ADMIN_ROLE: &'static str = "ADMIN";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns an RBAC component whose `ADMIN` role is seeded with `initial_admins` and whose
    /// additional roles are each seeded with the given `role_members` set at construction.
    ///
    /// Each seeded role's delegated admin is left unset, so — like any role — it is administered
    /// by the `ADMIN` role until an admin is delegated via `set_role_admin`. This lets an account
    /// be created already populated with role holders alongside the bootstrap administrator. A role
    /// mapped to an empty member set is dropped: a role with no members is a no-op.
    pub fn new(
        initial_admins: BTreeSet<AccountId>,
        role_members: BTreeMap<RoleSymbol, BTreeSet<AccountId>>,
    ) -> Self {
        Self {
            initial_admins,
            initial_role_members: role_members,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the built-in default admin [`RoleSymbol`].
    pub fn admin_role() -> RoleSymbol {
        RoleSymbol::new(Self::ADMIN_ROLE).expect("ADMIN is a valid role symbol")
    }

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &RBAC_CODE
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

        AccountComponentMetadata::new(Self::NAME)
            .with_description("Role-based access control component")
            .with_storage_schema(storage_schema)
    }
}

impl From<RoleBasedAccessControl> for AccountComponent {
    fn from(rbac: RoleBasedAccessControl) -> Self {
        // Combine the seeded ADMIN members with any additional seeded roles into a single
        // role -> members map. Each seeded role (including ADMIN) leaves its delegated admin unset
        // (0), so ADMIN administers it. Members provided for the `ADMIN` role are merged with
        // `initial_admins`.
        let mut roles = rbac.initial_role_members;
        if !rbac.initial_admins.is_empty() {
            roles
                .entry(RoleBasedAccessControl::admin_role())
                .or_default()
                .extend(rbac.initial_admins);
        }

        // Seed, for every non-empty role:
        // - role_config:     [0, 0, 0, role] -> [member_count, 0, 0, 0]
        // - role_membership: [0, role, acct_suffix, acct_prefix] -> [1, 0, 0, 0]
        let mut config_entries = Vec::new();
        let mut membership_entries = Vec::new();
        for (role, members) in &roles {
            if members.is_empty() {
                continue;
            }
            let role_symbol: Felt = role.as_element();
            let member_count =
                u32::try_from(members.len()).expect("role member count should fit in u32");
            config_entries.push((
                StorageMapKey::new(Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, role_symbol])),
                Word::from([Felt::from(member_count), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            ));
            for member in members {
                membership_entries.push((
                    StorageMapKey::new(Word::from([
                        Felt::ZERO,
                        role_symbol,
                        member.suffix(),
                        member.prefix().as_felt(),
                    ])),
                    Word::from([Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
                ));
            }
        }

        let role_membership_map = StorageMap::with_entries(membership_entries)
            .expect("seeded role membership map should be valid");
        let role_config_map = StorageMap::with_entries(config_entries)
            .expect("seeded role config map should be valid");

        let role_config_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_config_slot().clone(),
            role_config_map,
        );
        let role_membership_slot = StorageSlot::with_map(
            RoleBasedAccessControl::role_membership_slot().clone(),
            role_membership_map,
        );

        AccountComponent::new(
            RoleBasedAccessControl::code().clone(),
            vec![role_config_slot, role_membership_slot],
            RoleBasedAccessControl::component_metadata(),
        )
        .expect("RBAC component should satisfy the requirements of a valid account component")
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountType, StorageSlotContent};

    use super::*;

    fn test_admin(seed: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Private)
            .build_with_seed([seed; 32])
    }

    /// Returns the map content of the component's storage slot with the given name.
    fn find_map<'a>(
        component: &'a AccountComponent,
        slot_name: &StorageSlotName,
    ) -> &'a StorageMap {
        let slot = component
            .storage_slots()
            .iter()
            .find(|slot| slot.name() == slot_name)
            .expect("component should register the slot");
        match slot.content() {
            StorageSlotContent::Map(map) => map,
            _ => panic!("slot {slot_name} should be a map"),
        }
    }

    #[test]
    fn admin_role_encoding_matches_masm_constant() {
        // Must stay in sync with `const ADMIN_ROLE` in asm/standards/access/rbac.masm.
        const MASM_ADMIN_ROLE: u64 = 1836707;
        assert_eq!(
            RoleBasedAccessControl::admin_role().as_element().as_canonical_u64(),
            MASM_ADMIN_ROLE,
        );
    }

    #[test]
    fn with_admins_seeds_every_admin_and_the_member_count() {
        // `initial_admins` is a `BTreeSet`, so duplicate account IDs collapse before this point
        // and the member count always matches the number of membership entries.
        let admins = [test_admin(1), test_admin(2), test_admin(3)];
        let component: AccountComponent =
            RoleBasedAccessControl::new(admins.iter().copied().collect(), BTreeMap::default())
                .into();

        let admin_symbol = RoleBasedAccessControl::admin_role().as_element();

        let membership = find_map(&component, RoleBasedAccessControl::role_membership_slot());
        assert_eq!(membership.num_entries(), admins.len());
        for admin in admins {
            let key = StorageMapKey::new(Word::from([
                Felt::ZERO,
                admin_symbol,
                admin.suffix(),
                admin.prefix().as_felt(),
            ]));
            assert_eq!(
                membership.get(&key),
                Word::from([Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO])
            );
        }

        let config = find_map(&component, RoleBasedAccessControl::role_config_slot());
        let config_key =
            StorageMapKey::new(Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, admin_symbol]));
        let member_count = u32::try_from(admins.len()).unwrap();
        assert_eq!(
            config.get(&config_key),
            Word::from([Felt::from(member_count), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        );
    }

    #[test]
    fn with_admins_empty_seeds_no_admin() {
        let component: AccountComponent =
            RoleBasedAccessControl::new(BTreeSet::default(), BTreeMap::default()).into();

        // No membership entries and an empty config: the component starts with no administrator.
        let membership = find_map(&component, RoleBasedAccessControl::role_membership_slot());
        assert_eq!(membership.num_entries(), 0);
        let config = find_map(&component, RoleBasedAccessControl::role_config_slot());
        assert_eq!(config.num_entries(), 0);
    }
}
