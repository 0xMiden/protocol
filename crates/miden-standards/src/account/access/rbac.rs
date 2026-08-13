use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
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

use crate::account::{account_component_code, package_metadata};

account_component_code!(RBAC_CODE, "miden-standards-access-rbac.masp");

static ROLE_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::rbac::role_config")
        .expect("storage slot name should be valid")
});
static ROLE_MEMBERSHIP_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::rbac::role_membership")
        .expect("storage slot name should be valid")
});

// ROLE CONFIG
// ================================================================================================

/// A role configuration for the [`RoleBasedAccessControl`] component: the accounts holding the
/// role and the role administering it.
///
/// A config establishes the state that the `grant_role` and `set_role_admin` procedures would
/// otherwise have to reach on-chain, so an account can be created with its final role graph
/// already in place. A config is validated only once it is passed to the
/// [`RoleBasedAccessControl` builder][RoleBasedAccessControl::builder], which checks it against
/// the other roles; a `RoleConfig` on its own carries no guarantee of being usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleConfig {
    role: RoleSymbol,
    members: BTreeSet<AccountId>,
    admin: Option<RoleSymbol>,
}

impl RoleConfig {
    /// Returns an empty configuration for a new role.
    pub fn new(role: RoleSymbol) -> Self {
        Self {
            role,
            members: BTreeSet::new(),
            admin: None,
        }
    }

    /// Defines an admin for the role. `admin` delegates the role's administration to another role.
    /// Leaving it unset leaves the role administered by the built-in
    /// [`ADMIN`][RoleBasedAccessControl::ADMIN_ROLE] role.
    ///
    /// A role with a delegated admin but no members configures administration for a role that does
    /// not exist yet; the role starts existing once it is granted its first member.
    pub fn with_admin(mut self, admin: RoleSymbol) -> Self {
        self.admin = Some(admin);
        self
    }

    /// Adds the specified accounts to the role's member set.
    pub fn with_members(mut self, members: impl IntoIterator<Item = AccountId>) -> Self {
        self.members.extend(members);
        self
    }

    /// Adds a single account to this role's member set.
    pub fn with_member(mut self, member: AccountId) -> Self {
        self.members.insert(member);
        self
    }
}

impl RoleConfig {
    /// Returns the symbol of the role.
    pub fn role(&self) -> &RoleSymbol {
        &self.role
    }

    /// Returns the members set of the role.
    pub fn members(&self) -> &BTreeSet<AccountId> {
        &self.members
    }

    /// Returns the role administering the this role, or `None` if it is administered by the
    /// built-in [`ADMIN`][RoleBasedAccessControl::ADMIN_ROLE] role.
    pub fn admin(&self) -> Option<&RoleSymbol> {
        self.admin.as_ref()
    }
}

// ROLE BASED ACCESS CONTROL
// ================================================================================================

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
/// A component defined any role is configured with a live administration path for it (see
/// [`builder`][Self::builder]), which for a role left with the default admin means members of the
/// `ADMIN` role. The `ADMIN` role administers itself, so `ADMIN` membership can be granted,
/// revoked, and renounced through the standard API.
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
/// Both members and delegated admins can be configured at construction (see [`RoleConfig`]), which
/// establishes exclusive delegation atomically: a role configured with a delegated admin is never
/// reachable by `ADMIN`, not even transiently. Reaching the same configuration on an existing
/// account requires the sequence below, during which `ADMIN` still administers the role. That
/// window is also the only chance to repair a mistyped or hostile admin role, so a configured
/// delegation must be verified before account creation: initialization proves that *some* role can
/// administer the delegated role, never that the deployer controls it.
///
/// This supports a fully decentralized configuration: for each delegated role, (1) grant the
/// dedicated admin role's members, (2) make it self-administering (`set_role_admin(X, X)` —
/// only safe once `X` has members), (3) delegate the managed role to it, and (4) revoke or
/// renounce all bootstrap `ADMIN` members, waiting for each step to commit before issuing
/// the next. Emptying `ADMIN` is permanent and forfeits every `ADMIN`-defaulted capability
/// (the `Authority` procedure→role map is fixed at account creation), so an account whose
/// gated procedures are not all mapped to live roles must never empty `ADMIN`. A
/// self-administering role has no quorum — any single member can evict the rest — so its
/// members should themselves be strongly authenticated (e.g. multisig) accounts.
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
    /// The roles defined at construction, keyed by their symbol. May be empty, in which case the
    /// component starts with no administrator and no role members.
    roles: BTreeMap<RoleSymbol, RoleConfig>,
}

#[bon::bon]
impl RoleBasedAccessControl {
    /// Returns an RBAC component initialized with the given roles, each carrying its members and
    /// its delegated admin (see [`RoleConfig`]).
    ///
    /// Roles are added with the [`role`][RoleBasedAccessControlBuilder::role] and
    /// [`roles`][RoleBasedAccessControlBuilder::roles] setters. Initializing no role at all is
    /// allowed and produces a component with no roles and no administrator.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the same role is specified more than once.
    /// - a role is configured with neither members nor a delegated admin.
    /// - a role's member count exceeds [`u32::MAX`].
    /// - `ADMIN` is defined without members, or not defined at all, and a role's admin chain never
    ///   reaches a populated role, which would leave that role permanently unmanageable. A
    ///   populated `ADMIN` administers every role whose delegated admin is memberless, so it makes
    ///   any admin chain recoverable; without one, defining an operational role and no `ADMIN` is
    ///   the common defect, since `ADMIN` administers itself and nothing can ever populate it.
    #[builder]
    pub fn new(
        #[builder(field)] role_configs: Vec<RoleConfig>,
    ) -> Result<Self, RoleBasedAccessControlError> {
        let mut roles = BTreeMap::new();
        for config in role_configs {
            if config.members.is_empty() && config.admin.is_none() {
                return Err(RoleBasedAccessControlError::EmptyRoleConfig(config.role));
            }
            if u32::try_from(config.members.len()).is_err() {
                return Err(RoleBasedAccessControlError::MemberCountOverflow {
                    role: config.role,
                    member_count: config.members.len(),
                });
            }
            if roles.contains_key(&config.role) {
                return Err(RoleBasedAccessControlError::DuplicateRole(config.role));
            }
            roles.insert(config.role.clone(), config);
        }

        // A memberless role can authorize nothing, so authority over the roles it administers falls
        // back to `ADMIN` (see `assert_sender_is_role_admin`). A populated `ADMIN` therefore keeps
        // every role manageable, whatever its delegated admin looks like, and only a configuration
        // without one has to stand on its own admin chains.
        let admin_is_populated =
            roles.get(&Self::admin_role()).is_some_and(|config| !config.members.is_empty());
        if !admin_is_populated {
            for role_config in roles.values() {
                let admin = role_config.admin.clone().unwrap_or_else(Self::admin_role);
                if !reaches_populated_role(&admin, &roles) {
                    return Err(RoleBasedAccessControlError::UnmanageableRole {
                        role: role_config.role.clone(),
                        admin,
                    });
                }
            }
        }

        Ok(Self { roles })
    }
}

impl RoleBasedAccessControl {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::access::rbac";

    /// The built-in default admin role symbol. A role whose delegated admin is unset is
    /// administered by members of this role.
    ///
    /// Keep in sync with the `ADMIN_ROLE` constant in `asm/standards/access/rbac.masm`.
    pub const ADMIN_ROLE: &'static str = "ADMIN";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns an RBAC component whose built-in [`ADMIN`][Self::ADMIN_ROLE] role is configured
    /// with `admins` and which defines no other role.
    ///
    /// # Errors
    ///
    /// Returns an error if `admins` is empty, since the resulting component would have no
    /// administrator. Build such a component with the [`builder`][Self::builder] instead.
    pub fn with_admins(
        admins: impl IntoIterator<Item = AccountId>,
    ) -> Result<Self, RoleBasedAccessControlError> {
        Self::builder()
            .role(RoleConfig::new(Self::admin_role()).with_members(admins))
            .build()
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

    /// Returns the [`AccountComponentMetadata`] describing this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        package_metadata(Self::code())
    }
}

impl<S: role_based_access_control_builder::State> RoleBasedAccessControlBuilder<S> {
    /// Adds a single role to the component.
    pub fn role(mut self, config: RoleConfig) -> Self {
        self.role_configs.push(config);
        self
    }

    /// Adds multiple role to the component.
    pub fn roles(mut self, configs: impl IntoIterator<Item = RoleConfig>) -> Self {
        self.role_configs.extend(configs);
        self
    }
}

// HELPERS
// ================================================================================================

/// Returns `true` if walking the delegated-admin chain starting at `role` reaches a role defined
/// with at least one member.
///
/// Only relevant when `ADMIN` has no members: a populated `ADMIN` administers every role whose
/// delegated admin is memberless, which makes any chain recoverable. Without one, only a populated
/// role can grant members to the role below it in the chain, so a chain that reaches none of them
/// can never be acted on by anyone. A role that is not configured, or configured without members,
/// is administered by its delegated admin, defaulting to `ADMIN`. Every role has exactly one admin,
/// so the walk always ends in a cycle, which the visited set terminates.
fn reaches_populated_role(role: &RoleSymbol, configs: &BTreeMap<RoleSymbol, RoleConfig>) -> bool {
    let admin_role = RoleBasedAccessControl::admin_role();
    let mut visited = BTreeSet::new();
    let mut current = role.clone();

    while visited.insert(current.clone()) {
        current = match configs.get(&current) {
            Some(role) if !role.members.is_empty() => return true,
            Some(role) => role.admin.clone().unwrap_or_else(|| admin_role.clone()),
            None => admin_role.clone(),
        };
    }

    false
}

// CONVERSIONS
// ================================================================================================

impl From<RoleBasedAccessControl> for AccountComponent {
    fn from(rbac: RoleBasedAccessControl) -> Self {
        // Config, for every role:
        // - role_config:     [0, 0, 0, role] -> [member_count, admin_role, 0, 0]
        // - role_membership: [0, role, acct_suffix, acct_prefix] -> [1, 0, 0, 0]
        let mut config_entries = Vec::new();
        let mut membership_entries = Vec::new();
        for config in rbac.roles.into_values() {
            let role_symbol: Felt = config.role.as_element();
            let member_count = u32::try_from(config.members.len())
                .expect("member count is validated on initialization");
            let admin_symbol = config.admin.as_ref().map_or(Felt::ZERO, RoleSymbol::as_element);
            config_entries.push((
                StorageMapKey::new(Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, role_symbol])),
                Word::from([Felt::from(member_count), admin_symbol, Felt::ZERO, Felt::ZERO]),
            ));
            for member in config.members {
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
            .expect("config role membership map should be valid");
        let role_config_map = StorageMap::with_entries(config_entries)
            .expect("config role config map should be valid");

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

// ROLE BASED ACCESS CONTROL ERROR
// ================================================================================================

/// Errors that can occur when initializing the [`RoleBasedAccessControl`] component.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoleBasedAccessControlError {
    #[error("role {0} is defined more than once")]
    DuplicateRole(RoleSymbol),
    #[error("role {0} is defined with neither members nor a delegated admin")]
    EmptyRoleConfig(RoleSymbol),
    #[error(
        "role {role} is defined with {member_count} members which exceeds the maximum of {}",
        u32::MAX
    )]
    MemberCountOverflow { role: RoleSymbol, member_count: usize },
    #[error(
        "role {role} is defined with delegated admin {admin}, which can never hold members and so leaves {role} unmanageable"
    )]
    UnmanageableRole { role: RoleSymbol, admin: RoleSymbol },
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountType, StorageSlotContent};

    use super::*;

    fn test_admin(seed: u8) -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Private)
            .build_with_seed([seed; 32])
    }

    fn role(symbol: &str) -> RoleSymbol {
        RoleSymbol::new_unchecked(symbol)
    }

    /// Returns the role config map key of the given role.
    fn role_config_key(role: &RoleSymbol) -> StorageMapKey {
        StorageMapKey::new(Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, role.as_element()]))
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
    fn with_admins_sets_every_admin_and_the_member_count() -> anyhow::Result<()> {
        // Members are held in a `BTreeSet`, so duplicate account IDs collapse before this point
        // and the member count always matches the number of membership entries.
        let admins = [test_admin(1), test_admin(2), test_admin(3)];
        let component: AccountComponent = RoleBasedAccessControl::with_admins(admins)?.into();

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
        let member_count = u32::try_from(admins.len())?;
        assert_eq!(
            config.get(&role_config_key(&RoleBasedAccessControl::admin_role())),
            Word::from([Felt::from(member_count), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        );

        Ok(())
    }

    #[test]
    fn with_admins_rejects_an_empty_member_set() {
        let error =
            RoleBasedAccessControl::with_admins([]).expect_err("initialization should have failed");

        assert_eq!(
            error,
            RoleBasedAccessControlError::EmptyRoleConfig(RoleBasedAccessControl::admin_role())
        );
    }

    #[test]
    fn defining_no_role_defines_no_admin() -> anyhow::Result<()> {
        let component: AccountComponent = RoleBasedAccessControl::builder().build()?.into();

        // No membership entries and an empty config: the component starts with no administrator.
        let membership = find_map(&component, RoleBasedAccessControl::role_membership_slot());
        assert_eq!(membership.num_entries(), 0);
        let config = find_map(&component, RoleBasedAccessControl::role_config_slot());
        assert_eq!(config.num_entries(), 0);

        Ok(())
    }

    /// A delegated admin is defined in the role config, which places the role out of `ADMIN`'s
    /// reach without any on-chain `set_role_admin`.
    #[test]
    fn defining_delegated_admin_is_written_to_the_role_config() -> anyhow::Result<()> {
        let admin = test_admin(1);
        let manager = test_admin(2);
        let pauser = test_admin(3);

        let manager_role = RoleSymbol::new("DOM_MANAGER")?;
        let pauser_role = RoleSymbol::new("DOM_PAUSER")?;

        let component: AccountComponent = RoleBasedAccessControl::builder()
            .role(
                RoleConfig::new(RoleBasedAccessControl::admin_role()).with_member(admin),
            )
            // DOM_MANAGER administers itself, so ADMIN cannot rotate its membership.
            .role(
                RoleConfig::new(manager_role.clone()).with_member(manager)
                    .with_admin(manager_role.clone())
            )
            .role(
                RoleConfig::new(pauser_role.clone()).with_member(pauser)
                    .with_admin(manager_role.clone())
            )
            .build()?
            .into();

        let config = find_map(&component, RoleBasedAccessControl::role_config_slot());
        let manager_symbol = manager_role.as_element();
        assert_eq!(
            config.get(&role_config_key(&manager_role)),
            Word::from([Felt::ONE, manager_symbol, Felt::ZERO, Felt::ZERO]),
        );
        assert_eq!(
            config.get(&role_config_key(&pauser_role)),
            Word::from([Felt::ONE, manager_symbol, Felt::ZERO, Felt::ZERO]),
        );

        Ok(())
    }

    /// Delegating the admin of a role that has no members yet is what `set_role_admin` does on an
    /// existing account, so initializing it must be expressible too.
    #[test]
    fn role_initialized_without_members_holds_its_delegated_admin() -> anyhow::Result<()> {
        let admin = test_admin(1);
        let minter_role = RoleSymbol::new("MINTER")?;
        let minter_admin_role = RoleBasedAccessControl::admin_role();

        let component: AccountComponent = RoleBasedAccessControl::builder()
            .role(RoleConfig::new(minter_admin_role.clone()).with_member(admin))
            .role(RoleConfig::new(minter_role.clone()).with_admin(minter_admin_role))
            .build()?
            .into();

        // The role has a config entry but no members, so it does not exist yet.
        let config = find_map(&component, RoleBasedAccessControl::role_config_slot());
        assert_eq!(
            config.get(&role_config_key(&minter_role)),
            Word::from([
                Felt::ZERO,
                RoleBasedAccessControl::admin_role().as_element(),
                Felt::ZERO,
                Felt::ZERO
            ]),
        );
        let membership = find_map(&component, RoleBasedAccessControl::role_membership_slot());
        assert_eq!(membership.num_entries(), 1);

        Ok(())
    }

    /// A populated `ADMIN` administers every role whose delegated admin is memberless, so even an
    /// admin chain that reaches no populated role of its own leaves the role manageable.
    #[test]
    fn populated_admin_allows_an_otherwise_unmanageable_delegation() -> anyhow::Result<()> {
        let admin = test_admin(1);
        let minter_role = RoleSymbol::new("MINTER")?;
        let minter_admin_role = RoleSymbol::new("MINTER_ADMIN")?;

        // MINTER_ADMIN administers itself and has no members, so nothing in MINTER's chain can be
        // populated by the chain itself — ADMIN takes over administering both.
        RoleBasedAccessControl::builder()
            .role(RoleConfig::new(RoleBasedAccessControl::admin_role()).with_member(admin))
            .role(RoleConfig::new(minter_role).with_admin(minter_admin_role.clone()))
            .role(RoleConfig::new(minter_admin_role.clone()).with_admin(minter_admin_role))
            .build()?;

        Ok(())
    }

    /// A role whose delegated admin is empty is still manageable as long as the admin itself can
    /// be populated, which is the case while `ADMIN` is populated.
    #[test]
    fn delegating_to_a_role_populated_later_is_allowed() -> anyhow::Result<()> {
        let admin = test_admin(1);
        let minter_role = RoleSymbol::new("MINTER")?;
        let minter_admin_role = RoleSymbol::new("MINTER_ADMIN")?;

        RoleBasedAccessControl::builder()
            .role(RoleConfig::new(RoleBasedAccessControl::admin_role()).with_member(admin))
            .role(RoleConfig::new(minter_role).with_admin(minter_admin_role))
            .build()?;

        Ok(())
    }

    #[rstest::rstest]
    #[case::duplicate_role(
        vec![
            RoleConfig::new(role("MINTER")).with_member(test_admin(1)),
            RoleConfig::new(role("MINTER")).with_member(test_admin(2)),
        ],
        RoleBasedAccessControlError::DuplicateRole(role("MINTER")),
    )]
    #[case::empty_config(
        vec![RoleConfig::new(role("MINTER"))],
        RoleBasedAccessControlError::EmptyRoleConfig(role("MINTER")),
    )]
    // MINTER delegates to a self-administering role that has no members, so nobody can ever
    // populate MINTER_ADMIN and MINTER stays unmanageable.
    #[case::unmanageable_role(
        vec![
            RoleConfig::new(role("MINTER")).with_admin(role("MINTER_ADMIN")),
            RoleConfig::new(role("MINTER_ADMIN")).with_admin(role("MINTER_ADMIN")),
        ],
        RoleBasedAccessControlError::UnmanageableRole {
            role: role("MINTER"),
            admin: role("MINTER_ADMIN"),
        },
    )]
    #[case::empty_admins(
        vec![RoleConfig::new(RoleBasedAccessControl::admin_role())],
        RoleBasedAccessControlError::EmptyRoleConfig(RoleBasedAccessControl::admin_role()),
    )]
    // Leaving MINTER's admin unset makes ADMIN administer it, but ADMIN administers itself, so an
    // unspecified ADMIN can never hold members. This is the same defect as `unmanageable_role`,
    // spelled implicitly.
    #[case::unspecified_default_admin(
        vec![RoleConfig::new(role("MINTER")).with_member(test_admin(1))],
        RoleBasedAccessControlError::UnmanageableRole {
            role: role("MINTER"),
            admin: RoleBasedAccessControl::admin_role(),
        },
    )]
    fn invalid_role_configs_are_rejected(
        #[case] configs: Vec<RoleConfig>,
        #[case] expected: RoleBasedAccessControlError,
    ) {
        let error = RoleBasedAccessControl::builder()
            .roles(configs)
            .build()
            .expect_err("initialization should have failed");

        assert_eq!(error, expected);
    }
}
