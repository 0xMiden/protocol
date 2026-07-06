use alloc::collections::BTreeMap;
use alloc::vec;

use miden_protocol::account::{AccountComponent, AccountId, AccountProcedureRoot, RoleSymbol};

pub mod authority;
pub mod ownable2step;
pub mod pausable;
pub mod rbac;

/// Access control configuration for network-style accounts whose authority-gated setters are
/// gated by an owner / role check rather than by the account's auth component.
///
/// User-account faucets (where the auth component is itself the setter gate) install
/// [`Authority::AuthControlled`] directly via factories like
/// [`create_singlesig_user_fungible_faucet`][crate::account::faucets::create_singlesig_user_fungible_faucet];
/// they do not need this enum.
///
/// - [`AccessControl::Ownable2Step`] → [`Ownable2Step`] + [`Authority::OwnerControlled`]. The
///   setter gate enforces `sender == owner`.
/// - [`AccessControl::Rbac`] → [`Ownable2Step`] + [`RoleBasedAccessControl`] +
///   [`Authority::RbacControlled`]. The `roles` map assigns a role to individual gated procedures
///   (keyed by procedure root); procedures without a mapping fall back to the `owner` check.
///
/// Pass to
/// [`AccountBuilder::with_components`][miden_protocol::account::AccountBuilder::with_components]
/// to install the access control components on the account:
///
/// ```no_run
/// use std::collections::BTreeMap;
///
/// use miden_protocol::account::AccountBuilder;
/// use miden_standards::account::access::AccessControl;
/// # let owner: miden_protocol::account::AccountId = unimplemented!();
/// # let init_seed = [0u8; 32];
/// AccountBuilder::new(init_seed)
///     .with_components(AccessControl::Rbac { owner, roles: BTreeMap::new() });
/// ```
///
/// For accounts that don't use the [`AccessControl`] convenience but want to install the
/// [`Authority`] component directly, the [`Authority`] enum can be passed via
/// [`AccountBuilder::with_component`][miden_protocol::account::AccountBuilder::with_component].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessControl {
    /// Two-step ownership transfer with the provided initial owner. The setter gate enforces
    /// `sender == owner`.
    Ownable2Step { owner: AccountId },
    /// Role-based access control. Includes [`Ownable2Step`] internally. The provided `owner` is
    /// the account's [`Ownable2Step`] owner (used for the emergency freeze switch and as the
    /// fallback authority for gated procedures without a configured role) and is also seeded as
    /// the initial member of the RBAC `ADMIN` role, which bootstraps role administration.
    ///
    /// Role administration itself is fully role-based. Each role is managed by its effective
    /// admin role (its delegated admin, or `ADMIN` by default). See [`RoleBasedAccessControl`]
    /// for the administration model.
    ///
    /// `roles` assigns a role to individual authority-gated procedures, keyed by procedure root
    /// (e.g. `PausableManager::pause_root()` → `PAUSER`, `unpause_root()` → `UNPAUSER`). A gated
    /// procedure without an entry in `roles` falls back to the `owner` check. Role membership is
    /// managed through the standard RBAC API on the [`RoleBasedAccessControl`] component.
    Rbac {
        owner: AccountId,
        roles: BTreeMap<AccountProcedureRoot, RoleSymbol>,
    },
}

impl IntoIterator for AccessControl {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s implementing this access control configuration, in the
    /// order they must be installed on the account. The matching [`Authority`] component is
    /// always included.
    fn into_iter(self) -> Self::IntoIter {
        match self {
            AccessControl::Ownable2Step { owner } => {
                vec![Ownable2Step::new(owner).into(), Authority::OwnerControlled.into()].into_iter()
            },
            AccessControl::Rbac { owner, roles } => vec![
                Ownable2Step::new(owner).into(),
                RoleBasedAccessControl::new(owner).into(),
                Authority::RbacControlled { roles }.into(),
            ]
            .into_iter(),
        }
    }
}

pub use authority::{Authority, AuthorityError};
pub use ownable2step::{Ownable2Step, Ownable2StepError};
pub use pausable::{Pausable, PausableManager, PausableStorage};
pub use rbac::RoleBasedAccessControl;
