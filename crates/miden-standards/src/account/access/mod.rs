use alloc::collections::BTreeMap;
use alloc::vec;

use miden_protocol::Felt;
use miden_protocol::account::{AccountComponent, AccountId, AccountProcedureRoot, RoleSymbol};
use miden_protocol::errors::AccountIdError;

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
/// - [`AccessControl::Rbac`] → [`RoleBasedAccessControl`] + [`Authority::RbacControlled`]. The
///   `procedure_roles` map assigns a role to individual gated procedures (keyed by procedure root);
///   procedures without a mapping fall back to the `ADMIN` role check.
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
/// # let admin: miden_protocol::account::AccountId = unimplemented!();
/// # let init_seed = [0u8; 32];
/// AccountBuilder::new(init_seed)
///     .with_components(AccessControl::Rbac { admin, procedure_roles: BTreeMap::new() });
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
    /// Role-based access control. The provided `admin` is seeded as the initial member of the
    /// RBAC `ADMIN` role, which bootstraps role administration.
    ///
    /// Role administration itself is fully role-based. Each role is managed by its effective
    /// admin role (its delegated admin, or `ADMIN` by default). See [`RoleBasedAccessControl`]
    /// for the administration model.
    ///
    /// `procedure_roles` assigns a role to individual authority-gated procedures, keyed by
    /// procedure root (e.g. [`PausableManager::pause_root`] → `PAUSER`,
    /// [`PausableManager::unpause_root`] → `UNPAUSER`, and optionally [`Authority::freeze_root`] →
    /// `FREEZER` with [`Authority::unfreeze_root`] → `UNFREEZER`). A gated procedure without an
    /// entry in `procedure_roles` falls back to the `ADMIN` role. The emergency `freeze` /
    /// `unfreeze` switch resolves its role the same way, defaulting to `ADMIN`. Role membership is
    /// managed through the standard RBAC API on the [`RoleBasedAccessControl`] component.
    Rbac {
        admin: AccountId,
        procedure_roles: BTreeMap<AccountProcedureRoot, RoleSymbol>,
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
            AccessControl::Rbac { admin, procedure_roles } => vec![
                RoleBasedAccessControl::with_admins([admin])
                    .expect("a single ADMIN member is a valid seed")
                    .into(),
                Authority::RbacControlled { procedure_roles }.into(),
            ]
            .into_iter(),
        }
    }
}

pub use authority::{Authority, AuthorityError, ProcedureRole};
pub use ownable2step::{Ownable2Step, Ownable2StepError};
pub use pausable::{Pausable, PausableManager, PausableStorage};
pub use rbac::{RoleBasedAccessControl, RoleBasedAccessControlError, RoleConfig};

// HELPERS
// ================================================================================================

/// Constructs an `Option<AccountId>` from a suffix/prefix felt pair.
/// Returns `Ok(None)` when both felts are zero (e.g. no owner / no nomination).
pub(crate) fn account_id_from_felt_pair(
    suffix: Felt,
    prefix: Felt,
) -> Result<Option<AccountId>, AccountIdError> {
    if suffix == Felt::ZERO && prefix == Felt::ZERO {
        Ok(None)
    } else {
        AccountId::try_from_elements(suffix, prefix).map(Some)
    }
}
