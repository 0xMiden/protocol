use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::account_component_package;
use crate::procedure_root;

account_component_package!(
    SUPPLY_RESTRICTION_MANAGER_PACKAGE,
    "miden-standards-faucets-policies-transfer-supply-restriction-manager.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`SupplyRestrictionManager::NAME`], which mirrors the standards-side MASM module path.
const SUPPLY_RESTRICTION_MANAGER_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::transfer::supply_restriction::manager";

procedure_root!(
    SUPPLY_RESTRICTION_MANAGER_FREEZE,
    SUPPLY_RESTRICTION_MANAGER_LIBRARY_PATH,
    SupplyRestrictionManager::FREEZE_PROC_NAME,
    SupplyRestrictionManager::code()
);

procedure_root!(
    SUPPLY_RESTRICTION_MANAGER_UNFREEZE,
    SUPPLY_RESTRICTION_MANAGER_LIBRARY_PATH,
    SupplyRestrictionManager::UNFREEZE_PROC_NAME,
    SupplyRestrictionManager::code()
);

procedure_root!(
    SUPPLY_RESTRICTION_MANAGER_CONFISCATE,
    SUPPLY_RESTRICTION_MANAGER_LIBRARY_PATH,
    SupplyRestrictionManager::CONFISCATE_PROC_NAME,
    SupplyRestrictionManager::code()
);

// SUPPLY RESTRICTION MANAGER
// ================================================================================================

/// Account component of a fungible faucet that maintains the frozen and confiscated amounts in the
/// [`SupplyRestrictionStorage`](super::SupplyRestrictionStorage).
///
/// The component exposes `freeze`, `unfreeze` and `confiscate` admin procedures gated by the
/// account-wide [`Authority`](crate::account::access::Authority) component.
///
/// The issuer is trusted to not confiscate more than the holder's balance; doing so and re-minting
/// the amount inflates the circulating supply.
///
/// Companion components required:
/// - [`crate::account::access::Authority`] — provides the auth dispatch.
/// - [`crate::account::faucets::FungibleFaucet`] — provides the token supply that `confiscate`
///   decreases.
/// - A component that installs the `restricted_amounts` storage slot — typically
///   [`crate::account::policies::SupplyRestrictionPolicy`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SupplyRestrictionManager;

impl SupplyRestrictionManager {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::faucets::policies::transfer::supply_restriction::manager";

    const FREEZE_PROC_NAME: &'static str = "freeze";
    const UNFREEZE_PROC_NAME: &'static str = "unfreeze";
    const CONFISCATE_PROC_NAME: &'static str = "confiscate";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &SUPPLY_RESTRICTION_MANAGER_PACKAGE.code
    }

    /// Returns the procedure root of the `freeze` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn freeze_root() -> AccountProcedureRoot {
        *SUPPLY_RESTRICTION_MANAGER_FREEZE
    }

    /// Returns the procedure root of the `unfreeze` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn unfreeze_root() -> AccountProcedureRoot {
        *SUPPLY_RESTRICTION_MANAGER_UNFREEZE
    }

    /// Returns the procedure root of the `confiscate` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn confiscate_root() -> AccountProcedureRoot {
        *SUPPLY_RESTRICTION_MANAGER_CONFISCATE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        SUPPLY_RESTRICTION_MANAGER_PACKAGE.metadata.clone()
    }
}

impl From<SupplyRestrictionManager> for AccountComponent {
    fn from(_: SupplyRestrictionManager) -> Self {
        let metadata = SupplyRestrictionManager::component_metadata();
        AccountComponent::new(SupplyRestrictionManager::code().clone(), vec![], metadata)
            .expect("token supply restriction component should be valid")
    }
}
