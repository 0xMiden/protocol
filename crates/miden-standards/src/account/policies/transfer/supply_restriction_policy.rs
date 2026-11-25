use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::account_component_package;
use crate::account::policies::transfer::supply_restriction::SupplyRestrictionStorage;
use crate::procedure_root;

// SUPPLY RESTRICTION POLICY
// ================================================================================================

account_component_package!(
    SUPPLY_RESTRICTION_POLICY_PACKAGE,
    "miden-standards-faucets-policies-transfer-supply-restriction-policy.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`SupplyRestrictionPolicy::NAME`], which mirrors the standards-side MASM module path.
const SUPPLY_RESTRICTION_POLICY_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::transfer::supply_restriction_policy";

procedure_root!(
    SUPPLY_RESTRICTION_POLICY_SEND_ROOT,
    SUPPLY_RESTRICTION_POLICY_LIBRARY_PATH,
    SupplyRestrictionPolicy::SEND_PROC_NAME,
    SupplyRestrictionPolicy::code()
);

/// The supply restriction send policy account component.
///
/// Installs the [`SupplyRestrictionStorage`] plus the `check_send_policy` predicate procedure. Pair
/// with a [`crate::account::policies::TokenPolicyManager`] whose send policy map includes
/// [`SupplyRestrictionPolicy::send_root`], and with a
/// [`crate::account::policies::SupplyRestrictionManager`] to update the restricted amounts. When
/// active, transfers fail if they would spend frozen or confiscated amounts of the native account.
/// Receiving assets is never restricted.
///
/// A restricted account can only send what it held at the beginning of the transaction, so it must
/// spend assets it receives in a later transaction.
///
/// The issuing faucet is exempt from its own restrictions.
#[derive(Debug, Clone, Default)]
pub struct SupplyRestrictionPolicy {
    storage: SupplyRestrictionStorage,
}

impl SupplyRestrictionPolicy {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::faucets::policies::transfer::supply_restriction_policy";

    pub(crate) const SEND_PROC_NAME: &str = "check_send_policy";

    /// Creates a new [`SupplyRestrictionPolicy`].
    pub fn new(storage: SupplyRestrictionStorage) -> Self {
        Self { storage }
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &SUPPLY_RESTRICTION_POLICY_PACKAGE.code
    }

    /// Returns the procedure root of the send policy procedure.
    pub fn send_root() -> AccountProcedureRoot {
        *SUPPLY_RESTRICTION_POLICY_SEND_ROOT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        SUPPLY_RESTRICTION_POLICY_PACKAGE.metadata.clone()
    }
}

impl From<SupplyRestrictionPolicy> for AccountComponent {
    fn from(policy: SupplyRestrictionPolicy) -> Self {
        AccountComponent::new(
            SupplyRestrictionPolicy::code().clone(),
            vec![policy.storage.into_slot()],
            SupplyRestrictionPolicy::component_metadata(),
        )
        .expect("supply restriction policy component should be valid")
    }
}
