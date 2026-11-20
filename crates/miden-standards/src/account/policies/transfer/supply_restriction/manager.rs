use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    AccountComponent,
    AccountProcedureRoot,
    StorageMap,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;

use crate::account::account_component_package;
use crate::procedure_root;

account_component_package!(
    SUPPLY_RESTRICTION_MANAGER_PACKAGE,
    "miden-standards-faucets-policies-transfer-supply-restriction-manager.masp"
);

// STORAGE
// ================================================================================================

static RESTRICTIONS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::transfer::supply_restriction::restrictions",
    )
    .expect("storage slot name should be valid")
});

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

/// Account component of a fungible faucet that tracks frozen and confiscated amounts of its asset
/// per holder account.
///
/// The component exposes `freeze`, `unfreeze` and `confiscate` admin procedures gated by the
/// account-wide [`Authority`](crate::account::access::Authority) component via
/// `exec.authority::assert_authorized`. The amounts are disjoint:
/// - frozen: restricted but can still be unfrozen. Freezing does not change the token supply.
/// - confiscated: restricted for good. Confiscating decreases the token supply by the confiscated
///   amount, so the issuer can re-mint it to another account without counting it twice.
///
/// `frozen + confiscated` of an account never exceeds
/// [`FungibleAsset::MAX_AMOUNT`](miden_protocol::asset::FungibleAsset::MAX_AMOUNT).
///
/// The component only records the amounts; it does not restrict transfers by itself. A faucet
/// must not install it without a send policy that rejects transfers (including sending the asset
/// back to the faucet for burning) that would leave the holder's balance below
/// `frozen + confiscated`. Otherwise a holder can keep spending confiscated amounts that were
/// already removed from the token supply. That policy is a follow-up of
/// [#4202](https://github.com/0xMiden/protocol/issues/4202).
///
/// The faucet cannot read a holder's vault, so it cannot verify that the holder actually owns the
/// amounts being frozen or confiscated. The issuer is trusted to not confiscate more than the
/// holder's balance; doing so and re-minting the amount inflates the circulating supply.
///
/// Under [`Authority::RbacControlled`](crate::account::access::Authority::RbacControlled), map
/// [`Self::freeze_root`], [`Self::unfreeze_root`] and [`Self::confiscate_root`] to the same role
/// symbol or to distinct ones.
///
/// Companion components required:
/// - [`crate::account::access::Authority`] — provides the mode-aware auth dispatch.
/// - [`crate::account::faucets::FungibleFaucet`] — provides the token supply that `confiscate`
///   decreases.
///
/// ## Storage
///
/// - [`Self::restrictions_slot()`]: storage map keyed by account ID (word layout `[0, 0,
///   account_id_suffix, account_id_prefix]`) with values `[frozen, confiscated, 0, 0]`. The map
///   starts empty.
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

    /// Storage slot name for the map of frozen and confiscated amounts.
    pub fn restrictions_slot() -> &'static StorageSlotName {
        &RESTRICTIONS_SLOT_NAME
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
        let restrictions_slot =
            StorageSlot::with_map(RESTRICTIONS_SLOT_NAME.clone(), StorageMap::default());

        AccountComponent::new(
            SupplyRestrictionManager::code().clone(),
            vec![restrictions_slot],
            metadata,
        )
        .expect("token supply restriction component should be valid")
    }
}
