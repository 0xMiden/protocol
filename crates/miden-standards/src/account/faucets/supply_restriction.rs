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
    TOKEN_SUPPLY_RESTRICTION_PACKAGE,
    "miden-standards-faucets-supply-restriction.masp"
);

// STORAGE
// ================================================================================================

static RESTRICTED_AMOUNTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::supply_restriction::restricted_amounts")
        .expect("storage slot name should be valid")
});

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`TokenSupplyRestriction::NAME`], which mirrors the standards-side MASM module path.
const TOKEN_SUPPLY_RESTRICTION_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::supply_restriction";

procedure_root!(
    TOKEN_SUPPLY_RESTRICTION_FREEZE,
    TOKEN_SUPPLY_RESTRICTION_LIBRARY_PATH,
    TokenSupplyRestriction::FREEZE_PROC_NAME,
    TokenSupplyRestriction::code()
);

procedure_root!(
    TOKEN_SUPPLY_RESTRICTION_UNFREEZE,
    TOKEN_SUPPLY_RESTRICTION_LIBRARY_PATH,
    TokenSupplyRestriction::UNFREEZE_PROC_NAME,
    TokenSupplyRestriction::code()
);

procedure_root!(
    TOKEN_SUPPLY_RESTRICTION_CONFISCATE,
    TOKEN_SUPPLY_RESTRICTION_LIBRARY_PATH,
    TokenSupplyRestriction::CONFISCATE_PROC_NAME,
    TokenSupplyRestriction::code()
);

// TOKEN SUPPLY RESTRICTION
// ================================================================================================

/// Account component of a fungible faucet that tracks frozen and confiscated amounts of its asset
/// per holder account.
///
/// The component exposes `freeze`, `unfreeze` and `confiscate` admin procedures gated by the
/// account-wide [`Authority`](crate::account::access::Authority) component. The amounts are
/// disjoint:
/// - frozen: restricted but can still be unfrozen. Freezing does not change the token supply.
/// - confiscated: restricted for good. Confiscating decreases the token supply by the confiscated
///   amount, so the issuer can re-mint it to another account without counting it twice.
///
/// `frozen + confiscated` of an account never exceeds
/// [`FungibleAsset::MAX_AMOUNT`](miden_protocol::asset::FungibleAsset::MAX_AMOUNT).
///
/// The issuer is trusted to not confiscate more than the holder's balance; doing so and re-minting
/// the amount inflates the circulating supply.
///
/// Companion components required:
/// - [`crate::account::access::Authority`] — provides the auth dispatch.
/// - [`crate::account::faucets::FungibleFaucet`] — provides the token supply that `confiscate`
///   decreases.
///
/// ## Storage
///
/// - [`Self::restricted_amounts_slot()`]: storage map laid out as:
///   - key: `[0, 0, account_id_suffix, account_id_prefix]`
///   - value: `[frozen, confiscated, 0, 0]`.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenSupplyRestriction;

impl TokenSupplyRestriction {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::faucets::supply_restriction";

    const FREEZE_PROC_NAME: &'static str = "freeze";
    const UNFREEZE_PROC_NAME: &'static str = "unfreeze";
    const CONFISCATE_PROC_NAME: &'static str = "confiscate";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &TOKEN_SUPPLY_RESTRICTION_PACKAGE.code
    }

    /// Storage slot name for the map of frozen and confiscated amounts.
    pub fn restricted_amounts_slot() -> &'static StorageSlotName {
        &RESTRICTED_AMOUNTS_SLOT_NAME
    }

    /// Returns the procedure root of the `freeze` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn freeze_root() -> AccountProcedureRoot {
        *TOKEN_SUPPLY_RESTRICTION_FREEZE
    }

    /// Returns the procedure root of the `unfreeze` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn unfreeze_root() -> AccountProcedureRoot {
        *TOKEN_SUPPLY_RESTRICTION_UNFREEZE
    }

    /// Returns the procedure root of the `confiscate` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn confiscate_root() -> AccountProcedureRoot {
        *TOKEN_SUPPLY_RESTRICTION_CONFISCATE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        TOKEN_SUPPLY_RESTRICTION_PACKAGE.metadata.clone()
    }
}

impl From<TokenSupplyRestriction> for AccountComponent {
    fn from(_: TokenSupplyRestriction) -> Self {
        let metadata = TokenSupplyRestriction::component_metadata();
        let restricted_amounts_slot =
            StorageSlot::with_map(RESTRICTED_AMOUNTS_SLOT_NAME.clone(), StorageMap::default());

        AccountComponent::new(
            TokenSupplyRestriction::code().clone(),
            vec![restricted_amounts_slot],
            metadata,
        )
        .expect("token supply restriction component should be valid")
    }
}
