use alloc::vec;

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
    AccountProcedureRoot,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;

use crate::account::account_component_code;
use crate::procedure_root;

// PRICE ORACLE
// ================================================================================================

account_component_code!(PRICE_ORACLE_CODE, "miden-standards-oracle-price-oracle.masp");

/// MASL library namespace used for procedure-root lookups. Distinct from [`PriceOracle::NAME`],
/// which mirrors the standards-side MASM module path.
const PRICE_ORACLE_LIBRARY_PATH: &str = "miden::standards::components::oracle::price_oracle";

procedure_root!(
    PRICE_ORACLE_GET_CONVERSION_RATE_ROOT,
    PRICE_ORACLE_LIBRARY_PATH,
    PriceOracle::GET_CONVERSION_RATE_PROC_NAME,
    PriceOracle::code()
);

procedure_root!(
    PRICE_ORACLE_SET_RATE_PROVIDER_ROOT,
    PRICE_ORACLE_LIBRARY_PATH,
    PriceOracle::SET_RATE_PROVIDER_PROC_NAME,
    PriceOracle::code()
);

static ACTIVE_RATE_PROVIDER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::oracle::price_oracle::active_rate_provider_proc_root")
        .expect("storage slot name should be valid")
});

/// The price oracle account component.
///
/// Install it alongside a rate provider on the same account and an
/// [`Authority`][crate::account::access::Authority], which gates `set_rate_provider`.
/// `get_conversion_rate` invokes the registered provider dynamically, so the pricing can be
/// replaced without changing the procedure root consumers reach it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceOracle {
    rate_provider: AccountProcedureRoot,
}

impl PriceOracle {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::oracle::price_oracle";

    pub(crate) const GET_CONVERSION_RATE_PROC_NAME: &'static str = "get_conversion_rate";
    const SET_RATE_PROVIDER_PROC_NAME: &'static str = "set_rate_provider";

    /// Creates an oracle dispatching to the given rate provider.
    ///
    /// The root must belong to a procedure of the same account, since `dyncall` only reaches the
    /// account's own procedures.
    pub const fn new(rate_provider: AccountProcedureRoot) -> Self {
        Self { rate_provider }
    }

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &PRICE_ORACLE_CODE
    }

    /// Returns the procedure root of the `get_conversion_rate` account procedure.
    pub fn get_conversion_rate_root() -> AccountProcedureRoot {
        *PRICE_ORACLE_GET_CONVERSION_RATE_ROOT
    }

    /// Returns the procedure root of the `set_rate_provider` account procedure.
    pub fn set_rate_provider_root() -> AccountProcedureRoot {
        *PRICE_ORACLE_SET_RATE_PROVIDER_ROOT
    }

    /// Returns the [`StorageSlotName`] holding the active rate provider's procedure root.
    pub fn active_rate_provider_slot() -> &'static StorageSlotName {
        &ACTIVE_RATE_PROVIDER_SLOT_NAME
    }

    /// Returns the registered rate provider.
    pub const fn rate_provider(&self) -> AccountProcedureRoot {
        self.rate_provider
    }

    /// Returns the storage slot schema for the active rate provider slot.
    pub fn active_rate_provider_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::active_rate_provider_slot().clone(),
            StorageSlotSchema::value(
                "Procedure root of the active rate provider",
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([Self::active_rate_provider_slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("Reports the conversion rate between two assets")
            .with_storage_schema(storage_schema)
    }
}

impl From<PriceOracle> for AccountComponent {
    fn from(oracle: PriceOracle) -> Self {
        AccountComponent::new(
            PriceOracle::code().clone(),
            vec![StorageSlot::with_value(
                PriceOracle::active_rate_provider_slot().clone(),
                *oracle.rate_provider.mast_root(),
            )],
            PriceOracle::component_metadata(),
        )
        .expect(
            "price oracle component should satisfy the requirements of a valid account component",
        )
    }
}
