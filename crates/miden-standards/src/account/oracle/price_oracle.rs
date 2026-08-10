use alloc::vec;

use miden_protocol::Word;
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
    PRICE_ORACLE_SET_IMPLEMENTATION_ROOT,
    PRICE_ORACLE_LIBRARY_PATH,
    PriceOracle::SET_IMPLEMENTATION_PROC_NAME,
    PriceOracle::code()
);

static IMPLEMENTATION_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::oracle::price_oracle::implementation")
        .expect("storage slot name should be valid")
});

/// The price oracle account component: the interface consumers ask "what is one asset worth in
/// another".
///
/// `get_conversion_rate` returns a numerator and a denominator rather than a converted amount, in
/// the same shape the fee standard applies through `fee::convert_amount`, so both paths share one
/// rounding convention and this standard restates no arithmetic. It also returns how fresh the rate
/// is, since a rate derived from two prices is only as fresh as its stalest leg and how stale is
/// too stale is a consumer decision.
///
/// The procedure's body does nothing but dispatch to the implementation root stored in
/// [`PriceOracle::implementation_slot`]. That is deliberate: its MAST root is the address consumers
/// resolve over FPI, so keeping the body fixed lets the pricing behind it be replaced without
/// invalidating anyone's reference to it. Pair the component with an implementation such as
/// [`PriceFeed`][crate::account::oracle::PriceFeed] and with an
/// [`Authority`][crate::account::access::Authority], which gates `set_implementation`.
///
/// The wrapper is a stable address, not a gate. A dispatch target has to be an account procedure to
/// be reachable by `dyncall`, which also makes it reachable directly over FPI, so an implementation
/// must enforce its own guarantees rather than assume the wrapper ran first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceOracle {
    implementation: Option<AccountProcedureRoot>,
}

impl PriceOracle {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::oracle::price_oracle";

    pub(crate) const GET_CONVERSION_RATE_PROC_NAME: &'static str = "get_conversion_rate";
    const SET_IMPLEMENTATION_PROC_NAME: &'static str = "set_implementation";

    /// Creates an oracle with no implementation attached yet.
    ///
    /// `get_conversion_rate` aborts until one is registered, either at genesis through
    /// [`PriceOracle::with_implementation`] or later through the `set_implementation` procedure.
    pub const fn new() -> Self {
        Self { implementation: None }
    }

    /// Registers the pricing implementation `get_conversion_rate` dispatches to.
    ///
    /// The root must belong to a procedure of the same account, since `dyncall` only reaches the
    /// account's own procedures.
    pub const fn with_implementation(mut self, implementation: AccountProcedureRoot) -> Self {
        self.implementation = Some(implementation);
        self
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
    ///
    /// This is the address consumers resolve over FPI. It must not change across releases: see the
    /// type-level documentation.
    pub fn get_conversion_rate_root() -> AccountProcedureRoot {
        *PRICE_ORACLE_GET_CONVERSION_RATE_ROOT
    }

    /// Returns the procedure root of the `set_implementation` account procedure.
    pub fn set_implementation_root() -> AccountProcedureRoot {
        *PRICE_ORACLE_SET_IMPLEMENTATION_ROOT
    }

    /// Returns the [`StorageSlotName`] holding the active implementation's procedure root.
    pub fn implementation_slot() -> &'static StorageSlotName {
        &IMPLEMENTATION_SLOT_NAME
    }

    /// Returns the registered implementation, or `None` when none is attached.
    pub const fn implementation(&self) -> Option<AccountProcedureRoot> {
        self.implementation
    }

    /// Returns the storage slot schema for the implementation slot.
    pub fn implementation_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::implementation_slot().clone(),
            StorageSlotSchema::value(
                "Procedure root of the active pricing implementation",
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([Self::implementation_slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("Reports the conversion rate between two assets")
            .with_storage_schema(storage_schema)
    }
}

impl Default for PriceOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl From<PriceOracle> for AccountComponent {
    fn from(oracle: PriceOracle) -> Self {
        let implementation =
            oracle.implementation.map_or_else(Word::empty, |root| *root.mast_root());

        AccountComponent::new(
            PriceOracle::code().clone(),
            vec![StorageSlot::with_value(
                PriceOracle::implementation_slot().clone(),
                implementation,
            )],
            PriceOracle::component_metadata(),
        )
        .expect(
            "price oracle component should satisfy the requirements of a valid account component",
        )
    }
}
