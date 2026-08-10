use alloc::collections::BTreeMap;
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
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;

use super::types::{FeedPriceKey, PriceEntry, QuoteId};
use crate::account::account_component_code;
use crate::procedure_root;

// PRICE FEED
// ================================================================================================

account_component_code!(PRICE_FEED_CODE, "miden-standards-oracle-price-feed.masp");

/// MASL library namespace used for procedure-root lookups. Distinct from [`PriceFeed::NAME`],
/// which mirrors the standards-side MASM module path.
const PRICE_FEED_LIBRARY_PATH: &str = "miden::standards::components::oracle::price_feed";

procedure_root!(
    PRICE_FEED_COMPUTE_CONVERSION_RATE_ROOT,
    PRICE_FEED_LIBRARY_PATH,
    PriceFeed::COMPUTE_CONVERSION_RATE_PROC_NAME,
    PriceFeed::code()
);

procedure_root!(
    PRICE_FEED_PUBLISH_PRICE_ROOT,
    PRICE_FEED_LIBRARY_PATH,
    PriceFeed::PUBLISH_PRICE_PROC_NAME,
    PriceFeed::code()
);

static QUOTE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::oracle::price_feed::quote")
        .expect("storage slot name should be valid")
});

static PRICES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::oracle::price_feed::prices")
        .expect("storage slot name should be valid")
});

/// A price oracle implementation backed by published unit prices.
///
/// Each faucet gets a `(price, exponent, timestamp)` entry, all denominated in one quote unit fixed
/// at deployment. `compute_conversion_rate` divides two of them into the rate between the assets;
/// the quote cancels out of that division, which is why it never appears in the oracle interface
/// and why one feed must publish every price in the same unit.
///
/// Register [`PriceFeed::compute_conversion_rate_root`] on a
/// [`PriceOracle`][crate::account::oracle::PriceOracle] installed on the same account, and pair
/// both with an [`Authority`][crate::account::access::Authority], which gates `publish_price`.
///
/// The rate computation applies its own transaction expiration delta. It is the dispatch target of
/// the oracle's wrapper but is reachable directly over FPI as well, so it cannot rely on the
/// wrapper having run first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceFeed {
    quote_id: QuoteId,
    prices: BTreeMap<AccountId, PriceEntry>,
}

impl PriceFeed {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::oracle::price_feed";

    pub(crate) const COMPUTE_CONVERSION_RATE_PROC_NAME: &'static str = "compute_conversion_rate";
    const PUBLISH_PRICE_PROC_NAME: &'static str = "publish_price";

    /// Creates a feed quoting in the given unit with no prices published yet.
    pub fn new(quote_id: QuoteId) -> Self {
        Self { quote_id, prices: BTreeMap::new() }
    }

    /// Publishes a price for the given faucet at genesis.
    pub fn with_price(mut self, faucet_id: AccountId, entry: PriceEntry) -> Self {
        self.prices.insert(faucet_id, entry);
        self
    }

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &PRICE_FEED_CODE
    }

    /// Returns the procedure root of the `compute_conversion_rate` account procedure.
    ///
    /// Register it with
    /// [`PriceOracle::with_implementation`][crate::account::oracle::PriceOracle::with_implementation]
    /// so the oracle's stable wrapper dispatches to this feed.
    pub fn compute_conversion_rate_root() -> AccountProcedureRoot {
        *PRICE_FEED_COMPUTE_CONVERSION_RATE_ROOT
    }

    /// Returns the procedure root of the `publish_price` account procedure.
    pub fn publish_price_root() -> AccountProcedureRoot {
        *PRICE_FEED_PUBLISH_PRICE_ROOT
    }

    /// Returns the [`StorageSlotName`] where the quote unit is stored.
    pub fn quote_slot() -> &'static StorageSlotName {
        &QUOTE_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the published prices map.
    pub fn prices_slot() -> &'static StorageSlotName {
        &PRICES_SLOT_NAME
    }

    /// Returns the unit this feed quotes its prices in.
    pub const fn quote_id(&self) -> QuoteId {
        self.quote_id
    }

    /// Returns the prices published at genesis.
    pub const fn prices(&self) -> &BTreeMap<AccountId, PriceEntry> {
        &self.prices
    }

    /// Returns the storage slot schema for the quote unit slot.
    pub fn quote_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::quote_slot().clone(),
            StorageSlotSchema::value(
                "Quote unit prices are denominated in",
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the storage slot schema for the published prices map.
    pub fn prices_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::prices_slot().clone(),
            StorageSlotSchema::map(
                "Published prices indexed by faucet ID",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema =
            StorageSchema::new([Self::quote_slot_schema(), Self::prices_slot_schema()])
                .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("Prices assets from published unit prices in a fixed quote unit")
            .with_storage_schema(storage_schema)
    }

    /// Converts the published prices into the storage slots of this component.
    fn to_storage_slots(&self) -> Vec<StorageSlot> {
        let entries: Vec<(StorageMapKey, _)> = self
            .prices
            .iter()
            .map(|(faucet_id, entry)| {
                (
                    StorageMapKey::new(FeedPriceKey::from_faucet_id(*faucet_id).as_word()),
                    entry.to_word(),
                )
            })
            .collect();

        let prices_map =
            StorageMap::with_entries(entries).expect("seeded price map should be valid");

        vec![
            StorageSlot::with_value(Self::quote_slot().clone(), self.quote_id.as_word()),
            StorageSlot::with_map(Self::prices_slot().clone(), prices_map),
        ]
    }
}

impl From<PriceFeed> for AccountComponent {
    fn from(feed: PriceFeed) -> Self {
        let storage_slots = feed.to_storage_slots();

        AccountComponent::new(
            PriceFeed::code().clone(),
            storage_slots,
            PriceFeed::component_metadata(),
        )
        .expect("price feed component should satisfy the requirements of a valid account component")
    }
}
