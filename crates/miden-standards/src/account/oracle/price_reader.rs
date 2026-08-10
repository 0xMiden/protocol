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
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use super::config::PriceReaderConfig;
use super::types::FeedPriceKey;
use crate::account::account_component_code;
use crate::procedure_root;

// PRICE READER MANAGER
// ================================================================================================

account_component_code!(
    PRICE_READER_MANAGER_CODE,
    "miden-standards-oracle-price-reader-manager.masp"
);

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`PriceReaderManager::NAME`], which mirrors the standards-side MASM module path.
const PRICE_READER_MANAGER_LIBRARY_PATH: &str =
    "miden::standards::components::oracle::price_reader_manager";

procedure_root!(
    PRICE_READER_MANAGER_CONFIGURE_FEED_ROOT,
    PRICE_READER_MANAGER_LIBRARY_PATH,
    PriceReaderManager::CONFIGURE_FEED_PROC_NAME,
    PriceReaderManager::code()
);

procedure_root!(
    PRICE_READER_MANAGER_SET_READER_PARAMS_ROOT,
    PRICE_READER_MANAGER_LIBRARY_PATH,
    PriceReaderManager::SET_READER_PARAMS_PROC_NAME,
    PriceReaderManager::code()
);

procedure_root!(
    PRICE_READER_MANAGER_SET_ASSET_FEED_PRICE_KEY_ROOT,
    PRICE_READER_MANAGER_LIBRARY_PATH,
    PriceReaderManager::SET_ASSET_FEED_PRICE_KEY_PROC_NAME,
    PriceReaderManager::code()
);

static CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::oracle::price_reader_manager::config")
        .expect("storage slot name should be valid")
});

static PRICE_KEYS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::oracle::price_reader_manager::price_keys")
        .expect("storage slot name should be valid")
});

/// The price reader manager account component.
///
/// Owns the price reader configuration for an account and exposes it through authority-gated
/// setters, so the valuation logic in `miden::standards::oracle::price_reader` can be used without
/// defining bespoke storage. Other components installed on the same account value assets by calling
/// `quote_asset_value` with `exec`.
///
/// Pair with an [`Authority`][crate::account::access::Authority], which gates the setters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceReaderManager {
    config: PriceReaderConfig,
}

impl PriceReaderManager {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::oracle::price_reader_manager";

    pub(crate) const CONFIGURE_FEED_PROC_NAME: &'static str = "configure_feed";
    pub(crate) const SET_READER_PARAMS_PROC_NAME: &'static str = "set_reader_params";
    pub(crate) const SET_ASSET_FEED_PRICE_KEY_PROC_NAME: &'static str = "set_asset_feed_price_key";

    /// Creates a price reader manager with the given configuration.
    pub const fn new(config: PriceReaderConfig) -> Self {
        Self { config }
    }

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &PRICE_READER_MANAGER_CODE
    }

    /// Returns the procedure root of the `configure_feed` account procedure.
    pub fn configure_feed_root() -> AccountProcedureRoot {
        *PRICE_READER_MANAGER_CONFIGURE_FEED_ROOT
    }

    /// Returns the procedure root of the `set_reader_params` account procedure.
    pub fn set_reader_params_root() -> AccountProcedureRoot {
        *PRICE_READER_MANAGER_SET_READER_PARAMS_ROOT
    }

    /// Returns the procedure root of the `set_asset_feed_price_key` account procedure.
    pub fn set_asset_feed_price_key_root() -> AccountProcedureRoot {
        *PRICE_READER_MANAGER_SET_ASSET_FEED_PRICE_KEY_ROOT
    }

    /// Returns the config map key holding the feed account id, as `[prefix, suffix, 0, 0]`.
    ///
    /// Mirrors `CONFIG_KEY_FEED_ACCOUNT_ID` in `asm/standards/oracle/price_reader.masm`.
    pub fn config_key_feed_account_id() -> Word {
        Word::from([1u32, 0, 0, 0])
    }

    /// Returns the config map key holding the procedure root of the feed's `get_price`.
    ///
    /// Mirrors `CONFIG_KEY_GET_PRICE_PROC_ROOT` in `asm/standards/oracle/price_reader.masm`.
    pub fn config_key_get_price_proc_root() -> Word {
        Word::from([2u32, 0, 0, 0])
    }

    /// Returns the config map key holding the quote unit the feed is expected to publish in.
    ///
    /// Mirrors `CONFIG_KEY_QUOTE` in `asm/standards/oracle/price_reader.masm`.
    pub fn config_key_quote() -> Word {
        Word::from([3u32, 0, 0, 0])
    }

    /// Returns the config map key holding `[quote_exponent, max_age_secs, untracked_policy, 0]`.
    ///
    /// Mirrors `CONFIG_KEY_PARAMS` in `asm/standards/oracle/price_reader.masm`.
    pub fn config_key_params() -> Word {
        Word::from([4u32, 0, 0, 0])
    }

    /// Returns the [`StorageSlotName`] of the reader config map.
    pub fn config_slot() -> &'static StorageSlotName {
        &CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the per-faucet feed key map.
    pub fn price_keys_slot() -> &'static StorageSlotName {
        &PRICE_KEYS_SLOT_NAME
    }

    /// Returns the configuration this component was built with.
    pub const fn config(&self) -> &PriceReaderConfig {
        &self.config
    }

    /// Returns the storage slot schema for the reader config map.
    pub fn config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::config_slot().clone(),
            StorageSlotSchema::map(
                "Price reader configuration indexed by reserved config key",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the storage slot schema for the per-faucet feed key map.
    pub fn price_keys_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::price_keys_slot().clone(),
            StorageSlotSchema::map(
                "Feed price key overrides indexed by faucet ID",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema =
            StorageSchema::new([Self::config_slot_schema(), Self::price_keys_slot_schema()])
                .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("Owns the price reader configuration of an account")
            .with_storage_schema(storage_schema)
    }

    /// Returns the params word `[quote_exponent, max_age_secs, untracked_policy, 0]`.
    fn params_word(&self) -> Word {
        Word::new([
            Felt::from(self.config.quote_exponent()),
            Felt::from(self.config.max_age_secs()),
            self.config.untracked_policy().as_felt(),
            Felt::ZERO,
        ])
    }

    /// Converts the configuration into the storage slots of this component.
    fn to_storage_slots(&self) -> Vec<StorageSlot> {
        let mut config_entries = Vec::new();

        // An unconfigured feed is left as the empty word, which the reader rejects on use rather
        // than silently valuing assets at zero.
        let feed_account_id_word = match self.config.feed_account_id() {
            Some(feed_account_id) => FeedPriceKey::from_faucet_id(feed_account_id).as_word(),
            None => Word::empty(),
        };
        config_entries
            .push((StorageMapKey::new(Self::config_key_feed_account_id()), feed_account_id_word));

        let get_price_proc_root = self
            .config
            .get_price_proc_root()
            .map_or_else(Word::empty, |root| *root.mast_root());
        config_entries.push((
            StorageMapKey::new(Self::config_key_get_price_proc_root()),
            get_price_proc_root,
        ));

        config_entries
            .push((StorageMapKey::new(Self::config_key_quote()), self.config.quote_id().as_word()));
        config_entries.push((StorageMapKey::new(Self::config_key_params()), self.params_word()));

        let price_key_entries: Vec<(StorageMapKey, Word)> = self
            .config
            .feed_price_keys()
            .iter()
            .map(|(faucet_id, feed_price_key)| {
                (
                    StorageMapKey::new(FeedPriceKey::from_faucet_id(*faucet_id).as_word()),
                    feed_price_key.as_word(),
                )
            })
            .collect();

        let config_map =
            StorageMap::with_entries(config_entries).expect("seeded config map should be valid");
        let price_keys_map = StorageMap::with_entries(price_key_entries)
            .expect("seeded price key map should be valid");

        vec![
            StorageSlot::with_map(Self::config_slot().clone(), config_map),
            StorageSlot::with_map(Self::price_keys_slot().clone(), price_keys_map),
        ]
    }
}

impl From<PriceReaderManager> for AccountComponent {
    fn from(manager: PriceReaderManager) -> Self {
        let storage_slots = manager.to_storage_slots();

        AccountComponent::new(
            PriceReaderManager::code().clone(),
            storage_slots,
            PriceReaderManager::component_metadata(),
        )
        .expect(
            "price reader manager component should satisfy the requirements of a valid account component",
        )
    }
}
