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
    AccountId,
    AccountProcedureRoot,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

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
    PRICE_READER_MANAGER_SET_ORACLE_ROOT,
    PRICE_READER_MANAGER_LIBRARY_PATH,
    PriceReaderManager::SET_ORACLE_PROC_NAME,
    PriceReaderManager::code()
);

static ORACLE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::oracle::price_reader_manager::oracle")
        .expect("storage slot name should be valid")
});

/// The price reader manager account component: the consuming side of the price oracle standard.
///
/// It holds which oracle account to ask, and nothing else. The oracle's procedure root is not
/// configuration: consumers resolve it at assembly time from the oracle's stable wrapper, so
/// replacing an oracle's pricing implementation never touches a consumer's storage.
///
/// Other components installed on the same account convert through the `exec`-invoked
/// `get_conversion_rate` and `convert_asset_amount` procedures, so the oracle read happens in the
/// native account's context. Pair with an [`Authority`][crate::account::access::Authority], which
/// gates the setter.
///
/// Freshness is not enforced here. `get_conversion_rate` hands back the timestamp of the stalest
/// input the rate came from, and `price_reader::assert_fresh` applies a bound to it, but which
/// bound is a consumer decision: a spending limit and a liquidation engine do not want the same
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PriceReaderManager {
    oracle_account_id: Option<AccountId>,
}

impl PriceReaderManager {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::oracle::price_reader_manager";

    const SET_ORACLE_PROC_NAME: &'static str = "set_oracle";

    /// Creates a reader with no oracle attached yet.
    ///
    /// Conversions abort until one is configured, either at genesis through
    /// [`PriceReaderManager::with_oracle`] or later through the `set_oracle` procedure.
    pub const fn new() -> Self {
        Self { oracle_account_id: None }
    }

    /// Points the reader at the given oracle account.
    pub const fn with_oracle(mut self, oracle_account_id: AccountId) -> Self {
        self.oracle_account_id = Some(oracle_account_id);
        self
    }

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &PRICE_READER_MANAGER_CODE
    }

    /// Returns the procedure root of the `set_oracle` account procedure.
    pub fn set_oracle_root() -> AccountProcedureRoot {
        *PRICE_READER_MANAGER_SET_ORACLE_ROOT
    }

    /// Returns the [`StorageSlotName`] holding the configured oracle account id.
    pub fn oracle_slot() -> &'static StorageSlotName {
        &ORACLE_SLOT_NAME
    }

    /// Returns the configured oracle account, or `None` when none is attached.
    pub const fn oracle_account_id(&self) -> Option<AccountId> {
        self.oracle_account_id
    }

    /// Returns the storage slot schema for the oracle account slot.
    pub fn oracle_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::oracle_slot().clone(),
            StorageSlotSchema::value(
                "Oracle account this reader queries",
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([Self::oracle_slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("Converts assets through a configured price oracle")
            .with_storage_schema(storage_schema)
    }

    /// Returns the storage value word of the configured oracle account.
    fn oracle_word(&self) -> Word {
        self.oracle_account_id.map_or_else(Word::empty, |id| {
            Word::new([id.prefix().as_felt(), id.suffix(), Felt::ZERO, Felt::ZERO])
        })
    }
}

impl From<PriceReaderManager> for AccountComponent {
    fn from(manager: PriceReaderManager) -> Self {
        AccountComponent::new(
            PriceReaderManager::code().clone(),
            vec![StorageSlot::with_value(
                PriceReaderManager::oracle_slot().clone(),
                manager.oracle_word(),
            )],
            PriceReaderManager::component_metadata(),
        )
        .expect(
            "price reader manager component should satisfy the requirements of a valid account component",
        )
    }
}
