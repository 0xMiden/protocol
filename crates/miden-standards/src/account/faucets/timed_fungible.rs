use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    SchemaTypeId,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountStorageMode,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::TokenSymbol;
use miden_protocol::{Felt, FieldElement, Word};
use miden_protocol::utils::sync::LazyLock;

use super::{FungibleFaucetError, TokenMetadata};
use crate::account::AuthScheme;
use crate::account::auth::{
    AuthEcdsaK256KeccakAcl,
    AuthEcdsaK256KeccakAclConfig,
    AuthFalcon512RpoAcl,
    AuthFalcon512RpoAclConfig,
};
use crate::account::components::timed_fungible_faucet_library;

/// The schema type ID for token symbols.
const TOKEN_SYMBOL_TYPE_ID: &str = "miden::standards::fungible_faucets::metadata::token_symbol";
/// The schema type ID for timed supply config.
const TIMED_SUPPLY_CONFIG_TYPE_ID: &str = "miden::standards::supply::flexible_supply::config";

use crate::procedure_digest;

// SLOT NAMES
// ================================================================================================

static SUPPLY_CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::supply::flexible_supply::config")
        .expect("storage slot name should be valid")
});

// TIMED FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

procedure_digest!(
    TIMED_FUNGIBLE_FAUCET_DISTRIBUTE,
    TimedFungibleFaucet::DISTRIBUTE_PROC_NAME,
    timed_fungible_faucet_library
);

procedure_digest!(
    TIMED_FUNGIBLE_FAUCET_BURN,
    TimedFungibleFaucet::BURN_PROC_NAME,
    timed_fungible_faucet_library
);

pub struct TimedFungibleFaucet {
    metadata: TokenMetadata,
    distribution_end: u32,
    burn_only: bool,
}

impl TimedFungibleFaucet {
    pub const NAME: &'static str = "miden::timed_fungible_faucet";
    pub const MAX_DECIMALS: u8 = TokenMetadata::MAX_DECIMALS;

    const DISTRIBUTE_PROC_NAME: &str = "timed_fungible_faucet::distribute";
    const BURN_PROC_NAME: &str = "timed_fungible_faucet::burn";

    pub fn new(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
        distribution_end: u32,
        burn_only: bool,
    ) -> Result<Self, FungibleFaucetError> {
        let metadata = TokenMetadata::new(symbol, decimals, max_supply)?;
        Ok(Self {
            metadata,
            distribution_end,
            burn_only,
        })
    }

    pub fn metadata(&self) -> &TokenMetadata {
        &self.metadata
    }

    pub fn metadata_slot() -> &'static StorageSlotName {
        TokenMetadata::metadata_slot()
    }
    
    pub fn supply_config_slot() -> &'static StorageSlotName {
        &SUPPLY_CONFIG_SLOT
    }

    pub fn distribute_digest() -> Word {
        *TIMED_FUNGIBLE_FAUCET_DISTRIBUTE
    }

    pub fn burn_digest() -> Word {
        *TIMED_FUNGIBLE_FAUCET_BURN
    }
}

impl From<TimedFungibleFaucet> for AccountComponent {
    fn from(faucet: TimedFungibleFaucet) -> Self {
        let metadata_slot: StorageSlot = faucet.metadata.into();
        
        let config_val = [
            Felt::ZERO, // token_supply tracks supply here
            faucet.metadata.max_supply(),
            Felt::new(faucet.distribution_end as u64),
            Felt::new(faucet.burn_only as u64)
        ];
        
        let config_slot = StorageSlot::with_value(
            TimedFungibleFaucet::supply_config_slot().clone(), 
            Word::new(config_val)
        );

        let token_symbol_type = SchemaTypeId::new(TOKEN_SYMBOL_TYPE_ID).unwrap();
        let supply_config_type = SchemaTypeId::new(TIMED_SUPPLY_CONFIG_TYPE_ID).unwrap();

        let metadata_slot_schema = StorageSlotSchema::value(
            "Token metadata",
            [
                FeltSchema::felt("token_supply").with_default(Felt::new(0)),
                FeltSchema::felt("max_supply"),
                FeltSchema::u8("decimals"),
                FeltSchema::new_typed(token_symbol_type, "symbol"),
            ],
        );
        
        // Custom schema for supply config: [token_supply, max_supply, distribution_end, burn_only]
        let config_slot_schema = StorageSlotSchema::value(
            "Supply Config",
            [
                FeltSchema::felt("token_supply").with_default(Felt::new(0)),
                FeltSchema::felt("max_supply"),
                FeltSchema::u32("distribution_end"),
                FeltSchema::new_typed(supply_config_type, "burn_only_flag"),
            ],
        );
        
        // Use map or vec of tuples
        let schema_entries = alloc::vec![
            (TimedFungibleFaucet::metadata_slot().clone(), metadata_slot_schema),
            (TimedFungibleFaucet::supply_config_slot().clone(), config_slot_schema),
        ];

        let storage_schema = StorageSchema::new(schema_entries)
            .expect("storage schema valid");

        let metadata = AccountComponentMetadata::new(TimedFungibleFaucet::NAME)
            .with_description("Timed fungible faucet component")
            .with_supported_type(AccountType::FungibleFaucet)
            .with_storage_schema(storage_schema);

        AccountComponent::new(
            timed_fungible_faucet_library(), 
            vec![metadata_slot, config_slot], 
            metadata
        ).expect("timed fungible faucet component valid")
    }
}

pub fn create_timed_fungible_faucet(
    init_seed: [u8; 32],
    symbol: TokenSymbol,
    decimals: u8,
    max_supply: Felt,
    distribution_end: u32,
    burn_only: bool,
    storage_mode: AccountStorageMode,
    auth_scheme: AuthScheme,
) -> Result<Account, FungibleFaucetError> {
    let distribute_proc_root = TimedFungibleFaucet::distribute_digest();

    let auth_component: AccountComponent = match auth_scheme {
        AuthScheme::Falcon512Rpo { pub_key } => AuthFalcon512RpoAcl::new(
            pub_key,
            AuthFalcon512RpoAclConfig::new()
                .with_auth_trigger_procedures(vec![distribute_proc_root])
                .with_allow_unauthorized_input_notes(true),
        )
        .map_err(FungibleFaucetError::AccountError)?
        .into(),
        AuthScheme::EcdsaK256Keccak { pub_key } => AuthEcdsaK256KeccakAcl::new(
            pub_key,
            AuthEcdsaK256KeccakAclConfig::new()
                .with_auth_trigger_procedures(vec![distribute_proc_root])
                .with_allow_unauthorized_input_notes(true),
        )
        .map_err(FungibleFaucetError::AccountError)?
        .into(),
        _ => return Err(FungibleFaucetError::UnsupportedAuthScheme("Unsupported auth scheme".into())),
    };

    let faucet_component = TimedFungibleFaucet::new(symbol, decimals, max_supply, distribution_end, burn_only)?;
    
    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(storage_mode)
        .with_auth_component(auth_component)
        .with_component(faucet_component)
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}
