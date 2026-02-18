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
use miden_protocol::{Felt, Word};

use super::{FungibleFaucetError, TokenMetadata};
use crate::account::AuthScheme;
use crate::account::auth::{
    AuthEcdsaK256KeccakAcl,
    AuthEcdsaK256KeccakAclConfig,
    AuthFalcon512RpoAcl,
    AuthFalcon512RpoAclConfig,
};
use crate::account::components::unlimited_fungible_faucet_library;

/// The schema type ID for token symbols.
const TOKEN_SYMBOL_TYPE_ID: &str = "miden::standards::fungible_faucets::metadata::token_symbol";

use crate::procedure_digest;

// UNLIMITED FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

procedure_digest!(
    UNLIMITED_FUNGIBLE_FAUCET_DISTRIBUTE,
    UnlimitedFungibleFaucet::DISTRIBUTE_PROC_NAME,
    unlimited_fungible_faucet_library
);

procedure_digest!(
    UNLIMITED_FUNGIBLE_FAUCET_BURN,
    UnlimitedFungibleFaucet::BURN_PROC_NAME,
    unlimited_fungible_faucet_library
);

pub struct UnlimitedFungibleFaucet {
    metadata: TokenMetadata,
}

impl UnlimitedFungibleFaucet {
    pub const NAME: &'static str = "miden::unlimited_fungible_faucet";
    pub const MAX_DECIMALS: u8 = TokenMetadata::MAX_DECIMALS;

    const DISTRIBUTE_PROC_NAME: &str = "unlimited_fungible_faucet::distribute";
    const BURN_PROC_NAME: &str = "unlimited_fungible_faucet::burn";

    pub fn new(symbol: TokenSymbol, decimals: u8) -> Result<Self, FungibleFaucetError> {
        let max_supply = miden_protocol::asset::FungibleAsset::MAX_AMOUNT;
        // We assume Unlimited Faucet doesn't track supply on-chain in metadata slot effectively, 
        // as logic doesn't update it. But we initialize it correctly.
        let metadata = TokenMetadata::new(symbol, decimals, Felt::new(max_supply))?;
        Ok(Self { metadata })
    }

    pub fn metadata(&self) -> &TokenMetadata {
        &self.metadata
    }

    pub fn metadata_slot() -> &'static StorageSlotName {
        TokenMetadata::metadata_slot()
    }

    pub fn distribute_digest() -> Word {
        *UNLIMITED_FUNGIBLE_FAUCET_DISTRIBUTE
    }

    pub fn burn_digest() -> Word {
        *UNLIMITED_FUNGIBLE_FAUCET_BURN
    }
}

impl From<UnlimitedFungibleFaucet> for AccountComponent {
    fn from(faucet: UnlimitedFungibleFaucet) -> Self {
        let storage_slot: StorageSlot = faucet.metadata.into();

        let token_symbol_type = SchemaTypeId::new(TOKEN_SYMBOL_TYPE_ID).unwrap();
        
        let metadata_slot_schema = StorageSlotSchema::value(
            "Token metadata",
            [
                FeltSchema::felt("token_supply").with_default(Felt::new(0)),
                FeltSchema::felt("max_supply"),
                FeltSchema::u8("decimals"),
                FeltSchema::new_typed(token_symbol_type, "symbol"),
            ],
        );
        
        let schema_entry = (
            UnlimitedFungibleFaucet::metadata_slot().clone(),
            metadata_slot_schema
        );

        let storage_schema = StorageSchema::new(alloc::vec![schema_entry])
            .expect("storage schema valid");

        let metadata = AccountComponentMetadata::new(UnlimitedFungibleFaucet::NAME)
            .with_description("Unlimited fungible faucet component for minting and burning tokens")
            .with_supported_type(AccountType::FungibleFaucet)
            .with_storage_schema(storage_schema);

        AccountComponent::new(unlimited_fungible_faucet_library(), vec![storage_slot], metadata)
            .expect("unlimited fungible faucet component should satisfy the requirements of a valid account component")
    }
}

pub fn create_unlimited_fungible_faucet(
    init_seed: [u8; 32],
    symbol: TokenSymbol,
    decimals: u8,
    storage_mode: AccountStorageMode,
    auth_scheme: AuthScheme,
) -> Result<Account, FungibleFaucetError> {
    let distribute_proc_root = UnlimitedFungibleFaucet::distribute_digest();

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

    let faucet_component = UnlimitedFungibleFaucet::new(symbol, decimals)?;
    
    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(storage_mode)
        .with_auth_component(auth_component)
        .with_component(faucet_component)
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}
