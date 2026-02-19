use alloc::string::String;

use miden_protocol::account::StorageSlotName;
use miden_protocol::errors::{AccountError, TokenSymbolError};
use thiserror::Error;

mod basic_fungible;
mod network_fungible;
mod timed_fungible;
mod timed_unlimited_fungible;
mod token_metadata;
mod unlimited_fungible;

pub use basic_fungible::{BasicFungibleFaucet, create_basic_fungible_faucet};
pub use network_fungible::{NetworkFungibleFaucet, create_network_fungible_faucet};
pub use timed_fungible::{TimedFungibleFaucet, create_timed_fungible_faucet};
pub use timed_unlimited_fungible::{
    TimedUnlimitedFungibleFaucet, create_timed_unlimited_fungible_faucet,
};
pub use token_metadata::TokenMetadata;
pub use unlimited_fungible::{UnlimitedFungibleFaucet, create_unlimited_fungible_faucet};

// FUNGIBLE FAUCET ERROR
// ================================================================================================

/// Basic fungible faucet related errors.
#[derive(Debug, Error)]
pub enum FungibleFaucetError {
    #[error("faucet metadata decimals is {actual} which exceeds max value of {max}")]
    TooManyDecimals { actual: u64, max: u8 },
    #[error("faucet metadata max supply is {actual} which exceeds max value of {max}")]
    MaxSupplyTooLarge { actual: u64, max: u64 },
    #[error("token supply {token_supply} exceeds max_supply {max_supply}")]
    TokenSupplyExceedsMaxSupply { token_supply: u64, max_supply: u64 },
    #[error(
        "account interface does not have the procedures of the basic fungible faucet component"
    )]
    MissingBasicFungibleFaucetInterface,
    #[error(
        "account interface does not have the procedures of the network fungible faucet component"
    )]
    MissingNetworkFungibleFaucetInterface,
    #[error(
        "account interface does not have the procedures of the timed fungible faucet component"
    )]
    MissingTimedFungibleFaucetInterface,
    #[error(
        "account interface does not have the procedures of the unlimited fungible faucet component"
    )]
    MissingUnlimitedFungibleFaucetInterface,
    #[error(
        "account interface does not have the procedures of the timed unlimited fungible faucet component"
    )]
    MissingTimedUnlimitedFungibleFaucetInterface,
    #[error("failed to retrieve storage slot with name {slot_name}")]
    StorageLookupFailed {
        slot_name: StorageSlotName,
        source: AccountError,
    },
    #[error("invalid token symbol")]
    InvalidTokenSymbol(#[source] TokenSymbolError),
    #[error("storage slot name mismatch: expected {expected}, got {actual}")]
    SlotNameMismatch {
        expected: StorageSlotName,
        actual: StorageSlotName,
    },
    #[error("unsupported authentication scheme: {0}")]
    UnsupportedAuthScheme(String),
    #[error("account creation failed")]
    AccountError(#[source] AccountError),
    #[error("account is not a fungible faucet account")]
    NotAFungibleFaucetAccount,
}
