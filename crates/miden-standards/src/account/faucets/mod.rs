use miden_protocol::account::StorageSlotName;
use miden_protocol::errors::{AccountError, TokenSymbolError};
use thiserror::Error;

use crate::account::access::Ownable2StepError;
use crate::account::policies::{BurnOwnerOnly, MintOwnerOnly, TokenPolicyManager};
use crate::utils::FixedWidthStringError;

mod fungible;
mod non_fungible;
#[cfg(test)]
mod test_utils;
mod token_metadata;

pub use fungible::{
    FungibleFaucet,
    FungibleFaucetBuilder,
    create_guarded_user_fungible_faucet,
    create_multisig_user_fungible_faucet,
    create_native_fungible_faucet_for_genesis,
    create_network_fungible_faucet,
    create_singlesig_user_fungible_faucet,
};
pub use non_fungible::{
    AssetStatus,
    NonFungibleFaucet,
    NonFungibleFaucetBuilder,
    create_network_non_fungible_faucet,
    create_user_non_fungible_faucet,
};
pub use token_metadata::{Description, ExternalLink, LogoURI, TokenMetadata, TokenName};

// OWNER-ONLY POLICY DEPENDENCY CHECK
// ================================================================================================

/// Returns `true` if `token_policy_manager` registers an owner-gated mint or burn policy, either as
/// the active policy or as a reserved alternative that `set_mint_policy` / `set_burn_policy` can
/// activate later.
///
/// The owner-controlled policy family calls `ownable2step::assert_sender_is_owner`, which reads a
/// storage slot installed by [`Ownable2Step`](crate::account::access::Ownable2Step) and owned by no
/// policy component. A faucet registering such a policy without that component builds successfully
/// and then aborts on every dispatch to the policy, disabling minting or burning for the lifetime
/// of the account.
///
/// TODO: This is a temporary, faucet-specific check covering the one configuration the factories
/// can get wrong. Remove it once components can declare their dependencies generally
/// ([#2621](https://github.com/0xMiden/protocol/issues/2621)): the owner-only policy components
/// will then declare the ownership component themselves and every account is validated, not just
/// the ones these factories build.
pub(crate) fn registers_owner_only_policy(token_policy_manager: &TokenPolicyManager) -> bool {
    token_policy_manager.allowed_mint_policies().contains(&MintOwnerOnly::root())
        || token_policy_manager.allowed_burn_policies().contains(&BurnOwnerOnly::root())
}

// TOKEN METADATA ERROR
// ================================================================================================

/// Errors raised when parsing token metadata from storage.
#[derive(Debug, Error)]
pub enum TokenMetadataError {
    #[error("failed to retrieve storage slot with name {slot_name}")]
    StorageLookupFailed {
        slot_name: StorageSlotName,
        source: AccountError,
    },
    #[error("invalid string data in field '{field}'")]
    InvalidStringField {
        field: &'static str,
        #[source]
        source: FixedWidthStringError,
    },
    #[error("mutability flag at index {index} has invalid value {value}: must be 0 or 1")]
    InvalidMutabilityFlag { index: usize, value: u64 },
    #[error("storage slot name mismatch: expected {expected}, got {actual}")]
    SlotNameMismatch {
        expected: StorageSlotName,
        actual: StorageSlotName,
    },
    #[error("invalid token symbol")]
    InvalidTokenSymbol(#[source] TokenSymbolError),
}

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
    MissingFungibleFaucetInterface,
    #[error("account creation failed")]
    AccountError(#[source] AccountError),
    #[error("account is not a fungible faucet account")]
    NotAFungibleFaucetAccount,
    #[error("failed to read ownership data from storage")]
    OwnershipError(#[source] Ownable2StepError),
    #[error(
        "faucet registers an owner-gated mint or burn policy but does not install the Ownable2Step component the policy reads the owner from"
    )]
    OwnerOnlyPolicyWithoutOwnable2Step,
    #[error(transparent)]
    TokenMetadata(#[from] TokenMetadataError),
}

// NON-FUNGIBLE FAUCET ERROR
// ================================================================================================

/// Non-fungible (NFT) faucet related errors.
#[derive(Debug, Error)]
pub enum NonFungibleFaucetError {
    #[error("account creation failed")]
    AccountCreationFailed(#[source] AccountError),
    #[error("account is not a non-fungible faucet account")]
    NotANonFungibleFaucetAccount,
    #[error("asset status registry holds invalid status code {status}: must be 0, 1 or 2")]
    InvalidAssetStatus { status: u64 },
    #[error(
        "faucet registers an owner-gated mint or burn policy but does not install the Ownable2Step component the policy reads the owner from"
    )]
    OwnerOnlyPolicyWithoutOwnable2Step,
    #[error(transparent)]
    TokenMetadata(#[from] TokenMetadataError),
}
