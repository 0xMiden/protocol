use alloc::vec::Vec;

use miden_core::utils::bytes_to_packed_u32_elements;
use miden_protocol::Felt;
use miden_protocol::asset::FungibleAsset;
use primitive_types::U256;
use thiserror::Error;

// ================================================================================================
// ETHEREUM AMOUNT ERROR
// ================================================================================================

/// Error type for Ethereum amount conversions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EthAmountError {
    /// The amount doesn't fit in the target type.
    #[error("amount overflow: value doesn't fit in target type")]
    Overflow,
    /// The scaling factor is too large (> 18).
    #[error("scaling factor too large: maximum is 18")]
    ScaleTooLarge,
    /// The scaled-down value doesn't fit in a u64.
    #[error("scaled value doesn't fit in u64")]
    ScaledValueDoesNotFitU64,
    /// The scaled-down value exceeds the maximum fungible token amount.
    #[error("scaled value exceeds the maximum fungible token amount")]
    ScaledValueExceedsMaxFungibleAmount,
}

// ================================================================================================
// ETHEREUM AMOUNT
// ================================================================================================

/// Represents an Ethereum uint256 amount as 8 u32 values.
///
/// This type provides a more typed representation of Ethereum amounts compared to raw `[u32; 8]`
/// arrays, while maintaining compatibility with the existing MASM processing pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthAmount([u8; 32]);

impl EthAmount {
    /// Creates an [`EthAmount`] from a 32-byte array.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates an [`EthAmount`] from a decimal (uint) string.
    ///
    /// The string should contain only ASCII decimal digits (e.g. `"2000000000000000000"`).
    /// The value is stored as a 32-byte big-endian array, matching the Solidity uint256 layout.
    ///
    /// # Errors
    ///
    /// Returns [`EthAmountError`] if the string is empty, contains non-digit characters,
    /// or represents a value that overflows uint256.
    pub fn from_uint_str(s: &str) -> Result<Self, EthAmountError> {
        let value = U256::from_dec_str(s).map_err(|_| EthAmountError::Overflow)?;
        Ok(Self(value.to_big_endian()))
    }

    /// Converts the EthAmount to a U256 for easier arithmetic operations.
    pub fn to_u256(&self) -> U256 {
        U256::from_big_endian(&self.0)
    }

    /// Creates an EthAmount from a U256 value.
    ///
    /// This constructor is only available in test code to make test arithmetic easier.
    #[cfg(any(test, feature = "testing"))]
    pub fn from_u256(value: U256) -> Self {
        Self(value.to_big_endian())
    }

    /// Converts the amount to a vector of field elements for note storage.
    ///
    /// Each u32 value in the amount array is converted to a [`Felt`].
    pub fn to_elements(&self) -> Vec<Felt> {
        bytes_to_packed_u32_elements(&self.0)
    }

    /// Returns the raw 32-byte array.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ================================================================================================
// U256 SCALING DOWN HELPERS
// ================================================================================================

/// Maximum scaling factor for decimal conversions
const MAX_SCALING_FACTOR: u32 = 18;

/// Calculate 10^scale where scale is a u32 exponent.
///
/// # Errors
/// Returns [`EthAmountError::ScaleTooLarge`] if scale > 18.
fn pow10_u64(scale: u32) -> Result<u64, EthAmountError> {
    if scale > MAX_SCALING_FACTOR {
        return Err(EthAmountError::ScaleTooLarge);
    }
    Ok(10_u64.pow(scale))
}

impl EthAmount {
    /// Converts a U256 amount to a Miden Felt by scaling down by 10^scale_exp.
    ///
    /// This is the deterministic reference implementation that computes:
    /// - `y = floor(x / 10^scale_exp)` (the Miden amount as a Felt)
    ///
    /// # Arguments
    /// * `scale_exp` - The scaling exponent (0-18)
    ///
    /// # Returns
    /// The scaled-down Miden amount as a Felt
    ///
    /// # Errors
    /// - [`EthAmountError::ScaleTooLarge`] if scale_exp > 18
    /// - [`EthAmountError::ScaledValueDoesNotFitU64`] if the result doesn't fit in a u64
    /// - [`EthAmountError::ScaledValueExceedsMaxFungibleAmount`] if the scaled value exceeds the
    ///   maximum fungible token amount
    ///
    /// # Example
    /// ```ignore
    /// let eth_amount = EthAmount::from_u64(1_000_000_000_000_000_000); // 1 ETH in wei
    /// let miden_amount = eth_amount.scale_to_token_amount(12)?;
    /// // Result: 1_000_000 (1e6, Miden representation)
    /// ```
    pub fn scale_to_token_amount(&self, scale_exp: u32) -> Result<Felt, EthAmountError> {
        let x = self.to_u256();
        let scale = U256::from(pow10_u64(scale_exp)?);

        let y_u256 = x / scale;

        // y must fit into u64; canonical Felt is guaranteed by max amount bound
        let y_u64: u64 = y_u256.try_into().map_err(|_| EthAmountError::ScaledValueDoesNotFitU64)?;

        if y_u64 > FungibleAsset::MAX_AMOUNT {
            return Err(EthAmountError::ScaledValueExceedsMaxFungibleAmount);
        }

        // Safe because FungibleAsset::MAX_AMOUNT < Felt modulus
        let y_felt = Felt::try_from(y_u64).expect("scaled value must fit into canonical Felt");
        Ok(y_felt)
    }
}
