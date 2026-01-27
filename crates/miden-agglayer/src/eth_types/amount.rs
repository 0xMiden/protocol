use core::fmt;

use miden_core::FieldElement;
use miden_protocol::Felt;
use primitive_types::U256;

// ================================================================================================
// ETHEREUM AMOUNT ERROR
// ================================================================================================

/// Error type for Ethereum amount conversions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthAmountError {
    /// The amount doesn't fit in the target type.
    Overflow,
    /// The scaling factor is too large (> 18).
    ScaleTooLarge,
    /// The computed y value is not a canonical Felt (>= 2^64 - 2^32 + 1).
    YNotCanonicalFelt,
    /// Underflow detected: x < y * 10^s.
    Underflow,
    /// The remainder is too large (>= 10^s).
    RemainderTooLarge,
    /// The y value doesn't fit in a u64.
    YDoesNotFitU64,
}

impl fmt::Display for EthAmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EthAmountError::Overflow => {
                write!(f, "amount overflow: value doesn't fit in target type")
            },
            EthAmountError::ScaleTooLarge => {
                write!(f, "scaling factor too large: maximum is 18")
            },
            EthAmountError::YNotCanonicalFelt => {
                write!(f, "y value is not a canonical Felt (must be < 2^64 - 2^32 + 1)")
            },
            EthAmountError::Underflow => {
                write!(f, "underflow detected: x < y * 10^s")
            },
            EthAmountError::RemainderTooLarge => {
                write!(f, "remainder too large: must be < 10^s")
            },
            EthAmountError::YDoesNotFitU64 => {
                write!(f, "y value doesn't fit in u64")
            },
        }
    }
}

impl core::error::Error for EthAmountError {}

// ================================================================================================
// ETHEREUM AMOUNT
// ================================================================================================

/// Represents an Ethereum uint256 amount as 8 u32 values.
///
/// This type provides a more typed representation of Ethereum amounts compared to raw `[u32; 8]`
/// arrays, while maintaining compatibility with the existing MASM processing pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthAmount([u32; 8]);

impl EthAmount {
    /// Creates a new [`EthAmount`] from an array of 8 u32 values.
    ///
    /// The values are stored in little-endian order where `values[0]` contains
    /// the least significant 32 bits.
    pub const fn new(values: [u32; 8]) -> Self {
        Self(values)
    }

    /// Creates an [`EthAmount`] from a single u64 value.
    ///
    /// This is useful for smaller amounts that fit in a u64. The value is
    /// stored in the first two u32 slots with the remaining slots set to zero.
    pub const fn from_u64(value: u64) -> Self {
        let low = value as u32;
        let high = (value >> 32) as u32;
        Self([low, high, 0, 0, 0, 0, 0, 0])
    }

    /// Creates an [`EthAmount`] from a single u32 value.
    ///
    /// This is useful for smaller amounts that fit in a u32. The value is
    /// stored in the first u32 slot with the remaining slots set to zero.
    pub const fn from_u32(value: u32) -> Self {
        Self([value, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Returns the raw array of 8 u32 values.
    pub const fn as_array(&self) -> &[u32; 8] {
        &self.0
    }

    /// Converts the amount into an array of 8 u32 values.
    pub const fn into_array(self) -> [u32; 8] {
        self.0
    }

    /// Returns true if the amount is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }

    /// Attempts to convert the amount to a u64.
    ///
    /// # Errors
    /// Returns [`EthAmountError::Overflow`] if the amount doesn't fit in a u64
    /// (i.e., if any of the upper 6 u32 values are non-zero).
    pub fn try_to_u64(&self) -> Result<u64, EthAmountError> {
        if self.0[2..].iter().any(|&x| x != 0) {
            Err(EthAmountError::Overflow)
        } else {
            Ok((self.0[1] as u64) << 32 | self.0[0] as u64)
        }
    }

    /// Attempts to convert the amount to a u32.
    ///
    /// # Errors
    /// Returns [`EthAmountError::Overflow`] if the amount doesn't fit in a u32
    /// (i.e., if any of the upper 7 u32 values are non-zero).
    pub fn try_to_u32(&self) -> Result<u32, EthAmountError> {
        if self.0[1..].iter().any(|&x| x != 0) {
            Err(EthAmountError::Overflow)
        } else {
            Ok(self.0[0])
        }
    }

    /// Converts the amount to a vector of field elements for note storage.
    ///
    /// Each u32 value in the amount array is converted to a [`Felt`].
    pub fn to_elements(&self) -> [Felt; 8] {
        let mut result = [Felt::ZERO; 8];
        for (i, &value) in self.0.iter().enumerate() {
            result[i] = Felt::new(value as u64);
        }
        result
    }

    /// Converts the EthAmount to a U256 for easier arithmetic operations.
    pub fn to_u256(&self) -> U256 {
        limbs_le_to_u256(self.0)
    }

    /// Creates an EthAmount from a U256 value.
    pub fn from_u256(value: U256) -> Self {
        let mut limbs = [0u32; 8];

        // U256 is stored as 4 u64 words in little-endian order
        // We need to split each u64 into two u32 limbs
        for i in 0..4 {
            let word = value.0[i];
            limbs[i * 2] = word as u32; // Low 32 bits
            limbs[i * 2 + 1] = (word >> 32) as u32; // High 32 bits
        }

        Self(limbs)
    }
}

impl From<[u32; 8]> for EthAmount {
    fn from(values: [u32; 8]) -> Self {
        Self(values)
    }
}

impl From<EthAmount> for [u32; 8] {
    fn from(amount: EthAmount) -> Self {
        amount.0
    }
}

impl From<u64> for EthAmount {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<u32> for EthAmount {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl fmt::Display for EthAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // For display purposes, show as a hex string of the full 256-bit value
        write!(f, "0x")?;
        for &value in self.0.iter().rev() {
            write!(f, "{:08x}", value)?;
        }
        Ok(())
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

/// Convert little-endian u32 limbs to U256.
fn limbs_le_to_u256(limbs: [u32; 8]) -> U256 {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let b = limb.to_le_bytes();
        bytes[i * 4..i * 4 + 4].copy_from_slice(&b);
    }
    U256::from_little_endian(&bytes)
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
    /// - [`EthAmountError::YNotCanonicalFelt`] if the result doesn't fit in a canonical Felt
    /// - [`EthAmountError::YDoesNotFitU64`] if the result doesn't fit in a u64
    ///
    /// # Example
    /// ```ignore
    /// let eth_amount = EthAmount::from_u64(1_000_000_000_000_000_000); // 1 ETH in wei
    /// let miden_amount = eth_amount.scale_to_felt_deterministic(12)?;
    /// // Result: 1_000_000 (1e6, Miden representation)
    /// ```
    pub fn scale_to_felt_deterministic(&self, scale_exp: u32) -> Result<Felt, EthAmountError> {
        let x = limbs_le_to_u256(self.0);
        let scale = U256::from(pow10_u64(scale_exp)?);

        let y_u256 = x / scale;

        // y must fit into u64 and be canonical Felt (< p)
        let y_u64: u64 = y_u256.try_into().map_err(|_| EthAmountError::YDoesNotFitU64)?;

        Felt::try_from(y_u64).map_err(|_| EthAmountError::YNotCanonicalFelt)
    }
}
