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
    pub fn to_u64(&self) -> Result<u64, EthAmountError> {
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
    pub fn to_u32(&self) -> Result<u32, EthAmountError> {
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

/// Miden Felt modulus: p = 2^64 - 2^32 + 1
const FELT_MODULUS: u128 = (1u128 << 64) - (1u128 << 32) + 1;

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
    let mut acc: u64 = 1;
    for _ in 0..scale {
        acc = acc.saturating_mul(10);
    }
    Ok(acc)
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
    /// - `z = x - y * 10^scale_exp` (the remainder/truncated amount)
    ///
    /// # Arguments
    /// * `scale_exp` - The scaling exponent (0-18)
    ///
    /// # Returns
    /// A tuple of `(Felt, u64)` where:
    /// - The first element is the scaled-down Miden amount as a Felt
    /// - The second element is the remainder (truncated precision)
    ///
    /// # Errors
    /// - [`EthAmountError::ScaleTooLarge`] if scale_exp > 18
    /// - [`EthAmountError::YNotCanonicalFelt`] if the result doesn't fit in a canonical Felt
    /// - [`EthAmountError::YDoesNotFitU64`] if the result doesn't fit in a u64
    /// - [`EthAmountError::RemainderTooLarge`] if the remainder doesn't fit in a u64
    ///
    /// # Example
    /// ```ignore
    /// let eth_amount = EthAmount::from_u64(1_000_000_000_000_000_000); // 1 ETH in wei
    /// let (miden_amount, remainder) = eth_amount.scale_to_felt_deterministic(12)?;
    /// // Result: 1_000_000 (1e6, Miden representation), remainder: 0
    /// ```
    pub fn scale_to_felt_deterministic(
        &self,
        scale_exp: u32,
    ) -> Result<(Felt, u64), EthAmountError> {
        let x = limbs_le_to_u256(self.0);
        let scale = U256::from(pow10_u64(scale_exp)?);

        let y_u256 = x / scale;
        let z_u256 = x - (y_u256 * scale);

        // Remainder must fit into u64 because 10^s <= 1e18 < 2^64
        let z_u64: u64 = z_u256.try_into().map_err(|_| EthAmountError::RemainderTooLarge)?;

        // y must fit into u64 and be canonical Felt (< p)
        let y_u64: u64 = y_u256.try_into().map_err(|_| EthAmountError::YDoesNotFitU64)?;

        if (y_u64 as u128) >= FELT_MODULUS {
            return Err(EthAmountError::YNotCanonicalFelt);
        }

        Ok((Felt::new(y_u64), z_u64))
    }

    /// Verifies that a given y value is the correct scaled-down amount.
    ///
    /// This implements the verification logic used in the MASM procedure:
    /// 1. Compute `prod = y * 10^scale_exp`
    /// 2. Check that `x >= prod` (no underflow)
    /// 3. Compute `z = x - prod`
    /// 4. Check that `z < 10^scale_exp` (remainder bounds)
    ///
    /// # Arguments
    /// * `scale_exp` - The scaling exponent (0-18)
    /// * `y_u64` - The claimed Miden amount to verify
    ///
    /// # Returns
    /// The remainder `z` if verification succeeds.
    ///
    /// # Errors
    /// - [`EthAmountError::ScaleTooLarge`] if scale_exp > 18
    /// - [`EthAmountError::YNotCanonicalFelt`] if y >= 2^64 - 2^32 + 1
    /// - [`EthAmountError::Underflow`] if x < y * 10^scale_exp
    /// - [`EthAmountError::RemainderTooLarge`] if z >= 10^scale_exp
    pub fn verify_scaled_down_amount(
        &self,
        scale_exp: u32,
        y_u64: u64,
    ) -> Result<u64, EthAmountError> {
        let x = limbs_le_to_u256(self.0);
        let scale_u64 = pow10_u64(scale_exp)?;
        let scale = U256::from(scale_u64);

        if (y_u64 as u128) >= FELT_MODULUS {
            return Err(EthAmountError::YNotCanonicalFelt);
        }

        // Compute y * 10^s (fits in u128, but embed into U256)
        let prod_u256 = U256::from((y_u64 as u128) * (scale_u64 as u128));

        if x < prod_u256 {
            return Err(EthAmountError::Underflow);
        }

        let z = x - prod_u256;

        // Must have z < 10^s
        if z >= scale {
            return Err(EthAmountError::RemainderTooLarge);
        }

        // Return remainder as u64 (safe since z < 10^s <= 1e18)
        let z_u64: u64 = z.try_into().map_err(|_| EthAmountError::RemainderTooLarge)?;
        Ok(z_u64)
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
