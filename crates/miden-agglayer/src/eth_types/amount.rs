use core::fmt;

use miden_core::FieldElement;
use miden_protocol::Felt;

// ================================================================================================
// ETHEREUM AMOUNT ERROR
// ================================================================================================

/// Error type for Ethereum amount conversions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthAmountError {
    /// The amount doesn't fit in the target type.
    Overflow,
}

impl fmt::Display for EthAmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EthAmountError::Overflow => {
                write!(f, "amount overflow: value doesn't fit in target type")
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
            result[i] = Felt::from(value);
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
