use alloc::vec::Vec;
use core::fmt;

use miden_core_lib::handlers::bytes_to_packed_u32_felts;
use miden_protocol::Felt;

// ================================================================================================
// ETHEREUM AMOUNT
// ================================================================================================

/// Represents an Ethereum uint256 amount as 8 u32 values.
///
/// This type provides a more typed representation of Ethereum amounts compared to raw `[u32; 8]`
/// arrays, while maintaining compatibility with the existing MASM processing pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthAmount([u8; 32]);

/// Error type for parsing an [`EthAmount`] from a decimal string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthAmountError {
    /// The input string was empty.
    EmptyString,
    /// The input string contained a non-digit character.
    InvalidDigit(char),
    /// The decimal value overflows a uint256 (32 bytes).
    Overflow,
}

impl fmt::Display for EthAmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EthAmountError::EmptyString => write!(f, "empty string"),
            EthAmountError::InvalidDigit(c) => write!(f, "invalid digit: '{c}'"),
            EthAmountError::Overflow => write!(f, "value overflows uint256"),
        }
    }
}

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
        if s.is_empty() {
            return Err(EthAmountError::EmptyString);
        }

        let mut bytes = [0u8; 32];

        for ch in s.chars() {
            let digit = ch.to_digit(10).ok_or(EthAmountError::InvalidDigit(ch))? as u16;

            // Multiply current value by 10 (big-endian, from LSB to MSB).
            let mut carry: u16 = 0;
            for byte in bytes.iter_mut().rev() {
                let val = (*byte as u16) * 10 + carry;
                *byte = val as u8;
                carry = val >> 8;
            }
            if carry != 0 {
                return Err(EthAmountError::Overflow);
            }

            // Add the digit.
            let mut carry = digit;
            for byte in bytes.iter_mut().rev() {
                let val = (*byte as u16) + carry;
                *byte = val as u8;
                carry = val >> 8;
                if carry == 0 {
                    break;
                }
            }
            if carry != 0 {
                return Err(EthAmountError::Overflow);
            }
        }

        Ok(Self(bytes))
    }

    /// Converts the amount to a vector of field elements for note storage.
    ///
    /// Each u32 value in the amount array is converted to a [`Felt`].
    pub fn to_elements(&self) -> Vec<Felt> {
        bytes_to_packed_u32_felts(&self.0)
    }

    /// Returns the raw 32-byte array.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uint_str_zero() {
        let amount = EthAmount::from_uint_str("0").unwrap();
        assert_eq!(amount.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn from_uint_str_small_value() {
        // 256 = 0x100
        let amount = EthAmount::from_uint_str("256").unwrap();
        let mut expected = [0u8; 32];
        expected[30] = 0x01;
        expected[31] = 0x00;
        assert_eq!(amount.as_bytes(), &expected);
    }

    #[test]
    fn from_uint_str_real_amount() {
        // 100000000000000 = 0x5af3107a4000 (from claim asset test vector)
        let amount = EthAmount::from_uint_str("100000000000000").unwrap();
        let mut expected = [0u8; 32];
        expected[26] = 0x00;
        expected[27] = 0x00;
        expected[28] = 0x5a;
        expected[29] = 0xf3;
        expected[30] = 0x10;
        expected[31] = 0x7a;
        // Actually let me compute this properly:
        // 100000000000000 = 0x5AF3107A4000
        // bytes: [0x00, ..., 0x00, 0x5A, 0xF3, 0x10, 0x7A, 0x40, 0x00]
        expected[26] = 0x5a;
        expected[27] = 0xf3;
        expected[28] = 0x10;
        expected[29] = 0x7a;
        expected[30] = 0x40;
        expected[31] = 0x00;
        assert_eq!(amount.as_bytes(), &expected);
    }

    #[test]
    fn from_uint_str_2e18() {
        // 2000000000000000000 = 0x1BC16D674EC80000 (from leaf value test vector)
        let amount = EthAmount::from_uint_str("2000000000000000000").unwrap();
        let mut expected = [0u8; 32];
        expected[24] = 0x1b;
        expected[25] = 0xc1;
        expected[26] = 0x6d;
        expected[27] = 0x67;
        expected[28] = 0x4e;
        expected[29] = 0xc8;
        expected[30] = 0x00;
        expected[31] = 0x00;
        assert_eq!(amount.as_bytes(), &expected);
    }

    #[test]
    fn from_uint_str_empty() {
        assert_eq!(EthAmount::from_uint_str(""), Err(EthAmountError::EmptyString));
    }

    #[test]
    fn from_uint_str_invalid_digit() {
        assert_eq!(EthAmount::from_uint_str("12x3"), Err(EthAmountError::InvalidDigit('x')));
    }
}
