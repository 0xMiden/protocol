use alloc::vec::Vec;

use miden_core::utils::bytes_to_packed_u32_elements;
use miden_protocol::Felt;
use miden_protocol::utils::{HexParseError, hex_to_bytes};

// ================================================================================================
// GLOBAL INDEX ERROR
// ================================================================================================

/// Error type for GlobalIndex validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalIndexError {
    /// The leading 160 bits of the global index are not zero.
    LeadingBitsNonZero,
    /// The mainnet flag is not 1.
    InvalidMainnetFlag,
    /// The rollup index is not zero for a mainnet deposit.
    RollupIndexNonZero,
}

// ================================================================================================
// GLOBAL INDEX
// ================================================================================================

/// Represents an AggLayer global index as a 256-bit value (32 bytes).
///
/// The global index is a uint256 that encodes (from MSB to LSB):
/// - Top 160 bits (limbs 0-4): must be zero
/// - 32 bits (limb 5): mainnet flag (value = 1 for mainnet, 0 for rollup)
/// - 32 bits (limb 6): rollup index (must be 0 for mainnet deposits)
/// - 32 bits (limb 7): leaf index (deposit index in the local exit tree)
///
/// Bytes are stored in big-endian order, matching Solidity's uint256 representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GlobalIndex([u8; 32]);

impl GlobalIndex {
    /// Creates a [`GlobalIndex`] from a hex string (with or without "0x" prefix).
    ///
    /// The hex string should represent a Solidity uint256 in big-endian format
    /// (64 hex characters for 32 bytes).
    pub fn from_hex(hex_str: &str) -> Result<Self, HexParseError> {
        let bytes: [u8; 32] = hex_to_bytes(hex_str)?;
        Ok(Self(bytes))
    }

    /// Creates a new [`GlobalIndex`] from a 32-byte array (big-endian).
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Validates that this is a valid mainnet deposit global index.
    ///
    /// Checks that:
    /// - The top 160 bits (limbs 0-4, bytes 0-19) are zero
    /// - The mainnet flag (limb 5, bytes 20-23) is exactly 1
    /// - The rollup index (limb 6, bytes 24-27) is 0
    pub fn validate_mainnet(&self) -> Result<(), GlobalIndexError> {
        // Check limbs 0-4 are zero (bytes 0-19)
        if self.0[0..20].iter().any(|&b| b != 0) {
            return Err(GlobalIndexError::LeadingBitsNonZero);
        }

        // Check mainnet flag limb (bytes 20-23) is exactly 1
        if !self.is_mainnet() {
            return Err(GlobalIndexError::InvalidMainnetFlag);
        }

        // Check rollup index is zero (bytes 24-27)
        if u32::from_be_bytes([self.0[24], self.0[25], self.0[26], self.0[27]]) != 0 {
            return Err(GlobalIndexError::RollupIndexNonZero);
        }

        Ok(())
    }

    /// Returns the leaf index (limb 7, lowest 32 bits).
    pub fn leaf_index(&self) -> u32 {
        u32::from_be_bytes([self.0[28], self.0[29], self.0[30], self.0[31]])
    }

    /// Returns the rollup index (limb 6).
    pub fn rollup_index(&self) -> u32 {
        u32::from_be_bytes([self.0[24], self.0[25], self.0[26], self.0[27]])
    }

    /// Returns true if this is a mainnet deposit (mainnet flag = 1).
    pub fn is_mainnet(&self) -> bool {
        u32::from_be_bytes([self.0[20], self.0[21], self.0[22], self.0[23]]) == 1
    }

    /// Converts to field elements for note storage / MASM processing.
    pub fn to_elements(&self) -> Vec<Felt> {
        bytes_to_packed_u32_elements(&self.0)
    }

    /// Returns the raw 32-byte array (big-endian).
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_global_indices_from_production() {
        // Real mainnet global indices from production
        // Format: (1 << 64) + leaf_index for mainnet deposits
        // 18446744073709786619 = 0x1_0000_0000_0003_95FB (leaf_index = 235003)
        // 18446744073709786590 = 0x1_0000_0000_0003_95DE (leaf_index = 234974)
        let test_cases = [
            ("0x00000000000000000000000000000000000000000000000100000000000395fb", 235003u32),
            ("0x00000000000000000000000000000000000000000000000100000000000395de", 234974u32),
        ];

        for (hex, expected_leaf_index) in test_cases {
            let gi = GlobalIndex::from_hex(hex).expect("valid hex");

            // Validate as mainnet
            assert!(gi.validate_mainnet().is_ok(), "should be valid mainnet global index");

            // Construction sanity checks
            assert!(gi.is_mainnet());
            assert_eq!(gi.rollup_index(), 0);
            assert_eq!(gi.leaf_index(), expected_leaf_index);

            // Verify to_elements produces correct LE-packed u32 felts
            // --------------------------------------------------------------------------------

            let elements = gi.to_elements();
            assert_eq!(elements.len(), 8);

            // leading zeros
            assert_eq!(elements[0..5], [Felt::ZERO; 5]);

            // mainnet flag: BE value 1 → LE-packed as 0x01000000
            assert_eq!(elements[5], Felt::new(u32::from_le_bytes(1u32.to_be_bytes()) as u64));

            // rollup index
            assert_eq!(elements[6], Felt::ZERO);

            // leaf index: BE value → LE-packed
            assert_eq!(
                elements[7],
                Felt::new(u32::from_le_bytes(expected_leaf_index.to_be_bytes()) as u64)
            );
        }
    }
}
