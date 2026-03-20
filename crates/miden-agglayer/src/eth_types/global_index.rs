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
    /// The mainnet flag is not a valid boolean (must be exactly 0 or 1).
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

    /// Validates this global index.
    ///
    /// Checks that:
    /// - The top 160 bits (bytes 0-19) are zero
    /// - The mainnet flag (bytes 20-23) is exactly 0 or 1
    /// - For mainnet deposits (flag = 1): the rollup index is 0
    pub fn validate(&self) -> Result<(), GlobalIndexError> {
        // Check leading 160 bits are zero
        if self.0[0..20].iter().any(|&b| b != 0) {
            return Err(GlobalIndexError::LeadingBitsNonZero);
        }

        // Check mainnet flag is a valid boolean (exactly 0 or 1)
        let flag = self.mainnet_flag();
        if flag > 1 {
            return Err(GlobalIndexError::InvalidMainnetFlag);
        }

        // For mainnet deposits, rollup index must be zero
        if flag == 1 && self.rollup_index() != 0 {
            return Err(GlobalIndexError::RollupIndexNonZero);
        }

        Ok(())
    }

    /// Returns the raw mainnet flag value (limb 5, bytes 20-23).
    ///
    /// Valid values are 0 (rollup) or 1 (mainnet).
    pub fn mainnet_flag(&self) -> u32 {
        u32::from_be_bytes([self.0[20], self.0[21], self.0[22], self.0[23]])
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
        self.mainnet_flag() == 1
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
    fn test_rollup_global_index_validation() {
        // Rollup global index: mainnet_flag=0, rollup_index=5, leaf_index=42
        // Format: (rollup_index << 32) | leaf_index
        let mut bytes = [0u8; 32];
        // mainnet flag = 0 (bytes 20-23): already zero
        // rollup index = 5 (bytes 24-27, BE)
        bytes[27] = 5;
        // leaf index = 42 (bytes 28-31, BE)
        bytes[31] = 42;

        let gi = GlobalIndex::new(bytes);

        assert!(!gi.is_mainnet());
        assert_eq!(gi.rollup_index(), 5);
        assert_eq!(gi.leaf_index(), 42);
        assert!(gi.validate().is_ok());
        assert!(gi.validate().is_ok());
    }

    #[test]
    fn test_rollup_global_index_rejects_leading_bits() {
        let mut bytes = [0u8; 32];
        bytes[3] = 1; // non-zero leading bits
        bytes[27] = 5; // rollup index = 5
        bytes[31] = 42; // leaf index = 42

        let gi = GlobalIndex::new(bytes);
        assert_eq!(gi.validate(), Err(GlobalIndexError::LeadingBitsNonZero));
        assert_eq!(gi.validate(), Err(GlobalIndexError::LeadingBitsNonZero));
    }

    #[test]
    fn test_rollup_global_index_various_indices() {
        // Test with larger rollup index and leaf index values
        let test_cases = [
            (1u32, 0u32),  // first rollup, first leaf
            (7, 1000),     // rollup 7, leaf 1000
            (100, 999999), // larger values
        ];

        for (rollup_idx, leaf_idx) in test_cases {
            let mut bytes = [0u8; 32];
            bytes[24..28].copy_from_slice(&rollup_idx.to_be_bytes());
            bytes[28..32].copy_from_slice(&leaf_idx.to_be_bytes());

            let gi = GlobalIndex::new(bytes);
            assert!(!gi.is_mainnet());
            assert_eq!(gi.rollup_index(), rollup_idx);
            assert_eq!(gi.leaf_index(), leaf_idx);
            assert!(gi.validate().is_ok());
        }
    }

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
            assert!(gi.validate().is_ok(), "should be valid mainnet global index");

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

    #[test]
    fn test_invalid_mainnet_flag_rejected() {
        // mainnet flag = 3 (invalid, must be 0 or 1)
        let mut bytes = [0u8; 32];
        bytes[23] = 3;
        bytes[31] = 2;

        let gi = GlobalIndex::new(bytes);
        assert_eq!(gi.validate(), Err(GlobalIndexError::InvalidMainnetFlag));
    }
}
