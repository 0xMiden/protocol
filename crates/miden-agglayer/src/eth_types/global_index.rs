use crate::utils::Keccak256Output;

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
pub type GlobalIndex = Keccak256Output;

/// Extension trait for [`GlobalIndex`] providing AggLayer-specific field accessors and validation.
///
/// These methods interpret the underlying 32-byte Keccak256 output as a structured global index
/// with mainnet flag, rollup index, and leaf index fields.
#[cfg(any(test, feature = "testing"))]
pub trait GlobalIndexExt {
    /// Validates this global index.
    ///
    /// Checks that:
    /// - The top 160 bits (bytes 0-19) are zero
    /// - The mainnet flag (bytes 20-23) is exactly 0 or 1
    /// - For mainnet deposits (flag = 1): the rollup index is 0
    fn validate(&self) -> Result<(), GlobalIndexError>;

    /// Returns the raw mainnet flag value (limb 5, bytes 20-23).
    ///
    /// Valid values are 0 (rollup) or 1 (mainnet).
    fn mainnet_flag(&self) -> u32;

    /// Returns the leaf index (limb 7, lowest 32 bits).
    fn leaf_index(&self) -> u32;

    /// Returns the rollup index (limb 6).
    fn rollup_index(&self) -> u32;

    /// Returns true if this is a mainnet deposit (mainnet flag = 1).
    fn is_mainnet(&self) -> bool;
}

#[cfg(any(test, feature = "testing"))]
impl GlobalIndexExt for GlobalIndex {
    fn validate(&self) -> Result<(), GlobalIndexError> {
        let bytes = self.as_bytes();
        // Check leading 160 bits are zero
        if bytes[0..20].iter().any(|&b| b != 0) {
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

    fn mainnet_flag(&self) -> u32 {
        let bytes = self.as_bytes();
        u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]])
    }

    fn leaf_index(&self) -> u32 {
        let bytes = self.as_bytes();
        u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]])
    }

    fn rollup_index(&self) -> u32 {
        let bytes = self.as_bytes();
        u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]])
    }

    fn is_mainnet(&self) -> bool {
        self.mainnet_flag() == 1
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
        use miden_protocol::Felt;

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
