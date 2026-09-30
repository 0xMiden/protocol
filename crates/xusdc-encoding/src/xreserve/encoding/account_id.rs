//! Additional bytes32 conversion APIs for standard types.
//!
//! The AccountId layout `REQUIRES CIRCLE CONFIRMATION` and `REQUIRES IMPLEMENTATION VALIDATION` —
//! it stays an OPEN proposal to Circle.

use miden_standards::interop::eth::AddressConversionError;

use super::error::EncodingError;

// Re-export this type so callers don't need to depend on miden-standards directly.
pub use miden_standards::interop::eth::EthEmbeddedAccountId;

/// The inverse bytes32 decoding of [`EthEmbeddedAccountId::to_bytes32`].
pub trait EthEmbeddedAccountIdExt: Sized {
    /// Decodes the right-aligned bytes32 form — `bytes[0..16] = 0x00`, `bytes[16..24] = prefix` as
    /// u64 big-endian, `bytes[24..32] = suffix` as canonical u64 big-endian.
    ///
    /// The 16-byte zero pad is checked in two halves, because the container is: the leading 12
    /// bytes are this crate's to check, and the stock 20-byte decode owns the remaining four along
    /// with the field and canonicality checks.
    ///
    /// # Errors
    ///
    /// [`EncodingError::AccountIdOutOfRange`] if any pad byte is non-zero;
    /// [`EncodingError::NonCanonicalAccountId`] if the prefix/suffix do not form a canonical
    /// AccountId (an out-of-field felt or a failed `try_from_elements`).
    fn try_from_bytes32(bytes: [u8; 32]) -> Result<Self, EncodingError>;
}

impl EthEmbeddedAccountIdExt for EthEmbeddedAccountId {
    fn try_from_bytes32(bytes: [u8; 32]) -> Result<Self, EncodingError> {
        if bytes[..12] != [0u8; 12] {
            return Err(EncodingError::AccountIdOutOfRange);
        }

        let embedded: [u8; 20] = bytes[12..].try_into().expect("32 minus 12 is 20 bytes");
        Self::try_from(embedded).map_err(|source| match source {
            AddressConversionError::NonZeroBytePrefix => EncodingError::AccountIdOutOfRange,
            // the hex and Word variants belong to entry points this path never takes; a value that
            // is not an account id is what every remaining case means. The variants are unit, so
            // the source cannot be carried.
            _ => EncodingError::NonCanonicalAccountId,
        })
    }
}

// TESTS — TV-AID-1..3
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::vectors::{load, parse_hex32};

    /// TV-AID-1 (happy path, written first): round-trip is lossless for valid ids.
    #[test]
    fn tv_aid_1_roundtrip_lossless() {
        let v = load();
        for vec in v
            .families
            .aid
            .iter()
            .filter(|v| v.expected_variant.is_none())
        {
            let b = parse_hex32(&vec.bytes32);
            let embedded = EthEmbeddedAccountId::try_from_bytes32(b)
                .unwrap_or_else(|e| panic!("vector {}: must decode, got {e}", vec.id));
            assert_eq!(embedded.to_bytes32(), b, "vector {}: round-trip", vec.id);
        }
    }

    /// TV-AID-2 (negative): out-of-range bytes and in-region non-canonical ids are
    /// rejected with their specific variants.
    #[rstest]
    #[case::out_of_range("aid-rej-out-of-range")]
    #[case::non_canonical("aid-rej-non-canonical")]
    fn tv_aid_2_rejects(#[case] id: &str) {
        let v = load();
        let vec = v
            .families
            .aid
            .iter()
            .find(|v| v.id == id)
            .expect("vector present");
        let b = parse_hex32(&vec.bytes32);
        let result = EthEmbeddedAccountId::try_from_bytes32(b);
        match vec.expected_variant.as_deref() {
            Some("AccountIdOutOfRange") => {
                assert_matches!(
                    result,
                    Err(EncodingError::AccountIdOutOfRange),
                    "vector {id}"
                )
            }
            Some("NonCanonicalAccountId") => {
                assert_matches!(
                    result,
                    Err(EncodingError::NonCanonicalAccountId),
                    "vector {id}"
                )
            }
            other => panic!("vector {id}: unexpected expected_variant {other:?}"),
        }
    }

    /// Reject boundary of the fail-closed decode, per pad byte: a `0x01` at EVERY index of the
    /// leading 16-byte zero pad (not just byte 0, the canonical vector's shape) rejects with the
    /// EXACT `AccountIdOutOfRange`. The pad is checked in two halves — bytes 0..12 here, bytes
    /// 12..16 by the stock 20-byte decode — so the cases straddle the seam between them: a
    /// weakened check on either half would decode a padded wire form into a lossy,
    /// non-round-tripping AccountId.
    #[rstest]
    #[case::b0(0)]
    #[case::b1(1)]
    #[case::b2(2)]
    #[case::b3(3)]
    #[case::b4(4)]
    #[case::b5(5)]
    #[case::b6(6)]
    #[case::b7(7)]
    #[case::b8(8)]
    #[case::b9(9)]
    #[case::b10(10)]
    #[case::b11(11)]
    #[case::b12(12)]
    #[case::b13(13)]
    #[case::b14(14)]
    #[case::b15(15)]
    fn nonzero_pad_byte_rejects_at_every_index(#[case] pad_index: usize) {
        let v = load();
        let vec = v
            .families
            .aid
            .iter()
            .find(|v| v.id == "aid-rt-1")
            .expect("vector present");
        let mut b = parse_hex32(&vec.bytes32);
        b[pad_index] = 0x01;
        assert_matches!(
            EthEmbeddedAccountId::try_from_bytes32(b),
            Err(EncodingError::AccountIdOutOfRange),
            "pad byte {pad_index}"
        );
    }

    /// The `AccountIdOutOfRange` Display message must describe the SHIPPED layout — the
    /// account id region is the 16 bytes `bytes[16..32]` (prefix u64 BE + suffix u64
    /// BE) behind a 16-byte zero pad (see the message in `error.rs`).
    #[test]
    fn account_id_out_of_range_message_names_16_byte_region() {
        assert_eq!(
            EncodingError::AccountIdOutOfRange.to_string(),
            "bytes set outside the 16-byte account id region",
            "the AccountIdOutOfRange message must match the shipped 16-byte-pad layout"
        );
    }
}
