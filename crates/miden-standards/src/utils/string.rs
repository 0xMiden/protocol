//! Fixed-width UTF-8 string stored as N Words (7 bytes/felt, length-prefixed).
//!
//! [`FixedWidthString<N>`] is the generic building block for encoding arbitrary UTF-8 strings into
//! a fixed number of storage words. `N` must be at most 9; with N=9 the capacity is 9×4×7−1 = 251
//! bytes, which is the maximum that fits in the u8 length prefix (leaving 251 bytes for payload).
//! The maximum storable string length is therefore **251 bytes** (when N=9).
//!
//! ## Buffer layout (N × 4 × 7 bytes)
//!
//! ```text
//! Byte 0:          string length (u8)
//! Bytes 1..1+len:  UTF-8 content
//! Remaining:       zero-padded
//! ```
//!
//! Each 7-byte chunk is stored as a little-endian `u64` with the high byte always zero, so the
//! value is always < 2^56 and fits safely in a Goldilocks field element.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use miden_protocol::{Felt, WORD_SIZE, Word};

// ENCODING CONSTANT
// ================================================================================================

/// Number of data bytes packed into each felt (7 bytes = 56 bits, always < Goldilocks prime).
const BYTES_PER_FELT: usize = 7;

// FIXED-WIDTH STRING
// ================================================================================================

/// A UTF-8 string stored in exactly `N` Words (N×4 felts, 7 bytes/felt, length-prefixed).
///
/// `N` must be at most 9. With N=9 the maximum storable string length is **251 bytes** (the
/// full buffer is 252 bytes, one of which is consumed by the length prefix). Higher-level wrapper
/// types may impose a tighter limit.
///
/// Using N=10 (or larger) fails at compile time:
///
/// ```compile_fail
/// # use miden_standards::utils::string::FixedWidthString;
/// let _ = FixedWidthString::<10>::CAPACITY; // assertion failed: N <= 9
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedWidthString<const N: usize>(Box<str>);

impl<const N: usize> Default for FixedWidthString<N> {
    fn default() -> Self {
        Self("".into())
    }
}

/// Maximum storable string length (one byte is used for the length prefix).
const MAX_PAYLOAD_BYTES: usize = 251;

impl<const N: usize> FixedWidthString<N> {
    /// Compile-time check: N must be at most 9 so that CAPACITY ≤ 251 and the length
    /// fits in the u8 prefix. (Referenced by CAPACITY so the assert is always evaluated.)
    const _CAPACITY_FITS_LENGTH_PREFIX: () = assert!(N <= 9);

    /// Maximum bytes that can be stored (full capacity of the N words minus the length byte).
    /// Never exceeds 251 because the length is encoded in a single u8 (bytes 0..=251).
    pub const CAPACITY: usize =
        N * 4 * BYTES_PER_FELT - 1 + (Self::_CAPACITY_FITS_LENGTH_PREFIX, 0).1;

    /// Creates a [`FixedWidthString`] from a UTF-8 string, validating it fits within capacity.
    pub fn new(value: &str) -> Result<Self, FixedWidthStringError> {
        if value.len() > Self::CAPACITY {
            return Err(FixedWidthStringError::TooLong {
                actual: value.len(),
                max: Self::CAPACITY,
            });
        }
        Ok(Self(value.into()))
    }

    /// Returns the string content.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encodes the string into `N` Words (7 bytes/felt, length-prefixed, zero-padded).
    pub fn to_words(&self) -> Vec<Word> {
        let n_felts = N * WORD_SIZE;
        let buf_len = n_felts * BYTES_PER_FELT;
        let bytes = self.0.as_bytes();
        debug_assert!(bytes.len() < buf_len);

        let mut buf = alloc::vec![0u8; buf_len];
        buf[0] = bytes.len() as u8;
        buf[1..1 + bytes.len()].copy_from_slice(bytes);

        (0..N)
            .map(|word_idx| {
                let felts: [Felt; 4] = core::array::from_fn(|felt_idx| {
                    let start = (word_idx * 4 + felt_idx) * BYTES_PER_FELT;
                    let mut le_bytes = [0u8; 8];
                    le_bytes[..BYTES_PER_FELT].copy_from_slice(&buf[start..start + BYTES_PER_FELT]);
                    Felt::try_from(u64::from_le_bytes(le_bytes))
                        .expect("7-byte LE value always fits in a Goldilocks felt")
                });
                Word::from(felts)
            })
            .collect()
    }

    /// Decodes a [`FixedWidthString`] from a slice of exactly `N` Words.
    pub fn try_from_words(words: &[Word]) -> Result<Self, FixedWidthStringError> {
        if words.len() != N {
            return Err(FixedWidthStringError::InvalidLength { expected: N, got: words.len() });
        }
        let n_felts = N * WORD_SIZE;
        let buf_len = n_felts * BYTES_PER_FELT;
        let mut buf = alloc::vec![0u8; buf_len];

        for (word_idx, word) in words.iter().enumerate() {
            for (felt_idx, felt) in word.as_slice().iter().enumerate() {
                let felt_value = felt.as_canonical_u64();
                let le_bytes = felt_value.to_le_bytes();
                if le_bytes[BYTES_PER_FELT] != 0 {
                    return Err(FixedWidthStringError::InvalidPadding);
                }
                let start = (word_idx * 4 + felt_idx) * BYTES_PER_FELT;
                buf[start..start + BYTES_PER_FELT].copy_from_slice(&le_bytes[..BYTES_PER_FELT]);
            }
        }

        let len = buf[0] as usize;
        if len > MAX_PAYLOAD_BYTES {
            return Err(FixedWidthStringError::InvalidLengthPrefix);
        }
        if len + 1 > buf_len {
            return Err(FixedWidthStringError::InvalidLengthPrefix);
        }
        String::from_utf8(buf[1..1 + len].to_vec())
            .map_err(FixedWidthStringError::InvalidUtf8)
            .map(|s| Self(s.into()))
    }
}

// ERROR TYPE
// ================================================================================================

/// Error type for [`FixedWidthString`] construction and decoding.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FixedWidthStringError {
    /// String exceeds the maximum capacity for this word width.
    #[error("string must be at most {max} bytes, got {actual}")]
    TooLong { actual: usize, max: usize },
    /// Decoded bytes are not valid UTF-8.
    #[error("string is not valid UTF-8")]
    InvalidUtf8(#[source] alloc::string::FromUtf8Error),
    /// A felt's high byte (byte index 7 in LE) is non-zero, violating the 7-bytes-per-felt
    /// invariant.
    #[error("felt high byte is non-zero (invalid padding)")]
    InvalidPadding,
    /// The length prefix byte claims more bytes than the buffer can hold, or the length is >= 252.
    #[error("length prefix is invalid or exceeds buffer capacity")]
    InvalidLengthPrefix,
    /// Slice length does not match the expected word count.
    #[error("expected {expected} words, got {got}")]
    InvalidLength { expected: usize, got: usize },
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_roundtrip() {
        let s: FixedWidthString<2> = FixedWidthString::new("").unwrap();
        let words = s.to_words();
        assert_eq!(words.len(), 2);
        let decoded = FixedWidthString::<2>::try_from_words(&words).unwrap();
        assert_eq!(decoded.as_str(), "");
    }

    #[test]
    fn ascii_roundtrip_2_words() {
        let s = FixedWidthString::<2>::new("hello").unwrap();
        let decoded = FixedWidthString::<2>::try_from_words(&s.to_words()).unwrap();
        assert_eq!(decoded.as_str(), "hello");
    }

    #[test]
    fn ascii_roundtrip_7_words() {
        let text = "A longer description that spans many felts";
        let s = FixedWidthString::<7>::new(text).unwrap();
        let decoded = FixedWidthString::<7>::try_from_words(&s.to_words()).unwrap();
        assert_eq!(decoded.as_str(), text);
    }

    #[test]
    fn utf8_multibyte_roundtrip() {
        // "café" — contains a 2-byte UTF-8 sequence
        let s = FixedWidthString::<2>::new("café").unwrap();
        let decoded = FixedWidthString::<2>::try_from_words(&s.to_words()).unwrap();
        assert_eq!(decoded.as_str(), "café");
    }

    #[test]
    fn exactly_at_capacity_accepted() {
        let cap = FixedWidthString::<2>::CAPACITY; // 2*4*7 - 1 = 55
        let s = "a".repeat(cap);
        assert!(FixedWidthString::<2>::new(&s).is_ok());
    }

    #[test]
    fn one_over_capacity_rejected() {
        let cap = FixedWidthString::<2>::CAPACITY;
        let s = "a".repeat(cap + 1);
        assert!(matches!(
            FixedWidthString::<2>::new(&s),
            Err(FixedWidthStringError::TooLong { .. })
        ));
    }

    #[test]
    fn capacity_7_words() {
        // 7*4*7 - 1 = 195
        assert_eq!(FixedWidthString::<7>::CAPACITY, 195);
        let s = "b".repeat(195);
        let fw = FixedWidthString::<7>::new(&s).unwrap();
        let decoded = FixedWidthString::<7>::try_from_words(&fw.to_words()).unwrap();
        assert_eq!(decoded.as_str(), s);
    }

    #[test]
    fn capacity_9_words_is_max() {
        // Max N is 9: 9*4*7 - 1 = 251 (one byte for length prefix).
        assert_eq!(FixedWidthString::<9>::CAPACITY, 251);
        let s = "x".repeat(251);
        let fw = FixedWidthString::<9>::new(&s).unwrap();
        let decoded = FixedWidthString::<9>::try_from_words(&fw.to_words()).unwrap();
        assert_eq!(decoded.as_str(), s);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn n10_would_exceed_length_prefix() {
        // N=10 would give 10*4*7 - 1 = 279 > 251, so it is disallowed. CAPACITY is defined so
        // that it depends on _CAPACITY_FITS_LENGTH_PREFIX; therefore any use of
        // FixedWidthString::<10> (e.g. CAPACITY) fails at compile time with "assertion failed: N <=
        // 9". That compile-time failure is also tested by the `compile_fail` doctest in the
        // doc comment above (on [`FixedWidthString`]).
        assert!(10 * 4 * BYTES_PER_FELT - 1 > MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn to_words_returns_correct_count() {
        let s = FixedWidthString::<7>::new("test").unwrap();
        assert_eq!(s.to_words().len(), 7);
    }

    #[test]
    fn wrong_word_count_returns_error() {
        let s = FixedWidthString::<2>::new("hi").unwrap();
        let words = s.to_words();
        // pass only 1 word instead of 2
        assert!(matches!(
            FixedWidthString::<2>::try_from_words(&words[..1]),
            Err(FixedWidthStringError::InvalidLength { expected: 2, got: 1 })
        ));
    }

    #[test]
    fn length_prefix_overflow_returns_invalid_length_prefix() {
        // The length byte (first byte of first felt) is set to 0xFF, which exceeds the buffer
        // and triggers InvalidLengthPrefix. (This is the low byte of the felt, not the high byte.)
        let overflow_len = Felt::try_from(0xff_u64).unwrap();
        let words = [
            Word::from([overflow_len, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        ];
        assert!(matches!(
            FixedWidthString::<2>::try_from_words(&words),
            Err(FixedWidthStringError::InvalidLengthPrefix)
        ));
    }

    #[test]
    fn felt_with_high_byte_set_returns_invalid_padding() {
        // Construct words where one felt has its 8th byte (LE index 7) non-zero, violating the
        // 7-bytes-per-felt invariant. Bit 63 set gives a valid Felt but invalid length/padding.
        let high_byte_non_zero = Felt::try_from(2u64.pow(63)).unwrap();
        let words = [
            Word::from([Felt::ZERO, high_byte_non_zero, Felt::ZERO, Felt::ZERO]),
            Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        ];
        assert!(matches!(
            FixedWidthString::<2>::try_from_words(&words),
            Err(FixedWidthStringError::InvalidPadding)
        ));
    }

    #[test]
    fn non_utf8_bytes_return_invalid_utf8() {
        // Encode raw bytes that are not valid UTF-8 (e.g. 0xFF byte in content).
        // Length byte = 1, content byte = 0xFF (invalid UTF-8 start byte).
        // Pack into first felt: LE bytes [1, 0xFF, 0, 0, 0, 0, 0] → u64 = 0x0000_0000_0000_ff01
        let raw: u64 = 0x0000_0000_0000_ff01;
        let bad_felt = Felt::try_from(raw).unwrap();
        let words = [
            Word::from([bad_felt, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        ];
        assert!(matches!(
            FixedWidthString::<2>::try_from_words(&words),
            Err(FixedWidthStringError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn default_is_empty_string() {
        let s: FixedWidthString<2> = FixedWidthString::default();
        assert_eq!(s.as_str(), "");
    }
}
