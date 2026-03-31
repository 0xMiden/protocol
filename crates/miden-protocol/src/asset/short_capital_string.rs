use alloc::fmt;
use alloc::string::String;

use super::{Felt, ShortCapitalStringError};

/// A short string of uppercase ASCII (and optionally underscores) encoded into a [`Felt`] with a
/// configurable alphabet.
///
/// Use [`Self::from_ascii_uppercase`] or [`Self::from_ascii_uppercase_and_underscore`] to construct
/// a validated value (same rules as [`crate::asset::TokenSymbol`] and
/// [`crate::asset::RoleSymbol`]).
///
/// The text is stored as a [`String`] and can be converted to a [`Felt`] encoding via
/// [`as_element()`](Self::as_element), and decoded back via
/// [`try_from_encoded_felt()`](Self::try_from_encoded_felt).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShortCapitalString(String);

impl ShortCapitalString {
    /// Maximum allowed string length.
    pub const MAX_LENGTH: usize = 12;

    /// Constructs a value from up to 12 uppercase ASCII Latin letters (`A`–`Z`).
    ///
    /// # Errors
    /// Returns an error if:
    /// - The length of the provided string is less than 1 or greater than 12.
    /// - The string contains a character that is not uppercase ASCII.
    pub fn from_ascii_uppercase(s: &str) -> Result<Self, ShortCapitalStringError> {
        let len = s.len();
        if len == 0 || len > Self::MAX_LENGTH {
            return Err(ShortCapitalStringError::InvalidLength(len));
        }
        for byte in s.as_bytes() {
            if !byte.is_ascii_uppercase() {
                return Err(ShortCapitalStringError::InvalidCharacter);
            }
        }
        Ok(Self(String::from(s)))
    }

    /// Constructs a value from up to 12 characters from `A`–`Z` and `_`.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The length of the provided string is less than 1 or greater than 12.
    /// - The string contains a character outside `A`–`Z` and `_`.
    pub fn from_ascii_uppercase_and_underscore(s: &str) -> Result<Self, ShortCapitalStringError> {
        let len = s.len();
        if len == 0 || len > Self::MAX_LENGTH {
            return Err(ShortCapitalStringError::InvalidLength(len));
        }
        for byte in s.as_bytes() {
            if !byte.is_ascii_uppercase() && *byte != b'_' {
                return Err(ShortCapitalStringError::InvalidRoleCharacter);
            }
        }
        Ok(Self(String::from(s)))
    }

    /// Returns the [`Felt`] encoding of this string.
    ///
    /// The alphabet used in the encoding process is provided by the `alphabet` argument.
    ///
    /// The encoding is performed by multiplying the intermediate encoded value by the length of
    /// the used alphabet and adding the relative index of each character. At the end of the
    /// encoding process, the length of the initial string is added to the encoded value.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The string contains a character that is not part of the provided alphabet.
    pub fn as_element(&self, alphabet: &[u8]) -> Result<Felt, ShortCapitalStringError> {
        let alphabet_len = alphabet.len() as u64;
        let mut encoded_value: u64 = 0;

        for byte in self.0.as_bytes() {
            let digit = alphabet
                .iter()
                .position(|ch| ch == byte)
                .map(|pos| pos as u64)
                .ok_or(ShortCapitalStringError::InvalidCharacter)?;

            encoded_value = encoded_value * alphabet_len + digit;
        }

        // Append the original length so decoding is unambiguous.
        encoded_value = encoded_value * alphabet_len + self.0.len() as u64;
        Ok(Felt::new(encoded_value))
    }

    /// Decodes an encoded [`Felt`] value into a [`ShortCapitalString`].
    ///
    /// The alphabet used in the decoding process is provided by the `alphabet` argument.
    ///
    /// The decoding is performed by reading the encoded length from the least-significant digit,
    /// then repeatedly taking modulus by alphabet length to recover each character index.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The encoded value is outside of the provided `min_encoded_value..=max_encoded_value`.
    /// - The decoded length is not between 1 and 12.
    /// - Decoding leaves non-zero trailing data.
    pub fn try_from_encoded_felt(
        felt: Felt,
        alphabet: &[u8],
        min_encoded_value: u64,
        max_encoded_value: u64,
    ) -> Result<Self, ShortCapitalStringError> {
        let encoded_value = felt.as_canonical_u64();
        if encoded_value < min_encoded_value {
            return Err(ShortCapitalStringError::ValueTooSmall(encoded_value));
        }
        if encoded_value > max_encoded_value {
            return Err(ShortCapitalStringError::ValueTooLarge(encoded_value));
        }

        let alphabet_len = alphabet.len() as u64;
        let mut remaining_value = encoded_value;
        let string_len = (remaining_value % alphabet_len) as usize;
        if string_len == 0 || string_len > Self::MAX_LENGTH {
            return Err(ShortCapitalStringError::InvalidLength(string_len));
        }
        remaining_value /= alphabet_len;

        let mut decoded = String::new();
        for _ in 0..string_len {
            let digit = (remaining_value % alphabet_len) as usize;
            let char = *alphabet.get(digit).ok_or(ShortCapitalStringError::InvalidCharacter)?;
            decoded.insert(0, char as char);
            remaining_value /= alphabet_len;
        }

        if remaining_value != 0 {
            return Err(ShortCapitalStringError::DataNotFullyDecoded);
        }

        Ok(Self(decoded))
    }
}

impl fmt::Display for ShortCapitalString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use assert_matches::assert_matches;

    use super::{Felt, ShortCapitalString, ShortCapitalStringError};

    #[test]
    fn short_capital_string_encode_decode_roundtrip() {
        let s = ShortCapitalString::from_ascii_uppercase("MIDEN").unwrap();
        let encoded = s.as_element(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
        let decoded = ShortCapitalString::try_from_encoded_felt(
            encoded,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            1,
            2481152873203736562,
        )
        .unwrap();
        assert_eq!(decoded.to_string(), "MIDEN");
    }

    #[test]
    fn short_capital_string_rejects_invalid_values() {
        assert_matches!(
            ShortCapitalString::from_ascii_uppercase("").unwrap_err(),
            ShortCapitalStringError::InvalidLength(0)
        );
        assert_matches!(
            ShortCapitalString::from_ascii_uppercase("ABCDEFGHIJKLM").unwrap_err(),
            ShortCapitalStringError::InvalidLength(13)
        );
        assert_matches!(
            ShortCapitalString::from_ascii_uppercase("A_B").unwrap_err(),
            ShortCapitalStringError::InvalidCharacter
        );

        assert_matches!(
            ShortCapitalString::from_ascii_uppercase_and_underscore("MINTER-ADMIN").unwrap_err(),
            ShortCapitalStringError::InvalidRoleCharacter
        );

        let err = ShortCapitalString::try_from_encoded_felt(
            Felt::ZERO,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            1,
            2481152873203736562,
        )
        .unwrap_err();
        assert_matches!(err, ShortCapitalStringError::ValueTooSmall(0));
    }
}
