use alloc::fmt;
use alloc::string::String;

use crate::Felt;
use crate::errors::ShortCapitalStringError;

/// A short string of uppercase ASCII (and optionally underscores) encoded into a [`Felt`] with a
/// configurable alphabet.
///
/// Use [`Self::from_ascii_uppercase`] or [`Self::from_ascii_uppercase_and_underscore`] to construct
/// a validated value (same rules as [`crate::asset::TokenSymbol`] and
/// [`crate::account::RoleSymbol`]).
///
/// The text is stored as a [`String`] and can be converted to a [`Felt`] encoding via
/// [`as_element()`](Self::as_element), and decoded back via
/// [`try_from_encoded_felt()`](Self::try_from_encoded_felt).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ShortCapitalString(String);

impl ShortCapitalString {
    /// Maximum allowed string length.
    pub const MAX_LENGTH: usize = 12;

    /// Constructs a value from up to 12 uppercase ASCII Latin letters (`A`–`Z`).
    ///
    /// # Errors
    /// Returns an error if:
    /// - The number of characters is less than 1 or greater than 12.
    /// - The string contains a character that is not uppercase ASCII.
    pub fn from_ascii_uppercase(
        string: impl Into<String>,
    ) -> Result<Self, ShortCapitalStringError> {
        let string = string.into();
        let char_count = string.chars().count();
        if char_count == 0 || char_count > Self::MAX_LENGTH {
            return Err(ShortCapitalStringError::InvalidLength(char_count));
        }
        for character in string.chars() {
            if !character.is_ascii_uppercase() {
                return Err(ShortCapitalStringError::InvalidCharacter);
            }
        }
        Ok(Self(string))
    }

    /// Constructs a value from up to 12 characters from `A`–`Z` and `_`.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The number of characters is less than 1 or greater than 12.
    /// - The string contains a character outside `A`–`Z` and `_`.
    pub fn from_ascii_uppercase_and_underscore(
        string: impl Into<String>,
    ) -> Result<Self, ShortCapitalStringError> {
        let string = string.into();
        let char_count = string.chars().count();
        if char_count == 0 || char_count > Self::MAX_LENGTH {
            return Err(ShortCapitalStringError::InvalidLength(char_count));
        }
        for character in string.chars() {
            if !character.is_ascii_uppercase() && character != '_' {
                return Err(ShortCapitalStringError::InvalidCharacter);
            }
        }
        Ok(Self(string))
    }

    /// Returns the [`Felt`] encoding of this string.
    ///
    /// The alphabet used in the encoding process is provided by the `alphabet` argument.
    ///
    /// **Contract:** `alphabet` must contain **ASCII characters only**. Then each character
    /// occupies one UTF-8 byte, so the radix is [`str::len`] and matches the number of Unicode
    /// scalars.
    ///
    /// The encoding is performed by multiplying the intermediate encoded value by the length of
    /// the used alphabet and adding the relative index of each character. At the end of the
    /// encoding process, the character length of the initial string is added to the encoded value.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The string contains a character that is not part of the provided alphabet.
    pub fn as_element(&self, alphabet: &str) -> Result<Felt, ShortCapitalStringError> {
        debug_assert!(
            alphabet.is_ascii(),
            "ShortCapitalString::as_element: alphabet must be ASCII-only"
        );
        let alphabet_len = alphabet.len() as u64;
        let mut encoded_value: u64 = 0;

        for character in self.0.chars() {
            let digit = alphabet
                .chars()
                .position(|c| c == character)
                .map(|pos| pos as u64)
                .ok_or(ShortCapitalStringError::InvalidCharacter)?;

            encoded_value = encoded_value * alphabet_len + digit;
        }

        // Append the original length so decoding is unambiguous.
        let char_len = self.0.chars().count() as u64;
        encoded_value = encoded_value * alphabet_len + char_len;
        Ok(Felt::new(encoded_value))
    }

    /// Decodes an encoded [`Felt`] value into a [`ShortCapitalString`].
    ///
    /// `encoded_string` is the field element that carries the short-string encoding (as produced by
    /// [`as_element`](Self::as_element)).
    ///
    /// The alphabet used in the decoding process is provided by the `alphabet` argument. The same
    /// **ASCII-only** contract as [`as_element`](Self::as_element) applies; radix is [`str::len`].
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
        encoded_string: Felt,
        alphabet: &str,
        min_encoded_value: u64,
        max_encoded_value: u64,
    ) -> Result<Self, ShortCapitalStringError> {
        let encoded_value = encoded_string.as_canonical_u64();
        if encoded_value < min_encoded_value {
            return Err(ShortCapitalStringError::ValueTooSmall(encoded_value));
        }
        if encoded_value > max_encoded_value {
            return Err(ShortCapitalStringError::ValueTooLarge(encoded_value));
        }

        debug_assert!(
            alphabet.is_ascii(),
            "ShortCapitalString::try_from_encoded_felt: alphabet must be ASCII-only"
        );
        let alphabet_len = alphabet.len() as u64;
        let mut remaining_value = encoded_value;
        let string_len = (remaining_value % alphabet_len) as usize;
        if string_len == 0 || string_len > Self::MAX_LENGTH {
            return Err(ShortCapitalStringError::InvalidLength(string_len));
        }
        remaining_value /= alphabet_len;

        let mut decoded = String::with_capacity(string_len);
        for _ in 0..string_len {
            let digit = (remaining_value % alphabet_len) as usize;
            let character =
                alphabet.chars().nth(digit).ok_or(ShortCapitalStringError::InvalidCharacter)?;
            decoded.insert(0, character);
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
    use alloc::string::{String, ToString};

    use assert_matches::assert_matches;

    use super::{Felt, ShortCapitalString};
    use crate::errors::ShortCapitalStringError;

    #[test]
    fn short_capital_string_encode_decode_roundtrip() {
        let short_string = ShortCapitalString::from_ascii_uppercase("MIDEN").unwrap();
        let encoded = short_string.as_element("ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
        let decoded = ShortCapitalString::try_from_encoded_felt(
            encoded,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            1,
            2481152873203736562,
        )
        .unwrap();
        assert_eq!(decoded.to_string(), "MIDEN");

        let name = String::from("MIDEN");
        let from_name = ShortCapitalString::from_ascii_uppercase(name).unwrap();
        assert_eq!(from_name.to_string(), "MIDEN");
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
            ShortCapitalStringError::InvalidCharacter
        );

        let err = ShortCapitalString::try_from_encoded_felt(
            Felt::ZERO,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            1,
            2481152873203736562,
        )
        .unwrap_err();
        assert_matches!(err, ShortCapitalStringError::ValueTooSmall(0));
    }
}
