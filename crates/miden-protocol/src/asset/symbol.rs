use alloc::fmt;
use alloc::string::String;

use super::{Felt, SymbolError};

/// Represents a generic symbol encoded into a [`Felt`] with a configurable alphabet.
///
/// Use [`Self::parse_token_symbol`] or [`Self::parse_role_symbol`] to construct a validated
/// symbol (same rules as [`crate::asset::TokenSymbol`] and [`crate::asset::RoleSymbol`]).
///
/// The symbol is stored as a [`String`] and can be converted to a [`Felt`] encoding via
/// [`as_element()`](Self::as_element), and decoded back via
/// [`try_from_encoded_felt()`](Self::try_from_encoded_felt).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol(String);

impl Symbol {
    /// Maximum allowed symbol length.
    pub const MAX_SYMBOL_LENGTH: usize = 12;

    /// Parses a token-style symbol: up to 12 uppercase ASCII Latin letters (`A`–`Z`).
    ///
    /// # Errors
    /// Returns an error if:
    /// - The length of the provided string is less than 1 or greater than 12.
    /// - The string contains a character that is not uppercase ASCII.
    pub fn parse_token_symbol(s: &str) -> Result<Self, SymbolError> {
        let len = s.len();
        if len == 0 || len > Self::MAX_SYMBOL_LENGTH {
            return Err(SymbolError::InvalidLength(len));
        }
        for byte in s.as_bytes() {
            if !byte.is_ascii_uppercase() {
                return Err(SymbolError::InvalidCharacter);
            }
        }
        Ok(Self(String::from(s)))
    }

    /// Parses a role-style symbol: up to 12 characters from `A`–`Z` and `_`.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The length of the provided string is less than 1 or greater than 12.
    /// - The string contains a character outside `A`–`Z` and `_`.
    pub fn parse_role_symbol(s: &str) -> Result<Self, SymbolError> {
        let len = s.len();
        if len == 0 || len > Self::MAX_SYMBOL_LENGTH {
            return Err(SymbolError::InvalidLength(len));
        }
        for byte in s.as_bytes() {
            if !byte.is_ascii_uppercase() && *byte != b'_' {
                return Err(SymbolError::InvalidRoleCharacter);
            }
        }
        Ok(Self(String::from(s)))
    }

    /// Returns the [`Felt`] encoding of this symbol.
    ///
    /// The alphabet used in the encoding process is provided by the `alphabet` argument.
    ///
    /// The encoding is performed by multiplying the intermediate encoded value by the length of
    /// the used alphabet and adding the relative index of each character. At the end of the
    /// encoding process, the length of the initial symbol string is added to the encoded value.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The symbol contains a character that is not part of the provided alphabet.
    pub fn as_element(&self, alphabet: &[u8]) -> Result<Felt, SymbolError> {
        let alphabet_len = alphabet.len() as u64;
        let mut encoded_value: u64 = 0;

        for byte in self.0.as_bytes() {
            let digit = alphabet
                .iter()
                .position(|ch| ch == byte)
                .map(|pos| pos as u64)
                .ok_or(SymbolError::InvalidCharacter)?;

            encoded_value = encoded_value * alphabet_len + digit;
        }

        // Append the original length so decoding is unambiguous.
        encoded_value = encoded_value * alphabet_len + self.0.len() as u64;
        Ok(Felt::new(encoded_value))
    }

    /// Decodes an encoded [`Felt`] value into a [`Symbol`].
    ///
    /// The alphabet used in the decoding process is provided by the `alphabet` argument.
    ///
    /// The decoding is performed by reading the encoded length from the least-significant digit,
    /// then repeatedly taking modulus by alphabet length to recover each character index.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The encoded value is outside of the provided `min_encoded_value..=max_encoded_value`.
    /// - The decoded symbol length is not between 1 and 12.
    /// - Decoding leaves non-zero trailing data.
    pub fn try_from_encoded_felt(
        felt: Felt,
        alphabet: &[u8],
        min_encoded_value: u64,
        max_encoded_value: u64,
    ) -> Result<Self, SymbolError> {
        let encoded_value = felt.as_canonical_u64();
        if encoded_value < min_encoded_value {
            return Err(SymbolError::ValueTooSmall(encoded_value));
        }
        if encoded_value > max_encoded_value {
            return Err(SymbolError::ValueTooLarge(encoded_value));
        }

        let alphabet_len = alphabet.len() as u64;
        let mut remaining_value = encoded_value;
        let symbol_len = (remaining_value % alphabet_len) as usize;
        if symbol_len == 0 || symbol_len > Self::MAX_SYMBOL_LENGTH {
            return Err(SymbolError::InvalidLength(symbol_len));
        }
        remaining_value /= alphabet_len;

        let mut decoded = String::new();
        for _ in 0..symbol_len {
            let digit = (remaining_value % alphabet_len) as usize;
            let char = *alphabet.get(digit).ok_or(SymbolError::InvalidCharacter)?;
            decoded.insert(0, char as char);
            remaining_value /= alphabet_len;
        }

        if remaining_value != 0 {
            return Err(SymbolError::DataNotFullyDecoded);
        }

        Ok(Self(decoded))
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use assert_matches::assert_matches;

    use super::{Felt, Symbol, SymbolError};

    #[test]
    fn symbol_encode_decode_roundtrip() {
        let symbol = Symbol::parse_token_symbol("MIDEN").unwrap();
        let encoded = symbol.as_element(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
        let decoded = Symbol::try_from_encoded_felt(
            encoded,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            1,
            2481152873203736562,
        )
        .unwrap();
        assert_eq!(decoded.to_string(), "MIDEN");
    }

    #[test]
    fn symbol_rejects_invalid_values() {
        assert_matches!(Symbol::parse_token_symbol("").unwrap_err(), SymbolError::InvalidLength(0));
        assert_matches!(
            Symbol::parse_token_symbol("ABCDEFGHIJKLM").unwrap_err(),
            SymbolError::InvalidLength(13)
        );
        assert_matches!(
            Symbol::parse_token_symbol("A_B").unwrap_err(),
            SymbolError::InvalidCharacter
        );

        assert_matches!(
            Symbol::parse_role_symbol("MINTER-ADMIN").unwrap_err(),
            SymbolError::InvalidRoleCharacter
        );

        let err = Symbol::try_from_encoded_felt(
            Felt::ZERO,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            1,
            2481152873203736562,
        )
        .unwrap_err();
        assert_matches!(err, SymbolError::ValueTooSmall(0));
    }
}
