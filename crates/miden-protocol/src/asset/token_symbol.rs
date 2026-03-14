use alloc::fmt;
use alloc::string::String;

use super::{Felt, TokenSymbolError};

/// Represents a token symbol (e.g. "POL", "ETH").
///
/// Token Symbols can consist of up to 12 capital Latin characters, e.g. "C", "ETH", "MIDEN".
///
/// The symbol is stored as a [`String`] and can be converted to a [`Felt`] encoding via
/// [`as_element()`](Self::as_element).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenSymbol(String);

impl TokenSymbol {
    /// Maximum allowed length of the token string.
    pub const MAX_SYMBOL_LENGTH: usize = 12;

    /// The length of the set of characters that can be used in a token's name.
    pub const ALPHABET_LENGTH: u64 = 26;

    /// The minimum integer value of an encoded [`TokenSymbol`].
    ///
    /// This value encodes the "A" token symbol.
    pub const MIN_ENCODED_VALUE: u64 = 1;

    /// The maximum integer value of an encoded [`TokenSymbol`].
    ///
    /// This value encodes the "ZZZZZZZZZZZZ" token symbol.
    pub const MAX_ENCODED_VALUE: u64 = 2481152873203736562;

    /// Constructs a new [`TokenSymbol`] from a string, panicking on invalid input.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The length of the provided string is less than 1 or greater than 12.
    /// - The provided token string contains characters that are not uppercase ASCII.
    pub fn new_unchecked(symbol: &str) -> Self {
        Self::new(symbol).expect("invalid token symbol")
    }

    /// Creates a new [`TokenSymbol`] instance from the provided token name string.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The length of the provided string is less than 1 or greater than 12.
    /// - The provided token string contains characters that are not uppercase ASCII.
    pub fn new(symbol: &str) -> Result<Self, TokenSymbolError> {
        let len = symbol.len();

        if len == 0 || len > Self::MAX_SYMBOL_LENGTH {
            return Err(TokenSymbolError::InvalidLength(len));
        }

        for byte in symbol.as_bytes() {
            if !byte.is_ascii_uppercase() {
                return Err(TokenSymbolError::InvalidCharacter);
            }
        }

        Ok(Self(String::from(symbol)))
    }

    /// Returns the [`Felt`] encoding of this token symbol.
    ///
    /// The alphabet used in the encoding process consists of the Latin capital letters as defined
    /// in the ASCII table, having the length of 26 characters.
    ///
    /// The encoding is performed by multiplying the intermediate encoded value by the length of
    /// the used alphabet and adding the relative index of the character to it. At the end of the
    /// encoding process the length of the initial token string is added to the encoded value.
    ///
    /// Relative character index is computed by subtracting the index of the character "A" (65)
    /// from the index of the currently processing character, e.g., `A = 65 - 65 = 0`,
    /// `B = 66 - 65 = 1`, `...` , `Z = 90 - 65 = 25`.
    pub fn as_element(&self) -> Felt {
        let bytes = self.0.as_bytes();
        let len = bytes.len();

        let mut encoded_value: u64 = 0;
        let mut idx = 0;

        while idx < len {
            let digit = (bytes[idx] - b'A') as u64;
            encoded_value = encoded_value * Self::ALPHABET_LENGTH + digit;
            idx += 1;
        }

        // add token length to the encoded value to be able to decode the exact number of
        // characters
        encoded_value = encoded_value * Self::ALPHABET_LENGTH + len as u64;

        Felt::new(encoded_value)
    }
}

impl fmt::Display for TokenSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<TokenSymbol> for Felt {
    fn from(symbol: TokenSymbol) -> Self {
        symbol.as_element()
    }
}

impl From<&TokenSymbol> for Felt {
    fn from(symbol: &TokenSymbol) -> Self {
        symbol.as_element()
    }
}

impl TryFrom<&str> for TokenSymbol {
    type Error = TokenSymbolError;

    fn try_from(symbol: &str) -> Result<Self, Self::Error> {
        TokenSymbol::new(symbol)
    }
}

/// Decodes a [`Felt`] representation of the token symbol into a [`TokenSymbol`].
///
/// The alphabet used in the decoding process consists of the Latin capital letters as defined in
/// the ASCII table, having the length of 26 characters.
///
/// The decoding is performed by getting the modulus of the intermediate encoded value by the
/// length of the used alphabet and then dividing the intermediate value by the length of the
/// alphabet to shift to the next character. At the beginning of the decoding process the length
/// of the initial token string is obtained from the encoded value. After that the value obtained
/// after taking the modulus represents the relative character index, which then gets converted to
/// the ASCII index.
///
/// Final ASCII character index is computed by adding the index of the character "A" (65) to the
/// index of the currently processing character, e.g., `A = 0 + 65 = 65`, `B = 1 + 65 = 66`,
/// `...` , `Z = 25 + 65 = 90`.
impl TryFrom<Felt> for TokenSymbol {
    type Error = TokenSymbolError;

    fn try_from(felt: Felt) -> Result<Self, Self::Error> {
        let encoded_value = felt.as_canonical_u64();
        if encoded_value < Self::MIN_ENCODED_VALUE {
            return Err(TokenSymbolError::ValueTooSmall(encoded_value));
        }
        if encoded_value > Self::MAX_ENCODED_VALUE {
            return Err(TokenSymbolError::ValueTooLarge(encoded_value));
        }

        let mut decoded_string = String::new();
        let mut remaining_value = encoded_value;

        // get the token symbol length
        let token_len = (remaining_value % Self::ALPHABET_LENGTH) as usize;
        if token_len == 0 || token_len > Self::MAX_SYMBOL_LENGTH {
            return Err(TokenSymbolError::InvalidLength(token_len));
        }
        remaining_value /= Self::ALPHABET_LENGTH;

        for _ in 0..token_len {
            let digit = (remaining_value % Self::ALPHABET_LENGTH) as u8;
            let char = (digit + b'A') as char;
            decoded_string.insert(0, char);
            remaining_value /= Self::ALPHABET_LENGTH;
        }

        // return an error if some data still remains after specified number of characters have
        // been decoded.
        if remaining_value != 0 {
            return Err(TokenSymbolError::DataNotFullyDecoded);
        }

        Ok(TokenSymbol(decoded_string))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use alloc::string::ToString;

    use assert_matches::assert_matches;

    use super::{Felt, TokenSymbol, TokenSymbolError};

    #[test]
    fn test_token_symbol_decoding_encoding() {
        let symbols = vec![
            "AAAAAA",
            "AAAAB",
            "AAAC",
            "ABC",
            "BC",
            "A",
            "B",
            "ZZZZZZ",
            "ABCDEFGH",
            "MIDENCRYPTO",
            "ZZZZZZZZZZZZ",
        ];
        for symbol in symbols {
            let token_symbol = TokenSymbol::try_from(symbol).unwrap();
            let decoded_symbol = token_symbol.to_string();
            assert_eq!(symbol, decoded_symbol);
        }

        let err = TokenSymbol::new("").unwrap_err();
        assert_matches!(err, TokenSymbolError::InvalidLength(0));

        let err = TokenSymbol::new("ABCDEFGHIJKLM").unwrap_err();
        assert_matches!(err, TokenSymbolError::InvalidLength(13));

        let err = TokenSymbol::new("$$$").unwrap_err();
        assert_matches!(err, TokenSymbolError::InvalidCharacter);

        let symbol = "ABCDEFGHIJKL";
        let token_symbol = TokenSymbol::new(symbol).unwrap();
        let token_symbol_felt: Felt = token_symbol.into();
        assert_eq!(token_symbol_felt, TokenSymbol::new(symbol).unwrap().as_element());
    }

    /// Checks that if the encoded length of the token is less than the actual number of token
    /// characters, decoding should return the [TokenSymbolError::DataNotFullyDecoded] error.
    #[test]
    fn test_invalid_token_len() {
        // encoded value of this token has `6` as the length of the initial token string
        let encoded_symbol = TokenSymbol::try_from("ABCDEF").unwrap();

        // decrease encoded length by, for example, `3`
        let invalid_encoded_symbol_u64 = Felt::from(encoded_symbol).as_canonical_u64() - 3;

        // check that decoding returns an error for a token with invalid length
        let err = TokenSymbol::try_from(Felt::new(invalid_encoded_symbol_u64)).unwrap_err();
        assert_matches!(err, TokenSymbolError::DataNotFullyDecoded);
    }

    /// Utility test just to make sure that the [TokenSymbol::MAX_ENCODED_VALUE] constant still
    /// represents the maximum possible encoded value.
    #[test]
    fn test_token_symbol_max_value() {
        let token_symbol = TokenSymbol::try_from("ZZZZZZZZZZZZ").unwrap();
        assert_eq!(Felt::from(token_symbol).as_canonical_u64(), TokenSymbol::MAX_ENCODED_VALUE);
    }

    /// Utility test to make sure that the [TokenSymbol::MIN_ENCODED_VALUE] constant still
    /// represents the minimum possible encoded value.
    #[test]
    fn test_token_symbol_min_value() {
        let token_symbol = TokenSymbol::try_from("A").unwrap();
        assert_eq!(Felt::from(token_symbol).as_canonical_u64(), TokenSymbol::MIN_ENCODED_VALUE);
    }

    /// Checks that [TokenSymbol::try_from(Felt)] returns an error for values below the minimum.
    #[test]
    fn test_token_symbol_underflow() {
        let err = TokenSymbol::try_from(Felt::ZERO).unwrap_err();
        assert_matches!(err, TokenSymbolError::ValueTooSmall(0));
    }

    // new_unchecked tests
    // --------------------------------------------------------------------------------------------

    #[test]
    fn test_new_unchecked_matches_new() {
        // Test that new_unchecked produces the same result as new
        let symbols = ["A", "BC", "ETH", "MIDEN", "ZZZZZZ", "ABCDEFGH", "ZZZZZZZZZZZZ"];
        for symbol in symbols {
            let from_new = TokenSymbol::new(symbol).unwrap();
            let from_static = TokenSymbol::new_unchecked(symbol);
            assert_eq!(from_new, from_static, "Mismatch for symbol: {}", symbol);
        }
    }

    #[test]
    #[should_panic(expected = "invalid token symbol")]
    fn token_symbol_panics_on_empty_string() {
        TokenSymbol::new_unchecked("");
    }

    #[test]
    #[should_panic(expected = "invalid token symbol")]
    fn token_symbol_panics_on_too_long_string() {
        TokenSymbol::new_unchecked("ABCDEFGHIJKLM");
    }

    #[test]
    #[should_panic(expected = "invalid token symbol")]
    fn token_symbol_panics_on_lowercase() {
        TokenSymbol::new_unchecked("eth");
    }

    #[test]
    #[should_panic(expected = "invalid token symbol")]
    fn token_symbol_panics_on_invalid_character() {
        TokenSymbol::new_unchecked("ET$");
    }

    #[test]
    #[should_panic(expected = "invalid token symbol")]
    fn token_symbol_panics_on_number() {
        TokenSymbol::new_unchecked("ETH1");
    }
}
