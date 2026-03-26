use alloc::fmt;
use alloc::string::String;

use super::{Felt, SymbolError};

/// Generic fixed-width symbol encoding over a custom ASCII alphabet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol(String);

impl Symbol {
    /// Maximum allowed symbol length.
    pub const MAX_SYMBOL_LENGTH: usize = 12;

    /// Creates a new symbol with custom character validation.
    pub fn new(
        symbol: &str,
        is_valid_char: impl Fn(u8) -> bool,
        invalid_char_error: SymbolError,
    ) -> Result<Self, SymbolError> {
        let len = symbol.len();
        if len == 0 || len > Self::MAX_SYMBOL_LENGTH {
            return Err(SymbolError::InvalidLength(len));
        }

        for byte in symbol.as_bytes() {
            if !is_valid_char(*byte) {
                return Err(invalid_char_error);
            }
        }

        Ok(Self(String::from(symbol)))
    }

    /// Encodes this symbol into a [`Felt`] using a custom alphabet.
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

    /// Decodes a symbol from a [`Felt`] using a custom alphabet and encoded bounds.
    pub fn try_from_felt(
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
        let symbol =
            Symbol::new("MIDEN", |byte| byte.is_ascii_uppercase(), SymbolError::InvalidCharacter)
                .unwrap();
        let encoded = symbol.as_element(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
        let decoded =
            Symbol::try_from_felt(encoded, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1, 2481152873203736562)
                .unwrap();
        assert_eq!(decoded.to_string(), "MIDEN");
    }

    #[test]
    fn symbol_rejects_invalid_values() {
        assert_matches!(
            Symbol::new("", |byte| byte.is_ascii_uppercase(), SymbolError::InvalidCharacter)
                .unwrap_err(),
            SymbolError::InvalidLength(0)
        );
        assert_matches!(
            Symbol::new(
                "ABCDEFGHIJKLM",
                |byte| byte.is_ascii_uppercase(),
                SymbolError::InvalidCharacter
            )
            .unwrap_err(),
            SymbolError::InvalidLength(13)
        );
        assert_matches!(
            Symbol::new("A_B", |byte| byte.is_ascii_uppercase(), SymbolError::InvalidCharacter)
                .unwrap_err(),
            SymbolError::InvalidCharacter
        );

        let err = Symbol::try_from_felt(
            Felt::ZERO,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            1,
            2481152873203736562,
        )
        .unwrap_err();
        assert_matches!(err, SymbolError::ValueTooSmall(0));
    }
}
