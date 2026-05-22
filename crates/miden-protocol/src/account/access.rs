use alloc::fmt;

use crate::Felt;
use crate::errors::RoleSymbolError;
use crate::utils::ShortCapitalString;

/// Represents a role symbol for role-based access control.
///
/// Role symbols can consist of up to 12 uppercase Latin characters and underscores, e.g.
/// "MINTER", "BURNER", "MINTER_ADMIN".
///
/// The label is stored internally as a validated short string (`A`–`Z` and `_`) and can be
/// converted to a [`Felt`] encoding via [`as_element()`](Self::as_element).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoleSymbol(ShortCapitalString);

impl RoleSymbol {
    /// Alphabet used for role symbols (`A-Z` and `_`).
    pub const ALPHABET: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_";

    /// The minimum integer value of an encoded [`RoleSymbol`].
    ///
    /// This value encodes the "A" role symbol.
    pub const MIN_ENCODED_VALUE: u64 = 1;

    /// The maximum integer value of an encoded [`RoleSymbol`].
    ///
    /// This value encodes the "____________" role symbol (12 underscores).
    pub const MAX_ENCODED_VALUE: u64 = 4052555153018976252;

    /// Constructs a new [`RoleSymbol`] from a string, panicking on invalid input.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The length of the provided string is less than 1 or greater than 12.
    /// - The provided role symbol contains characters outside `A-Z` and `_`.
    pub fn new_unchecked(role_symbol: &str) -> Self {
        Self::new(role_symbol).expect("invalid role symbol")
    }

    /// Creates a new [`RoleSymbol`] from the provided role symbol string.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The length of the provided string is less than 1 or greater than 12.
    /// - The provided role symbol contains characters outside `A-Z` and `_`.
    pub fn new(role_symbol: &str) -> Result<Self, RoleSymbolError> {
        ShortCapitalString::from_ascii_uppercase_and_underscore(role_symbol)
            .map(Self)
            .map_err(Into::into)
    }

    /// Returns the [`Felt`] encoding of this role symbol.
    pub fn as_element(&self) -> Felt {
        self.0.as_element(Self::ALPHABET).expect("RoleSymbol alphabet is always valid")
    }
}

impl fmt::Display for RoleSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<RoleSymbol> for Felt {
    fn from(role_symbol: RoleSymbol) -> Self {
        role_symbol.as_element()
    }
}

impl From<&RoleSymbol> for Felt {
    fn from(role_symbol: &RoleSymbol) -> Self {
        role_symbol.as_element()
    }
}

impl TryFrom<&str> for RoleSymbol {
    type Error = RoleSymbolError;

    fn try_from(role_symbol: &str) -> Result<Self, Self::Error> {
        Self::new(role_symbol)
    }
}

impl TryFrom<Felt> for RoleSymbol {
    type Error = RoleSymbolError;

    /// Decodes a [`Felt`] representation of the role symbol into a [`RoleSymbol`].
    fn try_from(felt: Felt) -> Result<Self, Self::Error> {
        ShortCapitalString::try_from_encoded_felt(
            felt,
            Self::ALPHABET,
            Self::MIN_ENCODED_VALUE,
            Self::MAX_ENCODED_VALUE,
        )
        .map(Self)
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use assert_matches::assert_matches;

    use super::{Felt, RoleSymbol};
    use crate::errors::RoleSymbolError;

    #[test]
    fn test_role_symbol_roundtrip_and_validation() {
        let role_symbols = ["MINTER", "BURNER", "MINTER_ADMIN", "A", "A_B_C"];
        for role_symbol in role_symbols {
            let encoded: Felt = RoleSymbol::new(role_symbol).unwrap().into();
            let decoded = RoleSymbol::try_from(encoded).unwrap();
            assert_eq!(decoded.to_string(), role_symbol);
        }

        assert_matches!(RoleSymbol::new("").unwrap_err(), RoleSymbolError::InvalidLength(0));
        assert_matches!(
            RoleSymbol::new("ABCDEFGHIJKLM").unwrap_err(),
            RoleSymbolError::InvalidLength(13)
        );
        assert_matches!(
            RoleSymbol::new("MINTER-ADMIN").unwrap_err(),
            RoleSymbolError::InvalidCharacter
        );
        assert_matches!(RoleSymbol::new("mINTER").unwrap_err(), RoleSymbolError::InvalidCharacter);
    }
}
