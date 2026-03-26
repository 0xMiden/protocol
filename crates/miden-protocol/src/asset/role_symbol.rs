use alloc::fmt;

use super::{Felt, RoleSymbolError, Symbol, SymbolError};

/// Represents a role symbol for role-based access control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleSymbol(Symbol);

impl RoleSymbol {
    pub const ALPHABET: &'static [u8; 27] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ_";
    pub const ALPHABET_LENGTH: u64 = 27;
    pub const MIN_ENCODED_VALUE: u64 = 1;
    pub const MAX_ENCODED_VALUE: u64 = 4052555153018976252;

    pub fn new_unchecked(role_symbol: &str) -> Self {
        Self::new(role_symbol).expect("invalid role symbol")
    }

    pub fn new(role_symbol: &str) -> Result<Self, RoleSymbolError> {
        Symbol::new(
            role_symbol,
            |byte| byte.is_ascii_uppercase() || byte == b'_',
            SymbolError::InvalidRoleCharacter,
        )
        .map(Self)
        .map_err(Into::into)
    }

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

    fn try_from(felt: Felt) -> Result<Self, Self::Error> {
        Symbol::try_from_felt(
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

    use super::{Felt, RoleSymbol, RoleSymbolError};

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
