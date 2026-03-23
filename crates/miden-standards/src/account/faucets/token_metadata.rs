use miden_protocol::account::{AccountStorage, StorageSlot, StorageSlotName};
use miden_protocol::asset::{FungibleAsset, TokenSymbol};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use super::FungibleFaucetError;

// CONSTANTS
// ================================================================================================

static METADATA_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::fungible_faucets::metadata")
        .expect("storage slot name should be valid")
});

// TOKEN METADATA
// ================================================================================================

/// Token metadata for fungible faucet accounts.
///
/// This struct encapsulates the metadata associated with a fungible token faucet:
/// - `token_supply`: The current amount of tokens issued by the faucet.
/// - `max_supply`: The maximum amount of tokens that can be issued.
/// - `decimals`: The number of decimal places for token amounts.
/// - `symbol`: The token symbol.
///
/// The metadata is stored in a single storage slot as:
/// `[token_supply, max_supply, decimals, symbol]`
#[derive(Debug, Clone)]
pub struct TokenMetadata {
    token_supply: Felt,
    max_supply: Felt,
    decimals: u8,
    symbol: TokenSymbol,
}

impl TokenMetadata {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of decimals supported.
    pub const MAX_DECIMALS: u8 = 12;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TokenMetadata`] with the specified metadata and zero token supply.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The decimals parameter exceeds [`Self::MAX_DECIMALS`].
    /// - The max supply parameter exceeds [`FungibleAsset::MAX_AMOUNT`].
    pub fn new(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
    ) -> Result<Self, FungibleFaucetError> {
        Self::with_supply(symbol, decimals, max_supply, Felt::ZERO)
    }

    /// Creates a new [`TokenMetadata`] with the specified metadata and token supply.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The decimals parameter exceeds [`Self::MAX_DECIMALS`].
    /// - The max supply parameter exceeds [`FungibleAsset::MAX_AMOUNT`].
    /// - The token supply exceeds the max supply.
    pub fn with_supply(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
        token_supply: Felt,
    ) -> Result<Self, FungibleFaucetError> {
        if decimals > Self::MAX_DECIMALS {
            return Err(FungibleFaucetError::TooManyDecimals {
                actual: decimals as u64,
                max: Self::MAX_DECIMALS,
            });
        }

        if max_supply.as_canonical_u64() > FungibleAsset::MAX_AMOUNT {
            return Err(FungibleFaucetError::MaxSupplyTooLarge {
                actual: max_supply.as_canonical_u64(),
                max: FungibleAsset::MAX_AMOUNT,
            });
        }

        if token_supply.as_canonical_u64() > max_supply.as_canonical_u64() {
            return Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply {
                token_supply: token_supply.as_canonical_u64(),
                max_supply: max_supply.as_canonical_u64(),
            });
        }

        Ok(Self {
            token_supply,
            max_supply,
            decimals,
            symbol,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the token metadata is stored.
    pub fn metadata_slot() -> &'static StorageSlotName {
        &METADATA_SLOT_NAME
    }

    /// Returns the current token supply (amount issued).
    pub fn token_supply(&self) -> Felt {
        self.token_supply
    }

    /// Returns the maximum token supply.
    pub fn max_supply(&self) -> Felt {
        self.max_supply
    }

    /// Returns the number of decimals.
    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Returns the token symbol.
    pub fn symbol(&self) -> &TokenSymbol {
        &self.symbol
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Sets the token_supply (in base units).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the token supply exceeds the max supply.
    pub fn with_token_supply(mut self, token_supply: Felt) -> Result<Self, FungibleFaucetError> {
        if token_supply.as_canonical_u64() > self.max_supply.as_canonical_u64() {
            return Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply {
                token_supply: token_supply.as_canonical_u64(),
                max_supply: self.max_supply.as_canonical_u64(),
            });
        }

        self.token_supply = token_supply;

        Ok(self)
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl TryFrom<Word> for TokenMetadata {
    type Error = FungibleFaucetError;

    /// Parses token metadata from a Word.
    ///
    /// The Word is expected to be in the format: `[token_supply, max_supply, decimals, symbol]`
    fn try_from(word: Word) -> Result<Self, Self::Error> {
        let [token_supply, max_supply, decimals, token_symbol] = *word;

        let symbol =
            TokenSymbol::try_from(token_symbol).map_err(FungibleFaucetError::InvalidTokenSymbol)?;

        let decimals = decimals.as_canonical_u64().try_into().map_err(|_| {
            FungibleFaucetError::TooManyDecimals {
                actual: decimals.as_canonical_u64(),
                max: Self::MAX_DECIMALS,
            }
        })?;

        Self::with_supply(symbol, decimals, max_supply, token_supply)
    }
}

impl From<TokenMetadata> for Word {
    fn from(metadata: TokenMetadata) -> Self {
        // Storage layout: [token_supply, max_supply, decimals, symbol]
        Word::new([
            metadata.token_supply,
            metadata.max_supply,
            Felt::from(metadata.decimals),
            metadata.symbol.as_element(),
        ])
    }
}

impl From<TokenMetadata> for StorageSlot {
    fn from(metadata: TokenMetadata) -> Self {
        StorageSlot::with_value(TokenMetadata::metadata_slot().clone(), metadata.into())
    }
}

impl TryFrom<&StorageSlot> for TokenMetadata {
    type Error = FungibleFaucetError;

    /// Tries to create [`TokenMetadata`] from a storage slot.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The slot name does not match the expected metadata slot name.
    /// - The slot value cannot be parsed as valid token metadata.
    fn try_from(slot: &StorageSlot) -> Result<Self, Self::Error> {
        if slot.name() != Self::metadata_slot() {
            return Err(FungibleFaucetError::SlotNameMismatch {
                expected: Self::metadata_slot().clone(),
                actual: slot.name().clone(),
            });
        }
        TokenMetadata::try_from(slot.value())
    }
}

impl TryFrom<&AccountStorage> for TokenMetadata {
    type Error = FungibleFaucetError;

    /// Tries to create [`TokenMetadata`] from account storage.
    fn try_from(storage: &AccountStorage) -> Result<Self, Self::Error> {
        let metadata_word = storage.get_item(TokenMetadata::metadata_slot()).map_err(|err| {
            FungibleFaucetError::StorageLookupFailed {
                slot_name: TokenMetadata::metadata_slot().clone(),
                source: err,
            }
        })?;

        TokenMetadata::try_from(metadata_word)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::asset::TokenSymbol;
    use miden_protocol::{Felt, Word};

    use super::*;

    #[test]
    fn token_metadata_new() {
        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 8u8;
        let max_supply = Felt::new(1_000_000);

        let metadata = TokenMetadata::new(symbol.clone(), decimals, max_supply).unwrap();

        assert_eq!(metadata.symbol(), &symbol);
        assert_eq!(metadata.decimals(), decimals);
        assert_eq!(metadata.max_supply(), max_supply);
        assert_eq!(metadata.token_supply(), Felt::ZERO);
    }

    #[test]
    fn token_metadata_with_supply() {
        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 8u8;
        let max_supply = Felt::new(1_000_000);
        let token_supply = Felt::new(500_000);

        let metadata =
            TokenMetadata::with_supply(symbol.clone(), decimals, max_supply, token_supply).unwrap();

        assert_eq!(metadata.symbol(), &symbol);
        assert_eq!(metadata.decimals(), decimals);
        assert_eq!(metadata.max_supply(), max_supply);
        assert_eq!(metadata.token_supply(), token_supply);
    }

    #[test]
    fn token_metadata_too_many_decimals() {
        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 13u8; // exceeds MAX_DECIMALS
        let max_supply = Felt::new(1_000_000);

        let result = TokenMetadata::new(symbol, decimals, max_supply);
        assert!(matches!(result, Err(FungibleFaucetError::TooManyDecimals { .. })));
    }

    #[test]
    fn token_metadata_max_supply_too_large() {
        use miden_protocol::asset::FungibleAsset;

        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 8u8;
        // FungibleAsset::MAX_AMOUNT is 2^63 - 1, so we use MAX_AMOUNT + 1 to exceed it
        let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT + 1);

        let result = TokenMetadata::new(symbol, decimals, max_supply);
        assert!(matches!(result, Err(FungibleFaucetError::MaxSupplyTooLarge { .. })));
    }

    #[test]
    fn token_metadata_to_word() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let symbol_felt = symbol.as_element();
        let decimals = 2u8;
        let max_supply = Felt::new(123);

        let metadata = TokenMetadata::new(symbol, decimals, max_supply).unwrap();
        let word: Word = metadata.into();

        // Storage layout: [token_supply, max_supply, decimals, symbol]
        assert_eq!(word[0], Felt::ZERO); // token_supply
        assert_eq!(word[1], max_supply);
        assert_eq!(word[2], Felt::from(decimals));
        assert_eq!(word[3], symbol_felt);
    }

    #[test]
    fn token_metadata_from_storage_slot() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(123);

        let original = TokenMetadata::new(symbol.clone(), decimals, max_supply).unwrap();
        let slot: StorageSlot = original.into();

        let restored = TokenMetadata::try_from(&slot).unwrap();

        assert_eq!(restored.symbol(), &symbol);
        assert_eq!(restored.decimals(), decimals);
        assert_eq!(restored.max_supply(), max_supply);
        assert_eq!(restored.token_supply(), Felt::ZERO);
    }

    #[test]
    fn token_metadata_roundtrip_with_supply() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(1000);
        let token_supply = Felt::new(500);

        let original =
            TokenMetadata::with_supply(symbol.clone(), decimals, max_supply, token_supply).unwrap();
        let word: Word = original.into();
        let restored = TokenMetadata::try_from(word).unwrap();

        assert_eq!(restored.symbol(), &symbol);
        assert_eq!(restored.decimals(), decimals);
        assert_eq!(restored.max_supply(), max_supply);
        assert_eq!(restored.token_supply(), token_supply);
    }
}
