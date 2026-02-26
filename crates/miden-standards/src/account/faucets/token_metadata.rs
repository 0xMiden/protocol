use miden_protocol::account::{AccountStorage, StorageSlot, StorageSlotName};
use miden_protocol::asset::{FungibleAsset, TokenSymbol};
use miden_protocol::{Felt, Word};

use super::FungibleFaucetError;
use crate::account::metadata::{self, FieldBytesError, NameUtf8Error};

// TOKEN NAME
// ================================================================================================

/// Token display name (max 32 bytes UTF-8), stored as 2 Words in the metadata Info component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenName([Word; 2]);

impl TokenName {
    /// Creates a token name from a UTF-8 string (at most 32 bytes).
    pub fn try_from(s: &str) -> Result<Self, NameUtf8Error> {
        let words = metadata::name_from_utf8(s)?;
        Ok(Self(words))
    }

    /// Returns the name as two Words for storage in the Info component.
    pub fn as_words(&self) -> [Word; 2] {
        self.0
    }
}

// DESCRIPTION
// ================================================================================================

/// Token description (max 192 bytes), stored as 6 Words in the metadata Info component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Description([Word; 6]);

impl Description {
    /// Creates a description from a byte slice (at most 192 bytes).
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, FieldBytesError> {
        let words = metadata::field_from_bytes(bytes)?;
        Ok(Self(words))
    }

    /// Creates a description from a string (encoded as UTF-8 bytes; at most 192 bytes).
    pub fn try_from(s: &str) -> Result<Self, FieldBytesError> {
        Self::try_from_bytes(s.as_bytes())
    }

    /// Returns the description as six Words for storage in the Info component.
    pub fn as_words(&self) -> [Word; 6] {
        self.0
    }
}

// LOGO URI
// ================================================================================================

/// Token logo URI (max 192 bytes), stored as 6 Words in the metadata Info component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogoURI([Word; 6]);

impl LogoURI {
    /// Creates a logo URI from a byte slice (at most 192 bytes).
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, FieldBytesError> {
        let words = metadata::field_from_bytes(bytes)?;
        Ok(Self(words))
    }

    /// Creates a logo URI from a string (encoded as UTF-8 bytes; at most 192 bytes).
    pub fn try_from(s: &str) -> Result<Self, FieldBytesError> {
        Self::try_from_bytes(s.as_bytes())
    }

    /// Returns the logo URI as six Words for storage in the Info component.
    pub fn as_words(&self) -> [Word; 6] {
        self.0
    }
}

// EXTERNAL LINK
// ================================================================================================

/// Token external link (max 192 bytes), stored as 6 Words in the metadata Info component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalLink([Word; 6]);

impl ExternalLink {
    /// Creates an external link from a byte slice (at most 192 bytes).
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, FieldBytesError> {
        let words = metadata::field_from_bytes(bytes)?;
        Ok(Self(words))
    }

    /// Creates an external link from a string (encoded as UTF-8 bytes; at most 192 bytes).
    pub fn try_from(s: &str) -> Result<Self, FieldBytesError> {
        Self::try_from_bytes(s.as_bytes())
    }

    /// Returns the external link as six Words for storage in the Info component.
    pub fn as_words(&self) -> [Word; 6] {
        self.0
    }
}

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
///
/// `name` and optional `description`/`logo_uri`/`external_link` are not stored in that slot;
/// they are used only when building an account to populate the metadata Info component.
#[derive(Debug, Clone, Copy)]
pub struct TokenMetadata {
    token_supply: Felt,
    max_supply: Felt,
    decimals: u8,
    symbol: TokenSymbol,
    name: TokenName,
    description: Option<Description>,
    logo_uri: Option<LogoURI>,
    external_link: Option<ExternalLink>,
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
        name: TokenName,
        description: Option<Description>,
        logo_uri: Option<LogoURI>,
        external_link: Option<ExternalLink>,
    ) -> Result<Self, FungibleFaucetError> {
        Self::with_supply(
            symbol,
            decimals,
            max_supply,
            Felt::ZERO,
            name,
            description,
            logo_uri,
            external_link,
        )
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
        name: TokenName,
        description: Option<Description>,
        logo_uri: Option<LogoURI>,
        external_link: Option<ExternalLink>,
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
            name,
            description,
            logo_uri,
            external_link,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the token metadata is stored.
    /// Returns the storage slot name for token metadata (canonical slot shared with metadata
    /// module).
    pub fn metadata_slot() -> &'static StorageSlotName {
        metadata::token_metadata_slot()
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
    pub fn symbol(&self) -> TokenSymbol {
        self.symbol
    }

    /// Returns the token name (for Info component when building an account).
    pub fn name(&self) -> &TokenName {
        &self.name
    }

    /// Returns the optional description (for Info component when building an account).
    pub fn description(&self) -> Option<&Description> {
        self.description.as_ref()
    }

    /// Returns the optional logo URI (for Info component when building an account).
    pub fn logo_uri(&self) -> Option<&LogoURI> {
        self.logo_uri.as_ref()
    }

    /// Returns the optional external link (for Info component when building an account).
    pub fn external_link(&self) -> Option<&ExternalLink> {
        self.external_link.as_ref()
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

        // When parsing from storage, name is not available; use empty string.
        let name = TokenName::try_from("").expect("empty string should be valid");
        Self::with_supply(symbol, decimals, max_supply, token_supply, name, None, None, None)
    }
}

impl From<TokenMetadata> for Word {
    fn from(metadata: TokenMetadata) -> Self {
        // Storage layout: [token_supply, max_supply, decimals, symbol]
        Word::new([
            metadata.token_supply,
            metadata.max_supply,
            Felt::from(metadata.decimals),
            metadata.symbol.into(),
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
        let name = TokenName::try_from("TEST").unwrap();

        let metadata =
            TokenMetadata::new(symbol, decimals, max_supply, name, None, None, None).unwrap();

        assert_eq!(metadata.symbol(), symbol);
        assert_eq!(metadata.decimals(), decimals);
        assert_eq!(metadata.max_supply(), max_supply);
        assert_eq!(metadata.token_supply(), Felt::ZERO);
        assert_eq!(metadata.name(), &name);
        assert!(metadata.description().is_none());
        assert!(metadata.logo_uri().is_none());
        assert!(metadata.external_link().is_none());
    }

    #[test]
    fn token_metadata_with_supply() {
        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 8u8;
        let max_supply = Felt::new(1_000_000);
        let token_supply = Felt::new(500_000);
        let name = TokenName::try_from("TEST").unwrap();

        let metadata = TokenMetadata::with_supply(
            symbol,
            decimals,
            max_supply,
            token_supply,
            name,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(metadata.symbol(), symbol);
        assert_eq!(metadata.decimals(), decimals);
        assert_eq!(metadata.max_supply(), max_supply);
        assert_eq!(metadata.token_supply(), token_supply);
    }

    #[test]
    fn token_metadata_with_name_and_description() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(123);
        let name = TokenName::try_from("polygon").unwrap();
        let description = Description::try_from("A polygon token").unwrap();

        let metadata = TokenMetadata::new(
            symbol,
            decimals,
            max_supply,
            name,
            Some(description),
            None,
            None,
        )
        .unwrap();

        assert_eq!(metadata.symbol(), symbol);
        assert_eq!(metadata.name(), &name);
        assert_eq!(metadata.description(), Some(&description));
        // Word roundtrip does not include name/description
        let word: Word = metadata.into();
        let restored = TokenMetadata::try_from(word).unwrap();
        assert_eq!(restored.symbol(), symbol);
        assert!(restored.description().is_none());
    }

    #[test]
    fn token_name_try_from_valid() {
        let name = TokenName::try_from("polygon").unwrap();
        assert_eq!(metadata::name_to_utf8(&name.as_words()).unwrap(), "polygon");
    }

    #[test]
    fn token_name_try_from_too_long() {
        let s = "a".repeat(33);
        assert!(TokenName::try_from(&s).is_err());
    }

    #[test]
    fn description_try_from_valid() {
        let text = "A short description";
        let desc = Description::try_from(text).unwrap();
        let words = desc.as_words();
        let expected = metadata::field_from_bytes(text.as_bytes()).unwrap();
        assert_eq!(words, expected);
    }

    #[test]
    fn description_try_from_too_long() {
        let bytes = [0u8; 193];
        assert!(Description::try_from_bytes(&bytes).is_err());
    }

    #[test]
    fn logo_uri_try_from_valid() {
        let url = "https://example.com/logo.png";
        let uri = LogoURI::try_from(url).unwrap();
        let words = uri.as_words();
        let expected = metadata::field_from_bytes(url.as_bytes()).unwrap();
        assert_eq!(words, expected);
    }

    #[test]
    fn external_link_try_from_valid() {
        let url = "https://example.com";
        let link = ExternalLink::try_from(url).unwrap();
        let words = link.as_words();
        let expected = metadata::field_from_bytes(url.as_bytes()).unwrap();
        assert_eq!(words, expected);
    }

    #[test]
    fn token_metadata_too_many_decimals() {
        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 13u8; // exceeds MAX_DECIMALS
        let max_supply = Felt::new(1_000_000);
        let name = TokenName::try_from("TEST").unwrap();

        let result =
            TokenMetadata::new(symbol, decimals, max_supply, name, None, None, None);
        assert!(matches!(result, Err(FungibleFaucetError::TooManyDecimals { .. })));
    }

    #[test]
    fn token_metadata_max_supply_too_large() {
        use miden_protocol::asset::FungibleAsset;

        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 8u8;
        // FungibleAsset::MAX_AMOUNT is 2^63 - 1, so we use MAX_AMOUNT + 1 to exceed it
        let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT + 1);
        let name = TokenName::try_from("TEST").unwrap();

        let result =
            TokenMetadata::new(symbol, decimals, max_supply, name, None, None, None);
        assert!(matches!(result, Err(FungibleFaucetError::MaxSupplyTooLarge { .. })));
    }

    #[test]
    fn token_metadata_to_word() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(123);
        let name = TokenName::try_from("POL").unwrap();

        let metadata =
            TokenMetadata::new(symbol, decimals, max_supply, name, None, None, None).unwrap();
        let word: Word = metadata.into();

        // Storage layout: [token_supply, max_supply, decimals, symbol]
        assert_eq!(word[0], Felt::ZERO); // token_supply
        assert_eq!(word[1], max_supply);
        assert_eq!(word[2], Felt::from(decimals));
        assert_eq!(word[3], Felt::from(symbol));
    }

    #[test]
    fn token_metadata_from_storage_slot() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(123);
        let name = TokenName::try_from("POL").unwrap();

        let original =
            TokenMetadata::new(symbol, decimals, max_supply, name, None, None, None).unwrap();
        let slot: StorageSlot = original.into();

        let restored = TokenMetadata::try_from(&slot).unwrap();

        assert_eq!(restored.symbol(), symbol);
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
        let name = TokenName::try_from("POL").unwrap();

        let original = TokenMetadata::with_supply(
            symbol,
            decimals,
            max_supply,
            token_supply,
            name,
            None,
            None,
            None,
        )
        .unwrap();
        let word: Word = original.into();
        let restored = TokenMetadata::try_from(word).unwrap();

        assert_eq!(restored.symbol(), symbol);
        assert_eq!(restored.decimals(), decimals);
        assert_eq!(restored.max_supply(), max_supply);
        assert_eq!(restored.token_supply(), token_supply);
    }
}
