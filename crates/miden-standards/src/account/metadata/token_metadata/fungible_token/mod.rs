use alloc::vec::Vec;

use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountStorage,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{FungibleAsset, TokenSymbol};
use miden_protocol::{Felt, Word};
use thiserror::Error;

use super::{TokenMetadata, TokenName};
use crate::account::components::fungible_token_metadata_library;
use crate::account::faucets::FungibleFaucetError;
use crate::account::metadata;
use crate::utils::string::{FixedWidthString, FixedWidthStringError};

pub mod builder;

pub use builder::FungibleTokenMetadataBuilder;

/// Schema type string for the token symbol field in fungible token metadata storage.
pub(super) const TOKEN_SYMBOL_TYPE: &str =
    "miden::standards::fungible_faucets::metadata::token_symbol";

// FIELD TYPES
// ================================================================================================

/// Maximum length of a metadata field (description, logo_uri, external_link) in bytes.
/// 7 Words = 28 felts × 7 bytes = 196 byte buffer − 1 length byte = 195 bytes.
pub(crate) const FIELD_MAX_BYTES: usize = 195;

/// Errors when encoding or decoding metadata fields.
#[derive(Debug, Clone, Error)]
pub enum FieldBytesError {
    /// Field exceeds the maximum of 195 bytes.
    #[error("field must be at most 195 bytes, got {0}")]
    TooLong(usize),
    /// Decoded bytes are not valid UTF-8.
    #[error("field is not valid UTF-8")]
    InvalidUtf8,
}

/// Token description (max 195 bytes UTF-8), stored in 7 Words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description(FixedWidthString<7>);

impl Description {
    /// Maximum byte length for a description (7 Words × 4 felts × 7 bytes − 1 length byte).
    pub const MAX_BYTES: usize = FIELD_MAX_BYTES;

    /// Creates a description from a UTF-8 string.
    pub fn new(s: &str) -> Result<Self, FieldBytesError> {
        FixedWidthString::<7>::new(s).map(Self).map_err(|e| match e {
            FixedWidthStringError::TooLong { actual, .. } => FieldBytesError::TooLong(actual),
            _ => FieldBytesError::InvalidUtf8,
        })
    }

    /// Returns the description as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Encodes the description into 7 Words for storage.
    pub fn to_words(&self) -> Vec<Word> {
        self.0.to_words()
    }

    /// Decodes a description from a 7-Word slice.
    pub fn try_from_words(words: &[Word]) -> Result<Self, FieldBytesError> {
        FixedWidthString::<7>::try_from_words(words)
            .map(Self)
            .map_err(|_| FieldBytesError::InvalidUtf8)
    }
}

/// Token logo URI (max 195 bytes UTF-8), stored in 7 Words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoURI(FixedWidthString<7>);

impl LogoURI {
    /// Maximum byte length for a logo URI (7 Words × 4 felts × 7 bytes − 1 length byte).
    pub const MAX_BYTES: usize = FIELD_MAX_BYTES;

    /// Creates a logo URI from a UTF-8 string.
    pub fn new(s: &str) -> Result<Self, FieldBytesError> {
        FixedWidthString::<7>::new(s).map(Self).map_err(|e| match e {
            FixedWidthStringError::TooLong { actual, .. } => FieldBytesError::TooLong(actual),
            _ => FieldBytesError::InvalidUtf8,
        })
    }

    /// Returns the logo URI as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Encodes the logo URI into 7 Words for storage.
    pub fn to_words(&self) -> Vec<Word> {
        self.0.to_words()
    }

    /// Decodes a logo URI from a 7-Word slice.
    pub fn try_from_words(words: &[Word]) -> Result<Self, FieldBytesError> {
        FixedWidthString::<7>::try_from_words(words)
            .map(Self)
            .map_err(|_| FieldBytesError::InvalidUtf8)
    }
}

/// Token external link (max 195 bytes UTF-8), stored in 7 Words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLink(FixedWidthString<7>);

impl ExternalLink {
    /// Maximum byte length for an external link (7 Words × 4 felts × 7 bytes − 1 length byte).
    pub const MAX_BYTES: usize = FIELD_MAX_BYTES;

    /// Creates an external link from a UTF-8 string.
    pub fn new(s: &str) -> Result<Self, FieldBytesError> {
        FixedWidthString::<7>::new(s).map(Self).map_err(|e| match e {
            FixedWidthStringError::TooLong { actual, .. } => FieldBytesError::TooLong(actual),
            _ => FieldBytesError::InvalidUtf8,
        })
    }

    /// Returns the external link as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Encodes the external link into 7 Words for storage.
    pub fn to_words(&self) -> Vec<Word> {
        self.0.to_words()
    }

    /// Decodes an external link from a 7-Word slice.
    pub fn try_from_words(words: &[Word]) -> Result<Self, FieldBytesError> {
        FixedWidthString::<7>::try_from_words(words)
            .map(Self)
            .map_err(|_| FieldBytesError::InvalidUtf8)
    }
}

// FUNGIBLE TOKEN METADATA
// ================================================================================================

#[derive(Debug, Clone)]
pub struct FungibleTokenMetadata {
    token_supply: Felt,
    max_supply: Felt,
    decimals: u8,
    symbol: TokenSymbol,
    /// Embeds name, optional fields, and mutability flags.
    metadata: TokenMetadata,
}

impl FungibleTokenMetadata {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of decimals supported.
    pub const MAX_DECIMALS: u8 = 12;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a builder for [`FungibleTokenMetadata`] with the required fields set.
    ///
    /// This is the main entry point for constructing metadata; optional fields and token supply
    /// can be set via the builder before calling [`FungibleTokenMetadataBuilder::build`].
    pub fn builder(
        name: TokenName,
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
    ) -> FungibleTokenMetadataBuilder {
        FungibleTokenMetadataBuilder::new(name, symbol, decimals, max_supply)
    }

    /// Creates a new [`FungibleTokenMetadata`] with the specified metadata and token supply.
    /// Used internally by the builder.
    #[doc(hidden)]
    pub(super) fn with_supply(
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

        let mut token_metadata = TokenMetadata::new().with_name(name);
        if let Some(desc) = description {
            token_metadata = token_metadata.with_description(desc, false);
        }
        if let Some(uri) = logo_uri {
            token_metadata = token_metadata.with_logo_uri(uri, false);
        }
        if let Some(link) = external_link {
            token_metadata = token_metadata.with_external_link(link, false);
        }

        Ok(Self {
            token_supply,
            max_supply,
            decimals,
            symbol,
            metadata: token_metadata,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the token metadata is stored (canonical slot shared
    /// with the metadata module).
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
    pub fn symbol(&self) -> &TokenSymbol {
        &self.symbol
    }

    /// Returns the token name.
    pub fn name(&self) -> &TokenName {
        self.metadata.name().expect("FungibleTokenMetadata always has a name")
    }

    /// Returns the optional description.
    pub fn description(&self) -> Option<&Description> {
        self.metadata.description()
    }

    /// Returns the optional logo URI.
    pub fn logo_uri(&self) -> Option<&LogoURI> {
        self.metadata.logo_uri()
    }

    /// Returns the optional external link.
    pub fn external_link(&self) -> Option<&ExternalLink> {
        self.metadata.external_link()
    }

    /// Returns the storage slot schema for the metadata slot.
    pub fn metadata_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        let token_symbol_type = SchemaType::new(TOKEN_SYMBOL_TYPE).expect("valid type");
        (
            Self::metadata_slot().clone(),
            StorageSlotSchema::value(
                "Token metadata",
                [
                    FeltSchema::felt("token_supply").with_default(Felt::new(0)),
                    FeltSchema::felt("max_supply"),
                    FeltSchema::u8("decimals"),
                    FeltSchema::new_typed(token_symbol_type, "symbol"),
                ],
            ),
        )
    }

    /// Returns the single storage slot for the metadata word
    /// `[token_supply, max_supply, decimals, symbol]`. Useful when only this slot is needed (e.g.
    /// for components that extend the fungible metadata with additional slots).
    pub fn metadata_word_slot(&self) -> StorageSlot {
        let word = Word::new([
            self.token_supply,
            self.max_supply,
            Felt::from(self.decimals),
            self.symbol.clone().into(),
        ]);
        StorageSlot::with_value(Self::metadata_slot().clone(), word)
    }

    /// Returns all the storage slots for this component (metadata word + name + config +
    /// description + logo_uri + external_link).
    pub fn storage_slots(&self) -> Vec<StorageSlot> {
        let mut slots: Vec<StorageSlot> = Vec::new();
        slots.push(self.metadata_word_slot());
        slots.extend(self.metadata.storage_slots());
        slots
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

    /// Sets whether the description can be updated by the owner.
    pub fn with_description_mutable(mut self, mutable: bool) -> Self {
        self.metadata = self.metadata.with_description_mutable(mutable);
        self
    }

    /// Sets whether the logo URI can be updated by the owner.
    pub fn with_logo_uri_mutable(mut self, mutable: bool) -> Self {
        self.metadata = self.metadata.with_logo_uri_mutable(mutable);
        self
    }

    /// Sets whether the external link can be updated by the owner.
    pub fn with_external_link_mutable(mut self, mutable: bool) -> Self {
        self.metadata = self.metadata.with_external_link_mutable(mutable);
        self
    }

    /// Sets whether the max supply can be updated by the owner.
    pub fn with_max_supply_mutable(mut self, mutable: bool) -> Self {
        self.metadata = self.metadata.with_max_supply_mutable(mutable);
        self
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl FungibleTokenMetadata {
    /// Reconstructs from the metadata word and the name/optionals/mutability read from storage.
    pub(crate) fn from_metadata_word_and_token_metadata(
        word: Word,
        metadata: TokenMetadata,
    ) -> Result<Self, FungibleFaucetError> {
        let [token_supply, max_supply, decimals, token_symbol] = *word;
        let symbol =
            TokenSymbol::try_from(token_symbol).map_err(FungibleFaucetError::InvalidTokenSymbol)?;
        let decimals = decimals.as_canonical_u64().try_into().map_err(|_| {
            FungibleFaucetError::TooManyDecimals {
                actual: decimals.as_canonical_u64(),
                max: Self::MAX_DECIMALS,
            }
        })?;
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
            metadata,
        })
    }
}

impl From<FungibleTokenMetadata> for AccountComponent {
    fn from(metadata: FungibleTokenMetadata) -> Self {
        let storage_schema = StorageSchema::new([FungibleTokenMetadata::metadata_slot_schema()])
            .expect("storage schema should be valid");

        let component_metadata = AccountComponentMetadata::new(
            "miden::standards::components::faucets::fungible_token_metadata",
            [AccountType::FungibleFaucet],
        )
        .with_description("Fungible token metadata component storing token metadata, name, mutability config, description, logo URI, and external link")
        .with_storage_schema(storage_schema);

        AccountComponent::new(
            fungible_token_metadata_library(),
            metadata.storage_slots(),
            component_metadata,
        )
        .expect("fungible token metadata component should satisfy the requirements of a valid account component")
    }
}

impl TryFrom<&AccountStorage> for FungibleTokenMetadata {
    type Error = FungibleFaucetError;

    /// Reconstructs [`FungibleTokenMetadata`] by reading all relevant storage slots: the metadata
    /// word, name, mutability config, description, logo URI, and external link.
    fn try_from(storage: &AccountStorage) -> Result<Self, Self::Error> {
        let metadata_word = storage.get_item(Self::metadata_slot()).map_err(|err| {
            FungibleFaucetError::StorageLookupFailed {
                slot_name: Self::metadata_slot().clone(),
                source: err,
            }
        })?;

        let (name, description, logo_uri, external_link) =
            TokenMetadata::read_metadata_from_storage(storage);

        let mutability_word = storage
            .get_item(metadata::mutability_config_slot())
            .unwrap_or_else(|_| Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO]));

        let name = name.unwrap_or_default();
        let mut token_metadata = TokenMetadata::new().with_name(name);
        if let Some(d) = description {
            token_metadata = token_metadata.with_description(d, mutability_word[0] != Felt::ZERO);
        }
        if let Some(l) = logo_uri {
            token_metadata = token_metadata.with_logo_uri(l, mutability_word[1] != Felt::ZERO);
        }
        if let Some(e) = external_link {
            token_metadata = token_metadata.with_external_link(e, mutability_word[2] != Felt::ZERO);
        }
        token_metadata = token_metadata
            .with_description_mutable(mutability_word[0] != Felt::ZERO)
            .with_logo_uri_mutable(mutability_word[1] != Felt::ZERO)
            .with_external_link_mutable(mutability_word[2] != Felt::ZERO)
            .with_max_supply_mutable(mutability_word[3] != Felt::ZERO);

        Self::from_metadata_word_and_token_metadata(metadata_word, token_metadata)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::asset::TokenSymbol;
    use miden_protocol::{Felt, Word};

    use super::*;
    use crate::account::metadata::{Description, ExternalLink, LogoURI};

    #[test]
    fn token_metadata_new() {
        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 8u8;
        let max_supply = Felt::new(1_000_000);
        let name = TokenName::new("TEST").unwrap();

        let metadata =
            FungibleTokenMetadataBuilder::new(name.clone(), symbol.clone(), decimals, max_supply)
                .build()
                .unwrap();

        assert_eq!(metadata.symbol(), &symbol);
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
        let name = TokenName::new("TEST").unwrap();

        let metadata =
            FungibleTokenMetadataBuilder::new(name, symbol.clone(), decimals, max_supply)
                .token_supply(token_supply)
                .build()
                .unwrap();

        assert_eq!(metadata.symbol(), &symbol);
        assert_eq!(metadata.decimals(), decimals);
        assert_eq!(metadata.max_supply(), max_supply);
        assert_eq!(metadata.token_supply(), token_supply);
    }

    #[test]
    fn token_metadata_builder_with_optionals() {
        let symbol = TokenSymbol::new("MTK").unwrap();
        let name = TokenName::new("My Token").unwrap();
        let description = Description::new("A test token").unwrap();
        let logo_uri = LogoURI::new("https://example.com/logo.png").unwrap();
        let external_link = ExternalLink::new("https://example.com").unwrap();

        let metadata = FungibleTokenMetadataBuilder::new(
            name.clone(),
            symbol.clone(),
            8,
            Felt::new(1_000_000),
        )
        .token_supply(Felt::new(100))
        .description(description.clone())
        .logo_uri(logo_uri.clone())
        .external_link(external_link.clone())
        .is_description_mutable(true)
        .is_max_supply_mutable(true)
        .build()
        .unwrap();

        assert_eq!(metadata.token_supply(), Felt::new(100));
        assert_eq!(metadata.description(), Some(&description));
        assert_eq!(metadata.logo_uri(), Some(&logo_uri));
        assert_eq!(metadata.external_link(), Some(&external_link));
        let slots = metadata.storage_slots();
        let config_word = slots[3].value();
        assert_eq!(config_word[0], Felt::from(1u32), "is_desc_mutable");
        assert_eq!(config_word[3], Felt::from(1u32), "is_max_supply_mutable");
    }

    #[test]
    fn token_metadata_with_name_and_description() {
        use miden_protocol::account::{AccountBuilder, AccountType};

        use crate::account::auth::NoAuth;
        use crate::account::faucets::basic_fungible::BasicFungibleFaucet;

        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(123);
        let name = TokenName::new("polygon").unwrap();
        let description = Description::new("A polygon token").unwrap();

        let metadata =
            FungibleTokenMetadataBuilder::new(name.clone(), symbol.clone(), decimals, max_supply)
                .description(description.clone())
                .build()
                .unwrap();

        assert_eq!(metadata.symbol(), &symbol);
        assert_eq!(metadata.name(), &name);
        assert_eq!(metadata.description(), Some(&description));

        let account = AccountBuilder::new([2u8; 32])
            .account_type(AccountType::FungibleFaucet)
            .with_auth_component(NoAuth)
            .with_component(metadata.clone())
            .with_component(BasicFungibleFaucet)
            .build()
            .expect("account build should succeed");

        let restored = FungibleTokenMetadata::try_from(account.storage()).unwrap();
        assert_eq!(restored.symbol(), &symbol);
        assert_eq!(restored.name(), &name);
        assert_eq!(restored.description(), Some(&description));
    }

    #[test]
    fn token_name_roundtrip() {
        let name = TokenName::new("polygon").unwrap();
        let words = name.to_words();
        let decoded = TokenName::try_from_words(&words).unwrap();
        assert_eq!(decoded.as_str(), "polygon");
    }

    #[test]
    fn token_name_as_str() {
        let name = TokenName::new("my_token").unwrap();
        assert_eq!(name.as_str(), "my_token");
    }

    #[test]
    fn token_name_too_long() {
        let s = "a".repeat(33);
        assert!(TokenName::new(&s).is_err());
    }

    #[test]
    fn description_roundtrip() {
        let text = "A short description";
        let desc = Description::new(text).unwrap();
        let words = desc.to_words();
        let decoded = Description::try_from_words(&words).unwrap();
        assert_eq!(decoded.as_str(), text);
    }

    #[test]
    fn description_too_long() {
        let s = "a".repeat(Description::MAX_BYTES + 1);
        assert!(Description::new(&s).is_err());
    }

    #[test]
    fn logo_uri_roundtrip() {
        let url = "https://example.com/logo.png";
        let uri = LogoURI::new(url).unwrap();
        let words = uri.to_words();
        let decoded = LogoURI::try_from_words(&words).unwrap();
        assert_eq!(decoded.as_str(), url);
    }

    #[test]
    fn external_link_roundtrip() {
        let url = "https://example.com";
        let link = ExternalLink::new(url).unwrap();
        let words = link.to_words();
        let decoded = ExternalLink::try_from_words(&words).unwrap();
        assert_eq!(decoded.as_str(), url);
    }

    #[test]
    fn token_metadata_too_many_decimals() {
        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 13u8;
        let max_supply = Felt::new(1_000_000);
        let name = TokenName::new("TEST").unwrap();

        let result = FungibleTokenMetadataBuilder::new(name, symbol, decimals, max_supply).build();
        assert!(matches!(result, Err(FungibleFaucetError::TooManyDecimals { .. })));
    }

    #[test]
    fn token_metadata_max_supply_too_large() {
        use miden_protocol::asset::FungibleAsset;

        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 8u8;
        let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT + 1);
        let name = TokenName::new("TEST").unwrap();

        let result = FungibleTokenMetadataBuilder::new(name, symbol, decimals, max_supply).build();
        assert!(matches!(result, Err(FungibleFaucetError::MaxSupplyTooLarge { .. })));
    }

    #[test]
    fn token_metadata_to_word() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let symbol_felt = symbol.as_element();
        let decimals = 2u8;
        let max_supply = Felt::new(123);
        let name = TokenName::new("POL").unwrap();

        let metadata = FungibleTokenMetadataBuilder::new(name, symbol, decimals, max_supply)
            .build()
            .unwrap();
        let word = metadata.metadata_word_slot().value();

        assert_eq!(word[0], Felt::ZERO);
        assert_eq!(word[1], max_supply);
        assert_eq!(word[2], Felt::from(decimals));
        assert_eq!(word[3], symbol_felt);
    }

    #[test]
    fn token_metadata_from_account_storage() {
        use miden_protocol::account::{AccountBuilder, AccountType};

        use crate::account::auth::NoAuth;
        use crate::account::faucets::basic_fungible::BasicFungibleFaucet;

        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(123);
        let name = TokenName::new("POL").unwrap();

        let original =
            FungibleTokenMetadataBuilder::new(name, symbol.clone(), decimals, max_supply)
                .build()
                .unwrap();

        let account = AccountBuilder::new([3u8; 32])
            .account_type(AccountType::FungibleFaucet)
            .with_auth_component(NoAuth)
            .with_component(original)
            .with_component(BasicFungibleFaucet)
            .build()
            .expect("account build should succeed");

        let restored = FungibleTokenMetadata::try_from(account.storage()).unwrap();

        assert_eq!(restored.symbol(), &symbol);
        assert_eq!(restored.decimals(), decimals);
        assert_eq!(restored.max_supply(), max_supply);
        assert_eq!(restored.token_supply(), Felt::ZERO);
    }

    #[test]
    fn token_metadata_roundtrip_with_supply() {
        use miden_protocol::account::{AccountBuilder, AccountType};

        use crate::account::auth::NoAuth;
        use crate::account::faucets::basic_fungible::BasicFungibleFaucet;

        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(1000);
        let token_supply = Felt::new(500);
        let name = TokenName::new("POL").unwrap();

        let original =
            FungibleTokenMetadataBuilder::new(name, symbol.clone(), decimals, max_supply)
                .token_supply(token_supply)
                .build()
                .unwrap();

        let account = AccountBuilder::new([4u8; 32])
            .account_type(AccountType::FungibleFaucet)
            .with_auth_component(NoAuth)
            .with_component(original)
            .with_component(BasicFungibleFaucet)
            .build()
            .expect("account build should succeed");

        let restored = FungibleTokenMetadata::try_from(account.storage()).unwrap();

        assert_eq!(restored.symbol(), &symbol);
        assert_eq!(restored.decimals(), decimals);
        assert_eq!(restored.max_supply(), max_supply);
        assert_eq!(restored.token_supply(), token_supply);
    }

    #[test]
    fn mutability_builders() {
        let symbol = TokenSymbol::new("TST").unwrap();
        let name = TokenName::new("T").unwrap();

        let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, Felt::new(1_000))
            .is_description_mutable(true)
            .is_logo_uri_mutable(true)
            .is_external_link_mutable(false)
            .is_max_supply_mutable(true)
            .build()
            .unwrap();

        let slots = metadata.storage_slots();

        // Slot layout (no owner slot): [0]=metadata, [1]=name_0, [2]=name_1, [3]=mutability_config
        let config_slot = &slots[3];
        let config_word = config_slot.value();
        assert_eq!(config_word[0], Felt::from(1u32), "is_desc_mutable");
        assert_eq!(config_word[1], Felt::from(1u32), "is_logo_mutable");
        assert_eq!(config_word[2], Felt::from(0u32), "is_extlink_mutable");
        assert_eq!(config_word[3], Felt::from(1u32), "is_max_supply_mutable");
    }

    #[test]
    fn mutability_defaults_to_false() {
        let symbol = TokenSymbol::new("TST").unwrap();
        let name = TokenName::new("T").unwrap();

        let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, Felt::new(1_000))
            .build()
            .unwrap();

        let slots = metadata.storage_slots();
        let config_word = slots[3].value();
        assert_eq!(config_word[0], Felt::ZERO, "is_desc_mutable default");
        assert_eq!(config_word[1], Felt::ZERO, "is_logo_mutable default");
        assert_eq!(config_word[2], Felt::ZERO, "is_extlink_mutable default");
        assert_eq!(config_word[3], Felt::ZERO, "is_max_supply_mutable default");
    }

    #[test]
    fn storage_slots_includes_metadata_word() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let name = TokenName::new("polygon").unwrap();

        let metadata = FungibleTokenMetadataBuilder::new(name, symbol.clone(), 2, Felt::new(123))
            .build()
            .unwrap();
        let slots = metadata.storage_slots();

        // First slot is the metadata word [token_supply, max_supply, decimals, symbol]
        let metadata_word = slots[0].value();
        assert_eq!(metadata_word[0], Felt::ZERO); // token_supply
        assert_eq!(metadata_word[1], Felt::new(123)); // max_supply
        assert_eq!(metadata_word[2], Felt::from(2u32)); // decimals
        assert_eq!(metadata_word[3], Felt::from(symbol)); // symbol
    }

    #[test]
    fn storage_slots_includes_name() {
        let symbol = TokenSymbol::new("TST").unwrap();
        let name = TokenName::new("my token").unwrap();
        let expected_words = name.to_words();

        let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, Felt::new(100))
            .build()
            .unwrap();
        let slots = metadata.storage_slots();

        // Slot layout: [0]=metadata, [1]=name_0, [2]=name_1
        assert_eq!(slots[1].value(), expected_words[0]);
        assert_eq!(slots[2].value(), expected_words[1]);
    }

    #[test]
    fn storage_slots_includes_description() {
        let symbol = TokenSymbol::new("TST").unwrap();
        let name = TokenName::new("T").unwrap();
        let description = Description::new("A cool token").unwrap();
        let expected_words = description.to_words();

        let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, Felt::new(100))
            .description(description)
            .build()
            .unwrap();
        let slots = metadata.storage_slots();

        // Slots 4..11 are description (7 words): after metadata(1) + name(2) + config(1)
        for (i, expected) in expected_words.iter().enumerate() {
            assert_eq!(slots[4 + i].value(), *expected, "description word {i}");
        }
    }

    #[test]
    fn storage_slots_total_count() {
        let symbol = TokenSymbol::new("TST").unwrap();
        let name = TokenName::new("T").unwrap();

        let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, Felt::new(100))
            .build()
            .unwrap();
        let slots = metadata.storage_slots();

        // 1 metadata + 2 name + 1 config + 7 description + 7 logo + 7 external_link = 25
        assert_eq!(slots.len(), 25);
    }

    #[test]
    fn into_account_component() {
        use miden_protocol::account::{AccountBuilder, AccountType};

        use crate::account::auth::NoAuth;
        use crate::account::faucets::basic_fungible::BasicFungibleFaucet;

        let symbol = TokenSymbol::new("TST").unwrap();
        let name = TokenName::new("test token").unwrap();
        let description = Description::new("A test").unwrap();

        let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 4, Felt::new(10_000))
            .description(description)
            .is_max_supply_mutable(true)
            .build()
            .unwrap();

        // Should build an account successfully with FungibleTokenMetadata as a component
        let account = AccountBuilder::new([1u8; 32])
            .account_type(AccountType::FungibleFaucet)
            .with_auth_component(NoAuth)
            .with_component(metadata)
            .with_component(BasicFungibleFaucet)
            .build()
            .expect("account build should succeed");

        // Verify metadata slot is accessible
        let md_word = account.storage().get_item(FungibleTokenMetadata::metadata_slot()).unwrap();
        assert_eq!(md_word[1], Felt::new(10_000)); // max_supply
        assert_eq!(md_word[2], Felt::from(4u32)); // decimals

        // Verify mutability config
        let config = account.storage().get_item(metadata::mutability_config_slot()).unwrap();
        assert_eq!(config[3], Felt::from(1u32), "is_max_supply_mutable");
    }

    #[test]
    fn roundtrip_via_storage_matches_original() {
        use miden_protocol::account::{AccountBuilder, AccountType};

        use crate::account::auth::NoAuth;
        use crate::account::faucets::basic_fungible::BasicFungibleFaucet;

        let symbol = TokenSymbol::new("RND").unwrap();
        let name = TokenName::new("Roundtrip Token").unwrap();
        let description = Description::new("Description").unwrap();
        let logo_uri = LogoURI::new("https://example.com/logo.png").unwrap();
        let external_link = ExternalLink::new("https://example.com").unwrap();

        let original = FungibleTokenMetadataBuilder::new(
            name.clone(),
            symbol.clone(),
            6,
            Felt::new(2_000_000),
        )
        .token_supply(Felt::new(100_000))
        .description(description.clone())
        .logo_uri(logo_uri.clone())
        .external_link(external_link.clone())
        .is_description_mutable(true)
        .is_logo_uri_mutable(false)
        .is_external_link_mutable(true)
        .is_max_supply_mutable(false)
        .build()
        .unwrap();

        let account = AccountBuilder::new([5u8; 32])
            .account_type(AccountType::FungibleFaucet)
            .with_auth_component(NoAuth)
            .with_component(original)
            .with_component(BasicFungibleFaucet)
            .build()
            .expect("account build should succeed");

        let restored = FungibleTokenMetadata::try_from(account.storage()).unwrap();

        assert_eq!(restored.symbol(), &symbol);
        assert_eq!(restored.name(), &name);
        assert_eq!(restored.decimals(), 6);
        assert_eq!(restored.max_supply(), Felt::new(2_000_000));
        assert_eq!(restored.token_supply(), Felt::new(100_000));
        assert_eq!(restored.description(), Some(&description));
        assert_eq!(restored.logo_uri(), Some(&logo_uri));
        assert_eq!(restored.external_link(), Some(&external_link));
        let slots = restored.storage_slots();
        let config = slots[3].value();
        assert_eq!(config[0], Felt::from(1u32), "is_desc_mutable");
        assert_eq!(config[1], Felt::ZERO, "is_logo_mutable");
        assert_eq!(config[2], Felt::from(1u32), "is_extlink_mutable");
        assert_eq!(config[3], Felt::ZERO, "is_max_supply_mutable");
    }

    #[test]
    fn logo_uri_too_long() {
        let s = "a".repeat(LogoURI::MAX_BYTES + 1);
        assert!(LogoURI::new(&s).is_err());
    }

    #[test]
    fn external_link_too_long() {
        let s = "a".repeat(ExternalLink::MAX_BYTES + 1);
        assert!(ExternalLink::new(&s).is_err());
    }

    #[test]
    fn token_supply_exceeds_max_supply() {
        let symbol = TokenSymbol::new("TST").unwrap();
        let name = TokenName::new("T").unwrap();
        let max_supply = Felt::new(100);
        let token_supply = Felt::new(101);

        let result = FungibleTokenMetadataBuilder::new(name, symbol, 2, max_supply)
            .token_supply(token_supply)
            .build();
        assert!(matches!(result, Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply { .. })));
    }

    #[test]
    fn with_token_supply_exceeds_max_supply() {
        let symbol = TokenSymbol::new("TST").unwrap();
        let name = TokenName::new("T").unwrap();
        let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, Felt::new(100))
            .build()
            .unwrap();

        let result = metadata.with_token_supply(Felt::new(101));
        assert!(matches!(result, Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply { .. })));
    }

    #[test]
    fn invalid_token_symbol_in_metadata_word() {
        // TokenSymbol::try_from(Felt) fails when the value exceeds MAX_ENCODED_VALUE.
        let bad_symbol = Felt::new(TokenSymbol::MAX_ENCODED_VALUE + 1);
        let bad_word = Word::from([Felt::ZERO, Felt::new(100), Felt::new(2), bad_symbol]);
        let token_metadata = TokenMetadata::new().with_name(TokenName::default());
        let result =
            FungibleTokenMetadata::from_metadata_word_and_token_metadata(bad_word, token_metadata);
        assert!(matches!(result, Err(FungibleFaucetError::InvalidTokenSymbol(_))));
    }
}
