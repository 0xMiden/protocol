//! Fungible token metadata stored in account storage.
//!
//! ## Storage layout
//!
//! | Slot name | Contents |
//! |-----------|----------|
//! | `metadata::fungible_faucet::token_metadata` | `[token_supply, max_supply, decimals, token_symbol]` |
//! | `metadata::fungible_faucet::name_chunk_0` | first 4 felts of name |
//! | `metadata::fungible_faucet::name_chunk_1` | last 4 felts of name |
//! | `metadata::fungible_faucet::mutability_config` | `[is_desc_mutable, is_logo_mutable, is_extlink_mutable, is_max_supply_mutable]` |
//! | `metadata::fungible_faucet::description_0..=6` | description (7 Words, max 195 bytes) |
//! | `metadata::fungible_faucet::logo_uri_0..=6` | logo URI (7 Words, max 195 bytes) |
//! | `metadata::fungible_faucet::external_link_0..=6` | external link (7 Words, max 195 bytes) |
//!
//! Layout sync: the same layout is defined in MASM at
//! `asm/standards/metadata/fungible_faucet.masm`. Any change to slot names must be applied in both
//! Rust and MASM.
//!
//! ## Config Word
//!
//! `mutability_config`: `[is_desc_mutable, is_logo_mutable, is_extlink_mutable,
//! is_max_supply_mutable]` — each flag is 0 (immutable) or 1 (mutable / owner can update).
//!
//! Whether a field is *present* is determined by whether its storage words are all zero (absent)
//! or not (present).
//!
//! ## String encoding (UTF-8)
//!
//! All string fields use **7-bytes-per-felt, length-prefixed** encoding. The N felts are
//! serialized into a flat buffer of N × 7 bytes; byte 0 is the string length, followed by UTF-8
//! content, zero-padded. Each 7-byte chunk is stored as a LE u64 with the high byte always zero,
//! so it always fits in a Goldilocks field element.
//!
//! The name slots hold 2 Words (8 felts, capacity 55 bytes, capped at 32).

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
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use super::{TokenMetadata, TokenName};
use crate::account::components::fungible_token_metadata_library;
use crate::account::faucets::FungibleFaucetError;
use crate::utils::{FixedWidthString, FixedWidthStringError};

pub mod builder;

pub use builder::FungibleTokenMetadataBuilder;

#[cfg(test)]
mod tests;

// SLOT NAMES — canonical layout (sync with asm/standards/metadata/fungible_faucet.masm)
// ================================================================================================

/// Fungible token metadata word: `[token_supply, max_supply, decimals, token_symbol]`.
pub(crate) static FUNGIBLE_TOKEN_METADATA_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::metadata::fungible_faucet::token_metadata")
        .expect("storage slot name should be valid")
});

/// Token name (2 Words = 8 felts), split across 2 slots.
pub(crate) static NAME_SLOTS: LazyLock<[StorageSlotName; 2]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::name_chunk_0")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::name_chunk_1")
            .expect("valid slot name"),
    ]
});

/// Mutability config slot: `[is_desc_mutable, is_logo_mutable, is_extlink_mutable,
/// is_max_supply_mutable]`.
pub(crate) static MUTABILITY_CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::metadata::fungible_faucet::mutability_config")
        .expect("storage slot name should be valid")
});

/// Description (7 Words), split across 7 slots.
pub(crate) static DESCRIPTION_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::description_0")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::description_1")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::description_2")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::description_3")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::description_4")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::description_5")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::description_6")
            .expect("valid slot name"),
    ]
});

/// Logo URI (7 Words), split across 7 slots.
pub(crate) static LOGO_URI_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::logo_uri_0")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::logo_uri_1")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::logo_uri_2")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::logo_uri_3")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::logo_uri_4")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::logo_uri_5")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::logo_uri_6")
            .expect("valid slot name"),
    ]
});

/// External link (7 Words), split across 7 slots.
pub(crate) static EXTERNAL_LINK_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::external_link_0")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::external_link_1")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::external_link_2")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::external_link_3")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::external_link_4")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::external_link_5")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::fungible_faucet::external_link_6")
            .expect("valid slot name"),
    ]
});

/// Returns the [`StorageSlotName`] for the fungible token metadata word (slot 0).
pub(crate) fn fungible_token_metadata_slot() -> &'static StorageSlotName {
    &FUNGIBLE_TOKEN_METADATA_SLOT
}

/// Returns the [`StorageSlotName`] for the mutability config Word.
pub(crate) fn mutability_config_slot() -> &'static StorageSlotName {
    &MUTABILITY_CONFIG_SLOT
}

/// Schema type string for the token symbol field in fungible token metadata storage.
pub(super) const TOKEN_SYMBOL_TYPE: &str =
    "miden::standards::fungible_faucets::metadata::token_symbol";

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
    ///
    /// # Parameters
    ///
    /// - `name`: display name (at most 32 UTF-8 bytes).
    /// - `symbol`: token symbol.
    /// - `decimals`: decimal precision (0–12).
    /// - `max_supply`: maximum token supply (0–[`FungibleAsset::MAX_AMOUNT`], expressed as a
    ///   `u64`).
    pub fn builder(
        name: TokenName,
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: u64,
    ) -> FungibleTokenMetadataBuilder {
        FungibleTokenMetadataBuilder::new(name, symbol, decimals, max_supply)
    }

    /// Validates all fields and constructs a [`FungibleTokenMetadata`].
    ///
    /// This is the single point where `Self { ... }` is constructed. All other constructors
    /// delegate here.
    pub(crate) fn new_validated(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: u64,
        token_supply: u64,
        metadata: TokenMetadata,
    ) -> Result<Self, FungibleFaucetError> {
        if decimals > Self::MAX_DECIMALS {
            return Err(FungibleFaucetError::TooManyDecimals {
                actual: decimals as u64,
                max: Self::MAX_DECIMALS,
            });
        }

        if max_supply > FungibleAsset::MAX_AMOUNT {
            return Err(FungibleFaucetError::MaxSupplyTooLarge {
                actual: max_supply,
                max: FungibleAsset::MAX_AMOUNT,
            });
        }

        if token_supply > max_supply {
            return Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply {
                token_supply,
                max_supply,
            });
        }

        // SAFETY: max_supply and token_supply are validated above to be <= MAX_AMOUNT (2^63 - 1),
        // which is well below the Goldilocks prime, so Felt::new will not wrap.
        Ok(Self {
            token_supply: Felt::new(token_supply),
            max_supply: Felt::new(max_supply),
            decimals,
            symbol,
            metadata,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the token metadata is stored (canonical slot shared
    /// with the metadata module).
    pub fn metadata_slot() -> &'static StorageSlotName {
        fungible_token_metadata_slot()
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
        self.metadata.name()
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
                    FeltSchema::felt("token_supply").with_default(Felt::ZERO),
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
    fn metadata_word_slot(&self) -> StorageSlot {
        let word = Word::new([
            self.token_supply,
            self.max_supply,
            Felt::from(self.decimals),
            self.symbol.clone().into(),
        ]);
        StorageSlot::with_value(Self::metadata_slot().clone(), word)
    }

    /// Consumes `self` and returns all storage slots for this component (metadata word + name +
    /// config + description + logo_uri + external_link).
    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let mut slots: Vec<StorageSlot> = Vec::new();
        slots.push(self.metadata_word_slot());
        slots.extend(self.metadata.into_storage_slots());
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
        let [token_supply, max_supply, decimals_felt, token_symbol] = *word;
        let symbol =
            TokenSymbol::try_from(token_symbol).map_err(FungibleFaucetError::InvalidTokenSymbol)?;
        let decimals: u8 = decimals_felt.as_canonical_u64().try_into().map_err(|_| {
            FungibleFaucetError::TooManyDecimals {
                actual: decimals_felt.as_canonical_u64(),
                max: Self::MAX_DECIMALS,
            }
        })?;

        Self::new_validated(
            symbol,
            decimals,
            max_supply.as_canonical_u64(),
            token_supply.as_canonical_u64(),
            metadata,
        )
    }
}

impl From<FungibleTokenMetadata> for AccountComponent {
    fn from(metadata: FungibleTokenMetadata) -> Self {
        let mut schema_entries = vec![FungibleTokenMetadata::metadata_slot_schema()];

        // Name chunks (2 slots)
        for (i, slot) in NAME_SLOTS.iter().enumerate() {
            schema_entries.push((
                slot.clone(),
                StorageSlotSchema::value(
                    alloc::format!("Name chunk {i}"),
                    core::array::from_fn(|j| FeltSchema::felt(alloc::format!("data_{j}"))),
                ),
            ));
        }

        // Mutability config (1 slot)
        schema_entries.push((
            MUTABILITY_CONFIG_SLOT.clone(),
            StorageSlotSchema::value(
                "Mutability config",
                [
                    FeltSchema::bool("is_description_mutable"),
                    FeltSchema::bool("is_logo_uri_mutable"),
                    FeltSchema::bool("is_external_link_mutable"),
                    FeltSchema::bool("is_max_supply_mutable"),
                ],
            ),
        ));

        // Description, Logo URI, External link (7 slots each)
        for (label, slots) in [
            ("Description", DESCRIPTION_SLOTS.as_slice()),
            ("Logo URI", LOGO_URI_SLOTS.as_slice()),
            ("External link", EXTERNAL_LINK_SLOTS.as_slice()),
        ] {
            for (i, slot) in slots.iter().enumerate() {
                schema_entries.push((
                    slot.clone(),
                    StorageSlotSchema::value(
                        alloc::format!("{label} chunk {i}"),
                        core::array::from_fn(|j| FeltSchema::felt(alloc::format!("data_{j}"))),
                    ),
                ));
            }
        }

        let storage_schema =
            StorageSchema::new(schema_entries).expect("storage schema should be valid");

        let component_metadata = AccountComponentMetadata::new(
            "miden::standards::components::faucets::fungible_token_metadata",
            [AccountType::FungibleFaucet],
        )
        .with_description("Fungible token metadata component storing token metadata, name, mutability config, description, logo URI, and external link")
        .with_storage_schema(storage_schema);

        AccountComponent::new(
            fungible_token_metadata_library(),
            metadata.into_storage_slots(),
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

        let token_metadata = TokenMetadata::try_from_storage(storage)?;

        Self::from_metadata_word_and_token_metadata(metadata_word, token_metadata)
    }
}

// FIELD TYPES
// ================================================================================================

/// Token description (max 195 bytes UTF-8), stored in 7 Words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description(FixedWidthString<7>);

impl Description {
    /// Maximum byte length for a description (7 Words × 4 felts × 7 bytes − 1 length byte).
    pub const MAX_BYTES: usize = FixedWidthString::<7>::CAPACITY;

    /// Creates a description from a UTF-8 string.
    pub fn new(s: &str) -> Result<Self, FixedWidthStringError> {
        FixedWidthString::<7>::new(s).map(Self)
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
    pub fn try_from_words(words: &[Word]) -> Result<Self, FixedWidthStringError> {
        FixedWidthString::<7>::try_from_words(words).map(Self)
    }
}

/// Token logo URI (max 195 bytes UTF-8), stored in 7 Words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoURI(FixedWidthString<7>);

impl LogoURI {
    /// Maximum byte length for a logo URI (7 Words × 4 felts × 7 bytes − 1 length byte).
    pub const MAX_BYTES: usize = FixedWidthString::<7>::CAPACITY;

    /// Creates a logo URI from a UTF-8 string.
    pub fn new(s: &str) -> Result<Self, FixedWidthStringError> {
        FixedWidthString::<7>::new(s).map(Self)
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
    pub fn try_from_words(words: &[Word]) -> Result<Self, FixedWidthStringError> {
        FixedWidthString::<7>::try_from_words(words).map(Self)
    }
}

/// Token external link (max 195 bytes UTF-8), stored in 7 Words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLink(FixedWidthString<7>);

impl ExternalLink {
    /// Maximum byte length for an external link (7 Words × 4 felts × 7 bytes − 1 length byte).
    pub const MAX_BYTES: usize = FixedWidthString::<7>::CAPACITY;

    /// Creates an external link from a UTF-8 string.
    pub fn new(s: &str) -> Result<Self, FixedWidthStringError> {
        FixedWidthString::<7>::new(s).map(Self)
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
    pub fn try_from_words(words: &[Word]) -> Result<Self, FixedWidthStringError> {
        FixedWidthString::<7>::try_from_words(words).map(Self)
    }
}
