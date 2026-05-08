//! Generic token metadata helper.
//!
//! [`TokenMetadata`] is a builder-pattern struct used to manage the token name and optional
//! fields (description, logo_uri, external_link) along with their mutability flags. It is meant
//! to be embedded inside a token-bearing component such as
//! [`BasicFungibleFaucet`][crate::account::faucets::BasicFungibleFaucet], not used as a
//! standalone account component.
//!
//! Owner-gated mutators (`set_description`, `set_logo_uri`, `set_external_link`,
//! `set_max_supply`) are exposed through the embedding component's MASM library and rely on
//! the `Ownable2Step` access component for ownership checks.
//!
//! ## Storage layout (per-component, see embedding component for absolute slot order)
//!
//! | Slot name | Contents |
//! |-----------|----------|
//! | `faucets::fungible::token_name_0` | first 4 felts of name |
//! | `faucets::fungible::token_name_1` | last 4 felts of name |
//! | `faucets::fungible::mutability_config` | `[is_desc_mutable, is_logo_mutable, is_extlink_mutable, is_max_supply_mutable]` |
//! | `faucets::fungible::token_description_0..=6` | description (7 Words, max 195 bytes) |
//! | `faucets::fungible::logo_uri_0..=6` | logo URI (7 Words, max 195 bytes) |
//! | `faucets::fungible::external_link_0..=6` | external link (7 Words, max 195 bytes) |
//!
//! Layout sync: the same layout is defined in MASM at `asm/standards/faucets/fungible.masm`.
//! Any change to slot names must be applied in both Rust and MASM.
//!
//! ## String encoding (UTF-8)
//!
//! All string fields use **7-bytes-per-felt, length-prefixed** encoding. The N felts are
//! serialized into a flat buffer of N × 7 bytes; byte 0 is the string length, followed by
//! UTF-8 content, zero-padded. Each 7-byte chunk is stored as a LE u64 with the high byte
//! always zero, so it always fits in a Goldilocks field element.
//!
//! The name slots hold 2 Words (8 felts, capacity 55 bytes, capped at 32).

use alloc::vec::Vec;

use miden_protocol::account::component::{FeltSchema, StorageSlotSchema};
use miden_protocol::account::{AccountStorage, StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::faucets::TokenMetadataError;
use crate::utils::{FixedWidthString, FixedWidthStringError};

// SLOT NAMES — canonical layout (sync with asm/standards/faucets/fungible.masm)
// ================================================================================================

/// Token name (2 Words = 8 felts), split across 2 slots.
static NAME_SLOTS: LazyLock<[StorageSlotName; 2]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::faucets::fungible::token_name_0")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::token_name_1")
            .expect("valid slot name"),
    ]
});

/// Mutability config slot: `[is_desc_mutable, is_logo_mutable, is_extlink_mutable,
/// is_max_supply_mutable]`.
static MUTABILITY_CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::fungible::mutability_config")
        .expect("storage slot name should be valid")
});

/// Description (7 Words), split across 7 slots.
static DESCRIPTION_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::faucets::fungible::token_description_0")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::token_description_1")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::token_description_2")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::token_description_3")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::token_description_4")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::token_description_5")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::token_description_6")
            .expect("valid slot name"),
    ]
});

/// Logo URI (7 Words), split across 7 slots.
static LOGO_URI_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::faucets::fungible::logo_uri_0")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::logo_uri_1")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::logo_uri_2")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::logo_uri_3")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::logo_uri_4")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::logo_uri_5")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::logo_uri_6")
            .expect("valid slot name"),
    ]
});

/// External link (7 Words), split across 7 slots.
static EXTERNAL_LINK_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::faucets::fungible::external_link_0")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::external_link_1")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::external_link_2")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::external_link_3")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::external_link_4")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::external_link_5")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::fungible::external_link_6")
            .expect("valid slot name"),
    ]
});

/// Returns the [`StorageSlotName`] for the mutability config Word.
pub(crate) fn mutability_config_slot() -> &'static StorageSlotName {
    &MUTABILITY_CONFIG_SLOT
}

/// Maximum length of a name in bytes when using the UTF-8 encoding (capped at 32).
pub(crate) const NAME_UTF8_MAX_BYTES: usize = 32;

// TOKEN NAME
// ================================================================================================

/// Token display name (max 32 bytes UTF-8), stored in 2 Words.
///
/// The maximum is intentionally capped at 32 bytes even though the 2-Word encoding could
/// hold up to 55 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenName(FixedWidthString<2>);

impl TokenName {
    /// Maximum byte length for a token name (capped at 32, below the 55-byte capacity).
    pub const MAX_BYTES: usize = NAME_UTF8_MAX_BYTES;

    /// Creates a token name from a UTF-8 string (at most 32 bytes).
    pub fn new(s: &str) -> Result<Self, FixedWidthStringError> {
        if s.len() > Self::MAX_BYTES {
            return Err(FixedWidthStringError::TooLong { max: Self::MAX_BYTES, actual: s.len() });
        }
        Ok(Self(FixedWidthString::new(s).expect("length already validated above")))
    }

    /// Returns the name as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Encodes the name into 2 Words for storage.
    pub fn to_words(&self) -> Vec<Word> {
        self.0.to_words()
    }

    /// Decodes a token name from a 2-Word slice.
    pub fn try_from_words(words: &[Word]) -> Result<Self, FixedWidthStringError> {
        let inner = FixedWidthString::<2>::try_from_words(words)?;
        if inner.as_str().len() > Self::MAX_BYTES {
            return Err(FixedWidthStringError::TooLong {
                max: Self::MAX_BYTES,
                actual: inner.as_str().len(),
            });
        }
        Ok(Self(inner))
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

// TOKEN METADATA
// ================================================================================================

/// A helper that stores name, mutability config, and optional fields in fixed value slots.
///
/// Designed to be embedded in
/// [`BasicFungibleFaucet`][crate::account::faucets::BasicFungibleFaucet] (or other token-bearing
/// account components) to avoid duplication. Slot names are referenced via
/// [`TokenMetadata::name_chunk_0_slot`] and friends.
#[derive(Debug, Clone)]
pub struct TokenMetadata {
    name: TokenName,
    description: Option<Description>,
    logo_uri: Option<LogoURI>,
    external_link: Option<ExternalLink>,
    is_description_mutable: bool,
    is_logo_uri_mutable: bool,
    is_external_link_mutable: bool,
    is_max_supply_mutable: bool,
}

impl TokenMetadata {
    /// Creates a new token metadata with the given name (all optional fields absent, all flags
    /// false).
    pub fn new(name: TokenName) -> Self {
        Self {
            name,
            description: None,
            logo_uri: None,
            external_link: None,
            is_description_mutable: false,
            is_logo_uri_mutable: false,
            is_external_link_mutable: false,
            is_max_supply_mutable: false,
        }
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Sets the description and its mutability flag together.
    pub fn with_description(mut self, description: Description, mutable: bool) -> Self {
        self.description = Some(description);
        self.is_description_mutable = mutable;
        self
    }

    /// Sets whether the description can be updated by the owner.
    pub fn with_description_mutable(mut self, mutable: bool) -> Self {
        self.is_description_mutable = mutable;
        self
    }

    /// Sets the logo URI and its mutability flag together.
    pub fn with_logo_uri(mut self, logo_uri: LogoURI, mutable: bool) -> Self {
        self.logo_uri = Some(logo_uri);
        self.is_logo_uri_mutable = mutable;
        self
    }

    /// Sets whether the logo URI can be updated by the owner.
    pub fn with_logo_uri_mutable(mut self, mutable: bool) -> Self {
        self.is_logo_uri_mutable = mutable;
        self
    }

    /// Sets the external link and its mutability flag together.
    pub fn with_external_link(mut self, external_link: ExternalLink, mutable: bool) -> Self {
        self.external_link = Some(external_link);
        self.is_external_link_mutable = mutable;
        self
    }

    /// Sets whether the external link can be updated by the owner.
    pub fn with_external_link_mutable(mut self, mutable: bool) -> Self {
        self.is_external_link_mutable = mutable;
        self
    }

    /// Sets whether the max supply can be updated by the owner.
    pub fn with_max_supply_mutable(mut self, mutable: bool) -> Self {
        self.is_max_supply_mutable = mutable;
        self
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the token name.
    pub fn name(&self) -> &TokenName {
        &self.name
    }

    /// Returns the description if set.
    pub fn description(&self) -> Option<&Description> {
        self.description.as_ref()
    }

    /// Returns the logo URI if set.
    pub fn logo_uri(&self) -> Option<&LogoURI> {
        self.logo_uri.as_ref()
    }

    /// Returns the external link if set.
    pub fn external_link(&self) -> Option<&ExternalLink> {
        self.external_link.as_ref()
    }

    /// Returns whether the max supply is configured as mutable.
    pub fn is_max_supply_mutable(&self) -> bool {
        self.is_max_supply_mutable
    }

    // STATIC SLOT NAME ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] for name chunk 0.
    pub fn name_chunk_0_slot() -> &'static StorageSlotName {
        &NAME_SLOTS[0]
    }

    /// Returns the [`StorageSlotName`] for name chunk 1.
    pub fn name_chunk_1_slot() -> &'static StorageSlotName {
        &NAME_SLOTS[1]
    }

    /// Returns the [`StorageSlotName`] for the mutability config Word.
    pub fn mutability_config_slot() -> &'static StorageSlotName {
        mutability_config_slot()
    }

    /// Returns the [`StorageSlotName`] for a description chunk by index (0..=6).
    pub fn description_slot(index: usize) -> &'static StorageSlotName {
        &DESCRIPTION_SLOTS[index]
    }

    /// Returns the [`StorageSlotName`] for a logo URI chunk by index (0..=6).
    pub fn logo_uri_slot(index: usize) -> &'static StorageSlotName {
        &LOGO_URI_SLOTS[index]
    }

    /// Returns the [`StorageSlotName`] for an external link chunk by index (0..=6).
    pub fn external_link_slot(index: usize) -> &'static StorageSlotName {
        &EXTERNAL_LINK_SLOTS[index]
    }

    /// Returns the storage slot schema entries describing the token metadata layout
    /// (name chunks, mutability config, description, logo URI, external link).
    ///
    /// Embedding components should call this and extend their own schema with the result.
    pub fn storage_schema() -> Vec<(StorageSlotName, StorageSlotSchema)> {
        let mut entries: Vec<(StorageSlotName, StorageSlotSchema)> = Vec::new();

        for (i, slot) in NAME_SLOTS.iter().enumerate() {
            entries.push((
                slot.clone(),
                StorageSlotSchema::value(
                    alloc::format!("Name chunk {i}"),
                    core::array::from_fn(|j| FeltSchema::felt(alloc::format!("data_{j}"))),
                ),
            ));
        }

        entries.push((
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

        for (label, slots) in [
            ("Description", DESCRIPTION_SLOTS.as_slice()),
            ("Logo URI", LOGO_URI_SLOTS.as_slice()),
            ("External link", EXTERNAL_LINK_SLOTS.as_slice()),
        ] {
            for (i, slot) in slots.iter().enumerate() {
                entries.push((
                    slot.clone(),
                    StorageSlotSchema::value(
                        alloc::format!("{label} chunk {i}"),
                        core::array::from_fn(|j| FeltSchema::felt(alloc::format!("data_{j}"))),
                    ),
                ));
            }
        }

        entries
    }

    // STORAGE
    // --------------------------------------------------------------------------------------------

    /// Converts a single [`Felt`] at the given `index` in the mutability config word to a `bool`.
    ///
    /// Returns `Err` if the value is neither `0` nor `1`.
    fn felt_to_bool(felt: Felt, index: usize) -> Result<bool, TokenMetadataError> {
        match felt.as_canonical_u64() {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(TokenMetadataError::InvalidMutabilityFlag { index, value }),
        }
    }

    /// Decodes the mutability config [`Word`] into its four boolean flags.
    ///
    /// The word layout is `[is_desc_mutable, is_logo_mutable, is_extlink_mutable,
    /// is_max_supply_mutable]`. Each element must be exactly `0` or `1`.
    ///
    /// # Errors
    ///
    /// Returns [`TokenMetadataError::InvalidMutabilityFlag`] if any element is not `0` or `1`.
    fn mutability_flags_from_word(
        word: Word,
    ) -> Result<(bool, bool, bool, bool), TokenMetadataError> {
        Ok((
            Self::felt_to_bool(word[0], 0)?,
            Self::felt_to_bool(word[1], 1)?,
            Self::felt_to_bool(word[2], 2)?,
            Self::felt_to_bool(word[3], 3)?,
        ))
    }

    /// Returns the mutability config word for this metadata.
    fn mutability_config_word(&self) -> Word {
        Word::from([
            Felt::from(self.is_description_mutable as u32),
            Felt::from(self.is_logo_uri_mutable as u32),
            Felt::from(self.is_external_link_mutable as u32),
            Felt::from(self.is_max_supply_mutable as u32),
        ])
    }

    /// Constructs a [`TokenMetadata`] by reading all relevant name, optional-field, and
    /// mutability config slots from account storage.
    ///
    /// # Errors
    ///
    /// Returns [`TokenMetadataError`] if any storage lookup fails, a mutability flag is invalid,
    /// or a string field cannot be decoded.
    pub fn try_from_storage(storage: &AccountStorage) -> Result<Self, TokenMetadataError> {
        let chunk_0 = storage.get_item(TokenMetadata::name_chunk_0_slot()).map_err(|err| {
            TokenMetadataError::StorageLookupFailed {
                slot_name: TokenMetadata::name_chunk_0_slot().clone(),
                source: err,
            }
        })?;
        let chunk_1 = storage.get_item(TokenMetadata::name_chunk_1_slot()).map_err(|err| {
            TokenMetadataError::StorageLookupFailed {
                slot_name: TokenMetadata::name_chunk_1_slot().clone(),
                source: err,
            }
        })?;
        let name_words: [Word; 2] = [chunk_0, chunk_1];
        let name = TokenName::try_from_words(&name_words)
            .map_err(|err| TokenMetadataError::InvalidStringField { field: "name", source: err })?;

        let read_slots = |slots: &[StorageSlotName; 7]| -> Result<[Word; 7], TokenMetadataError> {
            let mut field = [Word::default(); 7];
            for (i, slot) in slots.iter().enumerate() {
                field[i] = storage.get_item(slot).map_err(|err| {
                    TokenMetadataError::StorageLookupFailed { slot_name: slot.clone(), source: err }
                })?;
            }
            Ok(field)
        };

        let description_words = read_slots(&DESCRIPTION_SLOTS)?;
        let description = Description::try_from_words(&description_words).map_err(|err| {
            TokenMetadataError::InvalidStringField { field: "description", source: err }
        })?;
        let description = if description.as_str().is_empty() {
            None
        } else {
            Some(description)
        };

        let logo_words = read_slots(&LOGO_URI_SLOTS)?;
        let logo_uri = LogoURI::try_from_words(&logo_words).map_err(|err| {
            TokenMetadataError::InvalidStringField { field: "logo_uri", source: err }
        })?;
        let logo_uri = if logo_uri.as_str().is_empty() {
            None
        } else {
            Some(logo_uri)
        };

        let link_words = read_slots(&EXTERNAL_LINK_SLOTS)?;
        let external_link = ExternalLink::try_from_words(&link_words).map_err(|err| {
            TokenMetadataError::InvalidStringField { field: "external_link", source: err }
        })?;
        let external_link = if external_link.as_str().is_empty() {
            None
        } else {
            Some(external_link)
        };

        let mutability_word = storage.get_item(mutability_config_slot()).map_err(|err| {
            TokenMetadataError::StorageLookupFailed {
                slot_name: mutability_config_slot().clone(),
                source: err,
            }
        })?;
        let (is_desc_mutable, is_logo_mutable, is_extlink_mutable, is_max_supply_mutable) =
            TokenMetadata::mutability_flags_from_word(mutability_word)?;

        let mut meta = TokenMetadata::new(name);
        if let Some(d) = description {
            meta = meta.with_description(d, is_desc_mutable);
        }
        meta = meta.with_description_mutable(is_desc_mutable);
        if let Some(l) = logo_uri {
            meta = meta.with_logo_uri(l, is_logo_mutable);
        }
        meta = meta.with_logo_uri_mutable(is_logo_mutable);
        if let Some(e) = external_link {
            meta = meta.with_external_link(e, is_extlink_mutable);
        }
        meta = meta.with_external_link_mutable(is_extlink_mutable);
        meta = meta.with_max_supply_mutable(is_max_supply_mutable);

        Ok(meta)
    }

    /// Consumes `self` and returns the storage slots for this metadata (name, mutability config,
    /// and all fields). Absent optional fields are encoded as empty strings (all-zero words).
    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let mut slots: Vec<StorageSlot> = Vec::new();

        let name_words = self.name.to_words();
        slots.push(StorageSlot::with_value(
            TokenMetadata::name_chunk_0_slot().clone(),
            name_words[0],
        ));
        slots.push(StorageSlot::with_value(
            TokenMetadata::name_chunk_1_slot().clone(),
            name_words[1],
        ));

        slots.push(StorageSlot::with_value(
            mutability_config_slot().clone(),
            self.mutability_config_word(),
        ));

        let description = self
            .description
            .unwrap_or_else(|| Description::new("").expect("empty description should be valid"));
        for (i, word) in description.to_words().iter().enumerate() {
            slots.push(StorageSlot::with_value(TokenMetadata::description_slot(i).clone(), *word));
        }

        let logo_uri = self
            .logo_uri
            .unwrap_or_else(|| LogoURI::new("").expect("empty logo URI should be valid"));
        for (i, word) in logo_uri.to_words().iter().enumerate() {
            slots.push(StorageSlot::with_value(TokenMetadata::logo_uri_slot(i).clone(), *word));
        }

        let external_link = self
            .external_link
            .unwrap_or_else(|| ExternalLink::new("").expect("empty external link should be valid"));
        for (i, word) in external_link.to_words().iter().enumerate() {
            slots
                .push(StorageSlot::with_value(TokenMetadata::external_link_slot(i).clone(), *word));
        }

        slots
    }
}
