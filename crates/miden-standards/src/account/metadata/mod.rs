//! Account / contract / faucet metadata (slots 0..25)
//!
//! All of the following are metadata of the account (or faucet): token_symbol, decimals,
//! max_supply, owner, name, mutability_config, description, logo URI,
//! and external link.
//!
//! ## Storage layout
//!
//! | Slot name | Contents |
//! |-----------|----------|
//! | `metadata::token_metadata` | `[token_supply, max_supply, decimals, token_symbol]` |
//! | `ownable::owner_config` | owner account id (defined by ownable module) |
//! | `metadata::name_0` | first 4 felts of name |
//! | `metadata::name_1` | last 4 felts of name |
//! | `metadata::mutability_config` | `[desc_mutable, logo_mutable, extlink_mutable, max_supply_mutable]` |
//! | `metadata::description_0..6` | description (7 Words, max 195 bytes) |
//! | `metadata::logo_uri_0..6` | logo URI (7 Words, max 195 bytes) |
//! | `metadata::external_link_0..6` | external link (7 Words, max 195 bytes) |
//!
//! Slot names use the `miden::standards::metadata::*` namespace, except for the
//! owner which is defined by the ownable module
//! (`miden::standards::access::ownable::owner_config`).
//!
//! Layout sync: the same layout is defined in MASM at `asm/standards/metadata/fungible.masm`.
//! Any change to slot indices or names must be applied in both Rust and MASM.
//!
//! ## Config Word
//!
//! A single config Word stores per-field boolean flags:
//!
//! **mutability_config**: `[desc_mutable, logo_mutable, extlink_mutable, max_supply_mutable]`
//! - Each flag is 0 (immutable) or 1 (mutable / owner can update).
//!
//! Whether a field is *present* is determined by whether its storage words are all zero
//! (absent) or not (present). No separate `initialized_config` is needed.
//!
//! ## MASM modules
//!
//! All metadata procedures (getters, `get_owner`, setters) live in
//! `miden::standards::metadata::fungible`, which depends on ownable. The standalone
//! The TokenMetadata component uses the standards library and exposes `get_name`,
//! `get_description`, `get_logo_uri`, `get_external_link`; for owner and mutable fields use a
//! component that re-exports from fungible (e.g. network fungible faucet).
//!
//! ## String encoding (UTF-8)
//!
//! All string fields use **7-bytes-per-felt, length-prefixed** encoding. The N felts are
//! serialized into a flat buffer of N × 7 bytes; byte 0 is the string length, followed by UTF-8
//! content, zero-padded. Each 7-byte chunk is stored as a LE u64 with the high byte always zero,
//! so it always fits in a Goldilocks field element.
//!
//! The name slots hold 2 Words (8 felts, capacity 55 bytes, capped at 32). See
//! [`name_from_utf8`], [`name_to_utf8`] for convenience helpers.
//!
//! # Example
//!
//! ```ignore
//! use miden_standards::account::metadata::TokenMetadata;
//! use miden_standards::account::faucets::{TokenName, Description, LogoURI};
//!
//! let info = TokenMetadata::new()
//!     .with_name(TokenName::new("My Token").unwrap())
//!     .with_description(Description::new("A cool token").unwrap(), true)
//!     .with_logo_uri(LogoURI::new("https://example.com/logo.png").unwrap(), false);
//!
//! let faucet = BasicFungibleFaucet::new(/* ... */).unwrap().with_info(info);
//! let account = AccountBuilder::new(seed)
//!     .with_component(faucet)
//!     .build()?;
//! ```

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use miden_protocol::account::component::{AccountComponentMetadata, StorageSchema};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountStorage,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::{AccountError, ComponentMetadataError};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use thiserror::Error;

use crate::account::components::{metadata_info_component_library, storage_schema_library};
use crate::account::faucets::{Description, ExternalLink, LogoURI, TokenName};

// CONSTANTS — canonical layout: slots 0–22
// ================================================================================================

/// Token metadata: `[token_supply, max_supply, decimals, token_symbol]`.
pub static TOKEN_METADATA_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::metadata::token_metadata")
        .expect("storage slot name should be valid")
});

/// Owner config — defined by the ownable module (`miden::standards::access::ownable`).
/// Referenced here so that faucets and other metadata consumers can locate the owner
/// through a single `metadata::owner_config_slot()` accessor, without depending on
/// the ownable module directly.
pub static OWNER_CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::ownable::owner_config")
        .expect("storage slot name should be valid")
});

/// Token name (2 Words = 8 felts), split across 2 slots.
///
/// The encoding is not specified; the value is opaque word data. For human-readable names,
/// use [`TokenName::new`] / [`TokenName::to_words`] / [`TokenName::try_from_words`].
pub static NAME_SLOTS: LazyLock<[StorageSlotName; 2]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::name_0").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::name_1").expect("valid slot name"),
    ]
});

/// Maximum length of a name in bytes when using the UTF-8 encoding (2 Words = 8 felts × 7 bytes
/// = 56 byte buffer − 1 length byte = 55 capacity, capped at 32).
pub const NAME_UTF8_MAX_BYTES: usize = 32;

/// Errors when encoding or decoding the metadata name as UTF-8.
#[derive(Debug, Clone, Error)]
pub enum NameUtf8Error {
    /// Name exceeds [`NAME_UTF8_MAX_BYTES`].
    #[error("name must be at most {NAME_UTF8_MAX_BYTES} UTF-8 bytes, got {0}")]
    TooLong(usize),
    /// Decoded bytes are not valid UTF-8.
    #[error("name is not valid UTF-8")]
    InvalidUtf8,
}

/// Encodes a UTF-8 string into the 2-Word name format.
///
/// Bytes are packed 7-bytes-per-felt, length-prefixed, into 8 felts (2 Words).
/// Returns an error if the UTF-8 byte length exceeds 32.
///
/// Prefer using [`TokenName::new`] + [`TokenName::to_words`] directly.
pub fn name_from_utf8(s: &str) -> Result<[Word; 2], NameUtf8Error> {
    use crate::account::faucets::TokenName;
    Ok(TokenName::new(s)?.to_words())
}

/// Decodes the 2-Word name format as UTF-8.
///
/// Assumes the name was encoded with [`name_from_utf8`] (7-bytes-per-felt, length-prefixed).
///
/// Prefer using [`TokenName::try_from_words`] directly.
pub fn name_to_utf8(words: &[Word; 2]) -> Result<String, NameUtf8Error> {
    use crate::account::faucets::TokenName;
    Ok(TokenName::try_from_words(words)?.as_str().into())
}

/// Mutability config slot: `[desc_mutable, logo_mutable, extlink_mutable, max_supply_mutable]`.
///
/// Each flag is 0 (immutable) or 1 (mutable / owner can update).
pub static MUTABILITY_CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::metadata::mutability_config")
        .expect("storage slot name should be valid")
});

/// Maximum length of a metadata field (description, logo_uri, external_link) in bytes.
/// 7 Words = 28 felts × 7 bytes = 196 byte buffer − 1 length byte = 195 bytes.
pub const FIELD_MAX_BYTES: usize = 195;

/// Errors when encoding or decoding metadata fields.
#[derive(Debug, Clone, Error)]
pub enum FieldBytesError {
    /// Field exceeds [`FIELD_MAX_BYTES`].
    #[error("field must be at most {FIELD_MAX_BYTES} bytes, got {0}")]
    TooLong(usize),
    /// Decoded bytes are not valid UTF-8.
    #[error("field is not valid UTF-8")]
    InvalidUtf8,
}

/// Encodes a UTF-8 string into 7 Words (28 felts).
///
/// Bytes are packed 7-bytes-per-felt, length-prefixed, into 28 felts (7 Words).
/// Returns an error if the length exceeds [`FIELD_MAX_BYTES`].
///
/// Prefer using [`Description::new`] + [`Description::to_words`] (or `LogoURI` / `ExternalLink`)
/// directly.
pub fn field_from_bytes(bytes: &[u8]) -> Result<[Word; 7], FieldBytesError> {
    use crate::account::faucets::Description;
    let s = core::str::from_utf8(bytes).map_err(|_| FieldBytesError::InvalidUtf8)?;
    Ok(Description::new(s)?.to_words())
}

/// Description (7 Words = 28 felts), split across 7 slots.
pub static DESCRIPTION_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::description_0").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::description_1").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::description_2").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::description_3").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::description_4").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::description_5").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::description_6").expect("valid slot name"),
    ]
});

/// Logo URI (7 Words = 28 felts), split across 7 slots.
pub static LOGO_URI_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::logo_uri_0").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::logo_uri_1").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::logo_uri_2").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::logo_uri_3").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::logo_uri_4").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::logo_uri_5").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::logo_uri_6").expect("valid slot name"),
    ]
});

/// External link (7 Words = 28 felts), split across 7 slots.
pub static EXTERNAL_LINK_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::external_link_0")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::external_link_1")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::external_link_2")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::external_link_3")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::external_link_4")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::external_link_5")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::external_link_6")
            .expect("valid slot name"),
    ]
});

/// Advice map key for the description field data (7 words).
pub const DESCRIPTION_DATA_KEY: Word =
    Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(1)]);

/// Advice map key for the logo URI field data (7 words).
pub const LOGO_URI_DATA_KEY: Word =
    Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]);

/// Advice map key for the external link field data (7 words).
pub const EXTERNAL_LINK_DATA_KEY: Word =
    Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(3)]);

/// Schema commitment slot name.
pub static SCHEMA_COMMITMENT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::metadata::schema_commitment")
        .expect("storage slot name should be valid")
});

// SLOT ACCESSORS
// ================================================================================================

/// Returns the [`StorageSlotName`] for token metadata (slot 0).
pub fn token_metadata_slot() -> &'static StorageSlotName {
    &TOKEN_METADATA_SLOT
}

/// Returns the [`StorageSlotName`] for owner config (slot 1).
pub fn owner_config_slot() -> &'static StorageSlotName {
    &OWNER_CONFIG_SLOT
}

/// Returns the [`StorageSlotName`] for the mutability config Word.
pub fn mutability_config_slot() -> &'static StorageSlotName {
    &MUTABILITY_CONFIG_SLOT
}

// INFO COMPONENT
// ================================================================================================

/// A metadata component storing name, config, and optional fields in fixed value slots.
///
/// ## Storage Layout
///
/// - Slot 2–3: name (2 Words = 8 felts)
/// - Slot 4: mutability_config `[desc_mutable, logo_mutable, extlink_mutable, max_supply_mutable]`
/// - Slot 5–11: description (7 Words)
/// - Slot 12–18: logo_uri (7 Words)
/// - Slot 19–25: external_link (7 Words)
#[derive(Debug, Clone, Default)]
pub struct TokenMetadata {
    owner: Option<AccountId>,
    name: Option<TokenName>,
    description: Option<Description>,
    logo_uri: Option<LogoURI>,
    external_link: Option<ExternalLink>,
    description_mutable: bool,
    logo_uri_mutable: bool,
    external_link_mutable: bool,
    max_supply_mutable: bool,
}

impl TokenMetadata {
    /// Creates a new empty token metadata (all fields absent by default).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the owner of this metadata component.
    ///
    /// The owner is stored in the `ownable::owner_config` slot and is used by the
    /// `metadata::fungible` MASM procedures to authorize mutations (e.g.
    /// `optional_set_description`).
    pub fn with_owner(mut self, owner: AccountId) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Sets whether the max supply can be updated by the owner via
    /// `optional_set_max_supply`. If `false` (default), the max supply is immutable.
    pub fn with_max_supply_mutable(mut self, mutable: bool) -> Self {
        self.max_supply_mutable = mutable;
        self
    }

    /// Sets the token name.
    pub fn with_name(mut self, name: TokenName) -> Self {
        self.name = Some(name);
        self
    }

    /// Sets the description with mutability.
    ///
    /// When `mutable` is `true`, the owner can update the description later.
    pub fn with_description(mut self, description: Description, mutable: bool) -> Self {
        self.description = Some(description);
        self.description_mutable = mutable;
        self
    }

    /// Sets the logo URI with mutability.
    ///
    /// When `mutable` is `true`, the owner can update the logo URI later.
    pub fn with_logo_uri(mut self, logo_uri: LogoURI, mutable: bool) -> Self {
        self.logo_uri = Some(logo_uri);
        self.logo_uri_mutable = mutable;
        self
    }

    /// Sets the external link with mutability.
    ///
    /// When `mutable` is `true`, the owner can update the external link later.
    pub fn with_external_link(mut self, external_link: ExternalLink, mutable: bool) -> Self {
        self.external_link = Some(external_link);
        self.external_link_mutable = mutable;
        self
    }

    /// Returns the slot name for name chunk 0.
    pub fn name_chunk_0_slot() -> &'static StorageSlotName {
        &NAME_SLOTS[0]
    }

    /// Returns the slot name for name chunk 1.
    pub fn name_chunk_1_slot() -> &'static StorageSlotName {
        &NAME_SLOTS[1]
    }

    /// Returns the slot name for a description chunk by index (0..7).
    pub fn description_slot(index: usize) -> &'static StorageSlotName {
        &DESCRIPTION_SLOTS[index]
    }

    /// Returns the slot name for a logo URI chunk by index (0..7).
    pub fn logo_uri_slot(index: usize) -> &'static StorageSlotName {
        &LOGO_URI_SLOTS[index]
    }

    /// Returns the slot name for an external link chunk by index (0..7).
    pub fn external_link_slot(index: usize) -> &'static StorageSlotName {
        &EXTERNAL_LINK_SLOTS[index]
    }

    /// Reads the name and optional metadata fields from account storage.
    ///
    /// Returns `(name, description, logo_uri, external_link)` where each is `Some` only if
    /// at least one word is non-zero. Decoding errors (e.g. invalid UTF-8 in storage) cause the
    /// field to be returned as `None`.
    pub fn read_metadata_from_storage(
        storage: &AccountStorage,
    ) -> (Option<TokenName>, Option<Description>, Option<LogoURI>, Option<ExternalLink>) {
        let name = if let (Ok(chunk_0), Ok(chunk_1)) = (
            storage.get_item(TokenMetadata::name_chunk_0_slot()),
            storage.get_item(TokenMetadata::name_chunk_1_slot()),
        ) {
            let words: [Word; 2] = [chunk_0, chunk_1];
            if words != [Word::default(); 2] {
                TokenName::try_from_words(&words).ok()
            } else {
                None
            }
        } else {
            None
        };

        let read_field = |slots: &[StorageSlotName; 7]| -> Option<[Word; 7]> {
            let mut field = [Word::default(); 7];
            let mut any_set = false;
            for (i, slot) in field.iter_mut().enumerate() {
                if let Ok(chunk) = storage.get_item(&slots[i]) {
                    *slot = chunk;
                    if chunk != Word::default() {
                        any_set = true;
                    }
                }
            }
            if any_set { Some(field) } else { None }
        };

        let description =
            read_field(&DESCRIPTION_SLOTS).and_then(|w| Description::try_from_words(&w).ok());
        let logo_uri = read_field(&LOGO_URI_SLOTS).and_then(|w| LogoURI::try_from_words(&w).ok());
        let external_link =
            read_field(&EXTERNAL_LINK_SLOTS).and_then(|w| ExternalLink::try_from_words(&w).ok());

        (name, description, logo_uri, external_link)
    }

    /// Returns the storage slots for this metadata (without creating an `AccountComponent`).
    ///
    /// These slots are meant to be included directly in a faucet component rather than
    /// added as a separate `AccountComponent`.
    pub fn storage_slots(&self) -> Vec<StorageSlot> {
        let mut slots: Vec<StorageSlot> = Vec::new();

        // Owner slot (ownable::owner_config) — required by metadata::fungible MASM procedures
        // for get_owner and verify_owner (used in optional_set_* mutations).
        // Word layout: [0, 0, owner_suffix, owner_prefix] so that after get_item (which places
        // word[0] on top), dropping the two leading zeros yields [owner_suffix, owner_prefix].
        // Only included when an owner is explicitly set, to avoid conflicting with components
        // (like NetworkFungibleFaucet) that provide their own owner_config slot.
        if let Some(id) = self.owner {
            let owner_word =
                Word::from([Felt::ZERO, Felt::ZERO, id.suffix(), id.prefix().as_felt()]);
            slots.push(StorageSlot::with_value(owner_config_slot().clone(), owner_word));
        }

        let name_words = self.name.as_ref().map(|n| n.to_words()).unwrap_or_default();
        slots.push(StorageSlot::with_value(
            TokenMetadata::name_chunk_0_slot().clone(),
            name_words[0],
        ));
        slots.push(StorageSlot::with_value(
            TokenMetadata::name_chunk_1_slot().clone(),
            name_words[1],
        ));

        let mutability_config_word = Word::from([
            Felt::from(self.description_mutable as u32),
            Felt::from(self.logo_uri_mutable as u32),
            Felt::from(self.external_link_mutable as u32),
            Felt::from(self.max_supply_mutable as u32),
        ]);
        slots.push(StorageSlot::with_value(
            mutability_config_slot().clone(),
            mutability_config_word,
        ));

        let desc_words: [Word; 7] =
            self.description.as_ref().map(|d| d.to_words()).unwrap_or_default();
        for (i, word) in desc_words.iter().enumerate() {
            slots.push(StorageSlot::with_value(TokenMetadata::description_slot(i).clone(), *word));
        }

        let logo_words: [Word; 7] =
            self.logo_uri.as_ref().map(|l| l.to_words()).unwrap_or_default();
        for (i, word) in logo_words.iter().enumerate() {
            slots.push(StorageSlot::with_value(TokenMetadata::logo_uri_slot(i).clone(), *word));
        }

        let link_words: [Word; 7] =
            self.external_link.as_ref().map(|e| e.to_words()).unwrap_or_default();
        for (i, word) in link_words.iter().enumerate() {
            slots
                .push(StorageSlot::with_value(TokenMetadata::external_link_slot(i).clone(), *word));
        }

        slots
    }
}

/// Converts [`TokenMetadata`] into a standalone [`AccountComponent`] that includes the metadata
/// MASM library (`metadata_info_component_library`). Use this when adding metadata as a separate
/// component alongside a faucet that does not embed info via `.with_info()`.
impl From<TokenMetadata> for AccountComponent {
    fn from(info: TokenMetadata) -> Self {
        let metadata =
            AccountComponentMetadata::new("miden::standards::metadata::info", AccountType::all())
                .with_description(
                    "Component exposing token name, description, logo URI and external link",
                );

        AccountComponent::new(metadata_info_component_library(), info.storage_slots(), metadata)
            .expect(
                "TokenMetadata component should satisfy the requirements of a valid account component",
            )
    }
}

// SCHEMA COMMITMENT COMPONENT
// ================================================================================================

/// An [`AccountComponent`] exposing the account storage schema commitment.
///
/// The [`AccountSchemaCommitment`] component can be constructed from a list of [`StorageSchema`],
/// from which a commitment is computed and then inserted into the [`SCHEMA_COMMITMENT_SLOT_NAME`]
/// slot.
///
/// It reexports the `get_schema_commitment` procedure from
/// `miden::standards::metadata::storage_schema`.
///
/// ## Storage Layout
///
/// - [`Self::schema_commitment_slot`]: Storage schema commitment.
pub struct AccountSchemaCommitment {
    schema_commitment: Word,
}

impl AccountSchemaCommitment {
    /// Creates a new [`AccountSchemaCommitment`] component from storage schemas.
    ///
    /// The input schemas are merged into a single schema before the final commitment is computed.
    ///
    /// # Errors
    ///
    /// Returns an error if the schemas contain conflicting definitions for the same slot name.
    pub fn new<'a>(
        schemas: impl IntoIterator<Item = &'a StorageSchema>,
    ) -> Result<Self, ComponentMetadataError> {
        Ok(Self {
            schema_commitment: compute_schema_commitment(schemas)?,
        })
    }

    /// Creates a new [`AccountSchemaCommitment`] component from a [`StorageSchema`].
    pub fn from_schema(storage_schema: &StorageSchema) -> Result<Self, ComponentMetadataError> {
        Self::new(core::slice::from_ref(storage_schema))
    }

    /// Returns the [`StorageSlotName`] where the schema commitment is stored.
    pub fn schema_commitment_slot() -> &'static StorageSlotName {
        &SCHEMA_COMMITMENT_SLOT_NAME
    }
}

impl From<AccountSchemaCommitment> for AccountComponent {
    fn from(schema_commitment: AccountSchemaCommitment) -> Self {
        let metadata =
            AccountComponentMetadata::new("miden::metadata::schema_commitment", AccountType::all())
                .with_description("Component exposing the account storage schema commitment");

        AccountComponent::new(
            storage_schema_library(),
            vec![StorageSlot::with_value(
                AccountSchemaCommitment::schema_commitment_slot().clone(),
                schema_commitment.schema_commitment,
            )],
            metadata,
        )
        .expect(
            "AccountSchemaCommitment component should satisfy the requirements of a valid account component",
        )
    }
}

// ACCOUNT BUILDER EXTENSION
// ================================================================================================

/// An extension trait for [`AccountBuilder`] that provides a convenience method for building an
/// account with an [`AccountSchemaCommitment`] component.
pub trait AccountBuilderSchemaCommitmentExt {
    /// Builds an [`Account`] out of the configured builder after computing the storage schema
    /// commitment from all components currently in the builder and adding an
    /// [`AccountSchemaCommitment`] component.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The components' storage schemas contain conflicting definitions for the same slot name.
    /// - [`AccountBuilder::build`] fails.
    fn build_with_schema_commitment(self) -> Result<Account, AccountError>;
}

impl AccountBuilderSchemaCommitmentExt for AccountBuilder {
    fn build_with_schema_commitment(self) -> Result<Account, AccountError> {
        let schema_commitment =
            AccountSchemaCommitment::new(self.storage_schemas()).map_err(|err| {
                AccountError::other_with_source("failed to compute account schema commitment", err)
            })?;

        self.with_component(schema_commitment).build()
    }
}

// HELPERS
// ================================================================================================

/// Computes the schema commitment.
///
/// The account schema commitment is computed from the merged schema commitment.
/// If the passed list of schemas is empty, [`Word::empty()`] is returned.
fn compute_schema_commitment<'a>(
    schemas: impl IntoIterator<Item = &'a StorageSchema>,
) -> Result<Word, ComponentMetadataError> {
    let mut schemas = schemas.into_iter().peekable();
    if schemas.peek().is_none() {
        return Ok(Word::empty());
    }

    let mut merged_slots = BTreeMap::new();

    for schema in schemas {
        for (slot_name, slot_schema) in schema.iter() {
            match merged_slots.get(slot_name) {
                None => {
                    merged_slots.insert(slot_name.clone(), slot_schema.clone());
                },
                // Slot exists, check if the schema is the same before erroring
                Some(existing) => {
                    if existing != slot_schema {
                        return Err(ComponentMetadataError::InvalidSchema(format!(
                            "conflicting definitions for storage slot `{slot_name}`",
                        )));
                    }
                },
            }
        }
    }

    let merged_schema = StorageSchema::new(merged_slots)?;

    Ok(merged_schema.commitment())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
    use miden_protocol::account::component::AccountComponentMetadata;
    use miden_protocol::account::{Account, AccountBuilder};

    use super::{
        AccountBuilderSchemaCommitmentExt,
        AccountSchemaCommitment,
        NAME_UTF8_MAX_BYTES,
        TokenMetadata as InfoType,
        mutability_config_slot,
    };
    use crate::account::auth::{AuthSingleSig, NoAuth};
    use crate::account::faucets::{BasicFungibleFaucet, Description, TokenName};

    fn build_account_with_info(info: InfoType) -> Account {
        let name = TokenName::new("T").unwrap();
        let faucet = BasicFungibleFaucet::new(
            miden_protocol::asset::TokenSymbol::new("TST").unwrap(),
            2,
            miden_protocol::Felt::new(1_000),
            name,
            None,
            None,
            None,
        )
        .unwrap()
        .with_info(info);
        AccountBuilder::new([1u8; 32])
            .account_type(miden_protocol::account::AccountType::FungibleFaucet)
            .with_auth_component(NoAuth)
            .with_component(faucet)
            .build()
            .unwrap()
    }

    #[test]
    fn metadata_info_can_store_name_and_description() {
        let name = TokenName::new("test_name").unwrap();
        let description = Description::new("test description").unwrap();

        let name_words = name.to_words();
        let desc_words = description.to_words();

        let info = InfoType::new().with_name(name).with_description(description, false);
        let account = build_account_with_info(info);

        let name_0 = account.storage().get_item(InfoType::name_chunk_0_slot()).unwrap();
        let name_1 = account.storage().get_item(InfoType::name_chunk_1_slot()).unwrap();
        assert_eq!(name_0, name_words[0]);
        assert_eq!(name_1, name_words[1]);

        for (i, expected) in desc_words.iter().enumerate() {
            let chunk = account.storage().get_item(InfoType::description_slot(i)).unwrap();
            assert_eq!(chunk, *expected);
        }
    }

    #[test]
    fn metadata_info_empty_works() {
        let _account = build_account_with_info(InfoType::new());
    }

    #[test]
    fn config_slots_set_correctly() {
        use miden_protocol::Felt;

        let info = InfoType::new()
            .with_description(Description::new("test").unwrap(), true)
            .with_max_supply_mutable(true);
        let account = build_account_with_info(info);

        let mut_word = account.storage().get_item(mutability_config_slot()).unwrap();
        assert_eq!(mut_word[0], Felt::from(1u32), "desc_mutable should be 1");
        assert_eq!(mut_word[1], Felt::from(0u32), "logo_mutable should be 0");
        assert_eq!(mut_word[2], Felt::from(0u32), "extlink_mutable should be 0");
        assert_eq!(mut_word[3], Felt::from(1u32), "max_supply_mutable should be 1");

        let account_default = build_account_with_info(InfoType::new());
        let mut_default = account_default.storage().get_item(mutability_config_slot()).unwrap();
        assert_eq!(mut_default[0], Felt::from(0u32), "desc_mutable should be 0 by default");
        assert_eq!(mut_default[3], Felt::from(0u32), "max_supply_mutable should be 0 by default");
    }

    #[test]
    fn name_roundtrip() {
        let s = "POL Faucet";
        let name = TokenName::new(s).unwrap();
        let words = name.to_words();
        let decoded = TokenName::try_from_words(&words).unwrap();
        assert_eq!(decoded.as_str(), s);
    }

    #[test]
    fn name_max_32_bytes_accepted() {
        let s = "a".repeat(NAME_UTF8_MAX_BYTES);
        assert_eq!(s.len(), 32);
        let name = TokenName::new(&s).unwrap();
        let words = name.to_words();
        let decoded = TokenName::try_from_words(&words).unwrap();
        assert_eq!(decoded.as_str(), s);
    }

    #[test]
    fn name_too_long_errors() {
        let s = "a".repeat(33);
        assert!(TokenName::new(&s).is_err());
    }

    #[test]
    fn description_max_bytes_accepted() {
        let s = "a".repeat(Description::MAX_BYTES);
        let desc = Description::new(&s).unwrap();
        assert_eq!(desc.to_words().len(), 7);
    }

    #[test]
    fn description_too_long_rejected() {
        let s = "a".repeat(super::FIELD_MAX_BYTES + 1);
        assert!(Description::new(&s).is_err());
    }

    #[test]
    fn metadata_info_with_name() {
        let name = TokenName::new("My Token").unwrap();
        let name_words = name.to_words();
        let info = InfoType::new().with_name(name);
        let account = build_account_with_info(info);
        let name_0 = account.storage().get_item(InfoType::name_chunk_0_slot()).unwrap();
        let name_1 = account.storage().get_item(InfoType::name_chunk_1_slot()).unwrap();
        let decoded = TokenName::try_from_words(&[name_0, name_1]).unwrap();
        assert_eq!(decoded.as_str(), "My Token");
        assert_eq!(name_0, name_words[0]);
        assert_eq!(name_1, name_words[1]);
    }

    #[test]
    fn storage_schema_commitment_is_order_independent() {
        let toml_a = r#"
            name = "Component A"
            description = "Component A schema"
            version = "0.1.0"
            supported-types = []

            [[storage.slots]]
            name = "test::slot_a"
            type = "word"
        "#;

        let toml_b = r#"
            name = "Component B"
            description = "Component B schema"
            version = "0.1.0"
            supported-types = []

            [[storage.slots]]
            name = "test::slot_b"
            description = "description is committed to"
            type = "word"
        "#;

        let metadata_a = AccountComponentMetadata::from_toml(toml_a).unwrap();
        let metadata_b = AccountComponentMetadata::from_toml(toml_b).unwrap();

        let schema_a = metadata_a.storage_schema().clone();
        let schema_b = metadata_b.storage_schema().clone();

        // Create one component for each of two different accounts, but switch orderings
        let component_a =
            AccountSchemaCommitment::new(&[schema_a.clone(), schema_b.clone()]).unwrap();
        let component_b = AccountSchemaCommitment::new(&[schema_b, schema_a]).unwrap();

        let account_a = AccountBuilder::new([1u8; 32])
            .with_auth_component(NoAuth)
            .with_component(component_a)
            .build()
            .unwrap();

        let account_b = AccountBuilder::new([2u8; 32])
            .with_auth_component(NoAuth)
            .with_component(component_b)
            .build()
            .unwrap();

        let slot_name = AccountSchemaCommitment::schema_commitment_slot();
        let commitment_a = account_a.storage().get_item(slot_name).unwrap();
        let commitment_b = account_b.storage().get_item(slot_name).unwrap();

        assert_eq!(commitment_a, commitment_b);
    }

    #[test]
    fn storage_schema_commitment_is_empty_for_no_schemas() {
        let component = AccountSchemaCommitment::new(&[]).unwrap();

        assert_eq!(component.schema_commitment, Word::empty());
    }

    #[test]
    fn build_with_schema_commitment_adds_schema_commitment_component() {
        let auth_component = AuthSingleSig::new(
            PublicKeyCommitment::from(Word::empty()),
            AuthScheme::EcdsaK256Keccak,
        );

        let account = AccountBuilder::new([1u8; 32])
            .with_auth_component(auth_component)
            .build_with_schema_commitment()
            .unwrap();

        // The auth component has 2 slots (public key and scheme ID) and the schema commitment adds
        // 1 more.
        assert_eq!(account.storage().num_slots(), 3);

        // The auth component's public key slot should be accessible.
        assert!(account.storage().get_item(AuthSingleSig::public_key_slot()).is_ok());

        // The schema commitment slot should be non-empty since we have a component with a schema.
        let slot_name = AccountSchemaCommitment::schema_commitment_slot();
        let commitment = account.storage().get_item(slot_name).unwrap();
        assert_ne!(commitment, Word::empty());
    }
}
