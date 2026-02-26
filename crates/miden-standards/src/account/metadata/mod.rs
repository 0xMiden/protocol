//! Account / contract / faucet metadata (slots 0..22)
//!
//! All of the following are metadata of the account (or faucet): token_symbol, decimals,
//! max_supply, owner, name, config, description, logo URI, and external link.
//!
//! ## Storage layout
//!
//! | Slot name | Contents |
//! |-----------|----------|
//! | `metadata::token_metadata` | `[token_supply, max_supply, decimals, token_symbol]` |
//! | `ownable::owner_config` | owner account id (defined by ownable module) |
//! | `metadata::name_0` | first 4 felts of name |
//! | `metadata::name_1` | last 4 felts of name |
//! | `metadata::config` | `[desc_flag, logo_flag, extlink_flag, max_supply_mutable]` |
//! | `metadata::description_0..5` | description (6 Words, ~192 bytes) |
//! | `metadata::logo_uri_0..5` | logo URI (6 Words, ~192 bytes) |
//! | `metadata::external_link_0..5` | external link (6 Words, ~192 bytes) |
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
//! The config Word stores per-field flags and the max_supply_mutable flag:
//! `[desc_flag, logo_flag, extlink_flag, max_supply_mutable]`
//!
//! Each flag uses 3 states:
//! - `0` = field not present
//! - `1` = field present, immutable
//! - `2` = field present, mutable (owner can update)
//!
//! `max_supply_mutable` uses 0/1 (always present when the faucet exists).
//!
//! ## MASM modules
//!
//! All metadata procedures (getters, `get_owner`, setters) live in
//! `miden::standards::metadata::fungible`, which depends on ownable. The standalone
//! Info component uses the standards library and exposes `get_name`, `get_description`,
//! `get_logo_uri`, `get_external_link`; for owner and mutable fields use a component
//! that re-exports from fungible (e.g. network fungible faucet).
//!
//! ## Name encoding (UTF-8)
//!
//! The name slots hold opaque words. This crate defines a **convention** for human-readable
//! names: UTF-8 bytes, 4 bytes per felt, little-endian, up to 32 bytes (see [`name_from_utf8`],
//! [`name_to_utf8`]). There is no Miden-wide standard for string→felt encoding; this convention
//! ensures Rust and MASM (or other consumers) can interoperate when they all use these helpers.
//!
//! # Example
//!
//! ```ignore
//! use miden_standards::account::metadata::Info;
//!
//! let info = Info::new()
//!     .with_name([name_word_0, name_word_1])
//!     .with_description([d0, d1, d2, d3, d4, d5], 2)   // present + mutable
//!     .with_logo_uri([l0, l1, l2, l3, l4, l5], 1);      // present + immutable
//!
//! let account = AccountBuilder::new(seed)
//!     .with_component(info)
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
    AccountStorage,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::{AccountError, ComponentMetadataError};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use thiserror::Error;

use crate::account::components::{metadata_info_component_library, storage_schema_library};

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
/// use UTF-8 encoding via [`name_from_utf8`] / [`name_to_utf8`] or [`Info::with_name_utf8`].
pub static NAME_SLOTS: LazyLock<[StorageSlotName; 2]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::name_0").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::name_1").expect("valid slot name"),
    ]
});

/// Maximum length of a name in bytes when using the UTF-8 encoding (2 Words = 8 felts × 4 bytes).
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
/// Bytes are packed little-endian, 4 bytes per felt (8 felts total). The string is
/// zero-padded to 32 bytes. Returns an error if the UTF-8 byte length exceeds 32.
pub fn name_from_utf8(s: &str) -> Result<[Word; 2], NameUtf8Error> {
    let bytes = s.as_bytes();
    if bytes.len() > NAME_UTF8_MAX_BYTES {
        return Err(NameUtf8Error::TooLong(bytes.len()));
    }
    let mut padded = [0u8; NAME_UTF8_MAX_BYTES];
    padded[..bytes.len()].copy_from_slice(bytes);
    let felts: [Felt; 8] = padded
        .chunks_exact(4)
        .map(|chunk| Felt::from(u32::from_le_bytes(chunk.try_into().unwrap())))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    Ok([
        Word::from([felts[0], felts[1], felts[2], felts[3]]),
        Word::from([felts[4], felts[5], felts[6], felts[7]]),
    ])
}

/// Decodes the 2-Word name format as UTF-8.
///
/// Assumes the name was encoded with [`name_from_utf8`] (little-endian, 4 bytes per felt).
/// Trailing zero bytes are trimmed before UTF-8 validation.
pub fn name_to_utf8(words: &[Word; 2]) -> Result<String, NameUtf8Error> {
    let mut bytes = [0u8; NAME_UTF8_MAX_BYTES];
    for (i, word) in words.iter().enumerate() {
        for (j, f) in word.iter().enumerate() {
            let v = f.as_int();
            if v > u32::MAX as u64 {
                return Err(NameUtf8Error::InvalidUtf8);
            }
            bytes[i * 16 + j * 4..][..4].copy_from_slice(&(v as u32).to_le_bytes());
        }
    }
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(NAME_UTF8_MAX_BYTES);
    String::from_utf8(bytes[..len].to_vec()).map_err(|_| NameUtf8Error::InvalidUtf8)
}

/// Config slot: `[desc_flag, logo_flag, extlink_flag, max_supply_mutable]`.
///
/// Each flag is 0 (not present), 1 (present+immutable), or 2 (present+mutable).
/// `max_supply_mutable` is 0 or 1.
pub static CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::metadata::config")
        .expect("storage slot name should be valid")
});

/// Maximum length of a metadata field (description, logo_uri, external_link) in bytes.
/// 6 Words = 24 felts × 8 bytes = 192 bytes.
pub const FIELD_MAX_BYTES: usize = 192;

/// Errors when encoding metadata fields from bytes.
#[derive(Debug, Clone, Error)]
pub enum FieldBytesError {
    /// Field exceeds [`FIELD_MAX_BYTES`].
    #[error("field must be at most {FIELD_MAX_BYTES} bytes, got {0}")]
    TooLong(usize),
}

/// Encodes a byte slice into 6 Words (24 felts).
///
/// Bytes are packed little-endian, 8 bytes per felt (24 felts total). The slice is zero-padded
/// to 192 bytes. Returns an error if the length exceeds 192.
pub fn field_from_bytes(bytes: &[u8]) -> Result<[Word; 6], FieldBytesError> {
    if bytes.len() > FIELD_MAX_BYTES {
        return Err(FieldBytesError::TooLong(bytes.len()));
    }
    let mut padded = [0u8; FIELD_MAX_BYTES];
    padded[..bytes.len()].copy_from_slice(bytes);
    let felts: Vec<Felt> = padded
        .chunks_exact(8)
        .map(|chunk| {
            Felt::try_from(u64::from_le_bytes(chunk.try_into().unwrap()))
                .expect("u64 values from 8-byte chunks fit in Felt")
        })
        .collect();
    let felts: [Felt; 24] = felts.try_into().unwrap();
    Ok([
        Word::from([felts[0], felts[1], felts[2], felts[3]]),
        Word::from([felts[4], felts[5], felts[6], felts[7]]),
        Word::from([felts[8], felts[9], felts[10], felts[11]]),
        Word::from([felts[12], felts[13], felts[14], felts[15]]),
        Word::from([felts[16], felts[17], felts[18], felts[19]]),
        Word::from([felts[20], felts[21], felts[22], felts[23]]),
    ])
}

/// Description (6 Words = 24 felts), split across 6 slots.
pub static DESCRIPTION_SLOTS: LazyLock<[StorageSlotName; 6]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::description_0").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::description_1").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::description_2").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::description_3").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::description_4").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::description_5").expect("valid slot name"),
    ]
});

/// Logo URI (6 Words = 24 felts), split across 6 slots.
pub static LOGO_URI_SLOTS: LazyLock<[StorageSlotName; 6]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::logo_uri_0").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::logo_uri_1").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::logo_uri_2").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::logo_uri_3").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::logo_uri_4").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::logo_uri_5").expect("valid slot name"),
    ]
});

/// External link (6 Words = 24 felts), split across 6 slots.
pub static EXTERNAL_LINK_SLOTS: LazyLock<[StorageSlotName; 6]> = LazyLock::new(|| {
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
    ]
});

/// Schema commitment slot.
pub static SCHEMA_COMMITMENT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::metadata::storage_schema")
        .expect("storage slot name should be valid")
});

/// The advice map key used by `optional_set_description` to read the 6 field words.
///
/// Must match `DESCRIPTION_DATA_KEY` in `fungible.masm`. The value stored under this key
/// should be 24 felts: `[FIELD_0, FIELD_1, FIELD_2, FIELD_3, FIELD_4, FIELD_5]`.
pub const DESCRIPTION_DATA_KEY: Word =
    Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(1)]);

/// The advice map key used by `optional_set_logo_uri` to read the 6 field words.
pub const LOGO_URI_DATA_KEY: Word =
    Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]);

/// The advice map key used by `optional_set_external_link` to read the 6 field words.
pub const EXTERNAL_LINK_DATA_KEY: Word =
    Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(3)]);

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

/// Returns the [`StorageSlotName`] for the config Word.
pub fn config_slot() -> &'static StorageSlotName {
    &CONFIG_SLOT
}

// INFO COMPONENT
// ================================================================================================

/// A metadata component storing name, config, and optional fields in fixed value slots.
///
/// ## Storage Layout
///
/// - Slot 2–3: name (2 Words = 8 felts)
/// - Slot 4: config `[desc_flag, logo_flag, extlink_flag, max_supply_mutable]`
/// - Slot 5–10: description (6 Words)
/// - Slot 11–16: logo_uri (6 Words)
/// - Slot 17–22: external_link (6 Words)
#[derive(Debug, Clone, Default)]
pub struct Info {
    name: Option<[Word; 2]>,
    /// Description flag: 0=not present, 1=present+immutable, 2=present+mutable.
    description_flag: u8,
    /// Logo URI flag: 0=not present, 1=present+immutable, 2=present+mutable.
    logo_uri_flag: u8,
    /// External link flag: 0=not present, 1=present+immutable, 2=present+mutable.
    external_link_flag: u8,
    /// If true (1), the owner may call optional_set_max_supply. If false (0), immutable.
    max_supply_mutable: bool,
    description: Option<[Word; 6]>,
    logo_uri: Option<[Word; 6]>,
    external_link: Option<[Word; 6]>,
}

impl Info {
    /// Creates a new empty metadata info (all fields absent by default).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether the max supply can be updated by the owner via
    /// `optional_set_max_supply`. If `false` (default), the max supply is immutable.
    pub fn with_max_supply_mutable(mut self, mutable: bool) -> Self {
        self.max_supply_mutable = mutable;
        self
    }

    /// Sets the name metadata (2 Words = 8 felts).
    ///
    /// Encoding is not specified; for human-readable UTF-8 text use
    /// [`with_name_utf8`](Info::with_name_utf8).
    pub fn with_name(mut self, name: [Word; 2]) -> Self {
        self.name = Some(name);
        self
    }

    /// Sets the name from a UTF-8 string (at most [`NAME_UTF8_MAX_BYTES`] bytes).
    pub fn with_name_utf8(mut self, s: &str) -> Result<Self, NameUtf8Error> {
        self.name = Some(name_from_utf8(s)?);
        Ok(self)
    }

    /// Sets the description metadata (6 Words) with mutability flag.
    ///
    /// `flag`: 1 = present+immutable, 2 = present+mutable.
    pub fn with_description(mut self, description: [Word; 6], flag: u8) -> Self {
        assert!(flag == 1 || flag == 2, "description flag must be 1 or 2");
        self.description = Some(description);
        self.description_flag = flag;
        self
    }

    /// Sets the description from a byte slice (at most [`FIELD_MAX_BYTES`] bytes).
    pub fn with_description_from_bytes(
        mut self,
        bytes: &[u8],
        flag: u8,
    ) -> Result<Self, FieldBytesError> {
        assert!(flag == 1 || flag == 2, "description flag must be 1 or 2");
        self.description = Some(field_from_bytes(bytes)?);
        self.description_flag = flag;
        Ok(self)
    }

    /// Sets the logo URI metadata (6 Words) with mutability flag.
    ///
    /// `flag`: 1 = present+immutable, 2 = present+mutable.
    pub fn with_logo_uri(mut self, logo_uri: [Word; 6], flag: u8) -> Self {
        assert!(flag == 1 || flag == 2, "logo_uri flag must be 1 or 2");
        self.logo_uri = Some(logo_uri);
        self.logo_uri_flag = flag;
        self
    }

    /// Sets the logo URI from a byte slice (at most [`FIELD_MAX_BYTES`] bytes).
    pub fn with_logo_uri_from_bytes(
        mut self,
        bytes: &[u8],
        flag: u8,
    ) -> Result<Self, FieldBytesError> {
        assert!(flag == 1 || flag == 2, "logo_uri flag must be 1 or 2");
        self.logo_uri = Some(field_from_bytes(bytes)?);
        self.logo_uri_flag = flag;
        Ok(self)
    }

    /// Sets the external link metadata (6 Words) with mutability flag.
    ///
    /// `flag`: 1 = present+immutable, 2 = present+mutable.
    pub fn with_external_link(mut self, external_link: [Word; 6], flag: u8) -> Self {
        assert!(flag == 1 || flag == 2, "external_link flag must be 1 or 2");
        self.external_link = Some(external_link);
        self.external_link_flag = flag;
        self
    }

    /// Sets the external link from a byte slice (at most [`FIELD_MAX_BYTES`] bytes).
    pub fn with_external_link_from_bytes(
        mut self,
        bytes: &[u8],
        flag: u8,
    ) -> Result<Self, FieldBytesError> {
        assert!(flag == 1 || flag == 2, "external_link flag must be 1 or 2");
        self.external_link = Some(field_from_bytes(bytes)?);
        self.external_link_flag = flag;
        Ok(self)
    }

    /// Returns the slot name for name chunk 0.
    pub fn name_chunk_0_slot() -> &'static StorageSlotName {
        &NAME_SLOTS[0]
    }

    /// Returns the slot name for name chunk 1.
    pub fn name_chunk_1_slot() -> &'static StorageSlotName {
        &NAME_SLOTS[1]
    }

    /// Returns the slot name for a description chunk by index (0..6).
    pub fn description_slot(index: usize) -> &'static StorageSlotName {
        &DESCRIPTION_SLOTS[index]
    }

    /// Returns the slot name for a logo URI chunk by index (0..6).
    pub fn logo_uri_slot(index: usize) -> &'static StorageSlotName {
        &LOGO_URI_SLOTS[index]
    }

    /// Returns the slot name for an external link chunk by index (0..6).
    pub fn external_link_slot(index: usize) -> &'static StorageSlotName {
        &EXTERNAL_LINK_SLOTS[index]
    }

    /// Reads the name and optional metadata fields from account storage.
    ///
    /// Returns `(name, description, logo_uri, external_link)` where each is `Some` only if
    /// at least one word is non-zero.
    #[allow(clippy::type_complexity)]
    pub fn read_metadata_from_storage(
        storage: &AccountStorage,
    ) -> (Option<[Word; 2]>, Option<[Word; 6]>, Option<[Word; 6]>, Option<[Word; 6]>) {
        // Read name
        let name = if let (Ok(chunk_0), Ok(chunk_1)) = (
            storage.get_item(Info::name_chunk_0_slot()),
            storage.get_item(Info::name_chunk_1_slot()),
        ) {
            let name: [Word; 2] = [chunk_0, chunk_1];
            if name != [Word::default(); 2] { Some(name) } else { None }
        } else {
            None
        };

        let read_field = |slots: &[StorageSlotName; 6]| -> Option<[Word; 6]> {
            let mut field = [Word::default(); 6];
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

        let description = read_field(&DESCRIPTION_SLOTS);
        let logo_uri = read_field(&LOGO_URI_SLOTS);
        let external_link = read_field(&EXTERNAL_LINK_SLOTS);

        (name, description, logo_uri, external_link)
    }
}

impl From<Info> for AccountComponent {
    fn from(extension: Info) -> Self {
        let mut storage_slots: Vec<StorageSlot> = Vec::new();

        if let Some(name) = extension.name {
            storage_slots.push(StorageSlot::with_value(Info::name_chunk_0_slot().clone(), name[0]));
            storage_slots.push(StorageSlot::with_value(Info::name_chunk_1_slot().clone(), name[1]));
        }

        // Config word: [desc_flag, logo_flag, extlink_flag, max_supply_mutable]
        let config_word = Word::from([
            Felt::from(extension.description_flag as u32),
            Felt::from(extension.logo_uri_flag as u32),
            Felt::from(extension.external_link_flag as u32),
            Felt::from(extension.max_supply_mutable as u32),
        ]);
        storage_slots.push(StorageSlot::with_value(config_slot().clone(), config_word));

        // Description slots (always write 6 slots if flag > 0)
        let description = extension.description.unwrap_or([Word::default(); 6]);
        if extension.description_flag > 0 {
            for (i, word) in description.iter().enumerate() {
                storage_slots
                    .push(StorageSlot::with_value(Info::description_slot(i).clone(), *word));
            }
        }

        // Logo URI slots
        let logo_uri = extension.logo_uri.unwrap_or([Word::default(); 6]);
        if extension.logo_uri_flag > 0 {
            for (i, word) in logo_uri.iter().enumerate() {
                storage_slots.push(StorageSlot::with_value(Info::logo_uri_slot(i).clone(), *word));
            }
        }

        // External link slots
        let external_link = extension.external_link.unwrap_or([Word::default(); 6]);
        if extension.external_link_flag > 0 {
            for (i, word) in external_link.iter().enumerate() {
                storage_slots
                    .push(StorageSlot::with_value(Info::external_link_slot(i).clone(), *word));
            }
        }

        let metadata = AccountComponentMetadata::new("miden::standards::metadata::info")
            .with_description(
                "Metadata info (name, config, description, logo URI, external link) in fixed value slots",
            )
            .with_supports_all_types();

        AccountComponent::new(metadata_info_component_library(), storage_slots, metadata)
            .expect("Info component should satisfy the requirements")
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
        let metadata = AccountComponentMetadata::new("miden::metadata::schema_commitment")
            .with_description("Component exposing the account storage schema commitment")
            .with_supports_all_types();

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
    use miden_protocol::account::AccountBuilder;
    use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
    use miden_protocol::account::component::AccountComponentMetadata;

    use super::{
        AccountBuilderSchemaCommitmentExt,
        AccountSchemaCommitment,
        FIELD_MAX_BYTES,
        FieldBytesError,
        Info,
        NAME_UTF8_MAX_BYTES,
        NameUtf8Error,
        config_slot,
        field_from_bytes,
        name_from_utf8,
        name_to_utf8,
    };
    use crate::account::auth::{AuthSingleSig, NoAuth};

    #[test]
    fn metadata_info_can_store_name_and_description() {
        let name = [Word::from([1u32, 2, 3, 4]), Word::from([5u32, 6, 7, 8])];
        let description = [
            Word::from([10u32, 11, 12, 13]),
            Word::from([14u32, 15, 16, 17]),
            Word::from([18u32, 19, 20, 21]),
            Word::from([22u32, 23, 24, 25]),
            Word::from([26u32, 27, 28, 29]),
            Word::from([30u32, 31, 32, 33]),
        ];

        let extension = Info::new().with_name(name).with_description(description, 1);

        let account = AccountBuilder::new([1u8; 32])
            .with_auth_component(NoAuth)
            .with_component(extension)
            .build()
            .unwrap();

        // Verify name chunks
        let name_0 = account.storage().get_item(Info::name_chunk_0_slot()).unwrap();
        let name_1 = account.storage().get_item(Info::name_chunk_1_slot()).unwrap();
        assert_eq!(name_0, name[0]);
        assert_eq!(name_1, name[1]);

        // Verify description chunks
        for (i, expected) in description.iter().enumerate() {
            let chunk = account.storage().get_item(Info::description_slot(i)).unwrap();
            assert_eq!(chunk, *expected);
        }
    }

    #[test]
    fn metadata_info_empty_works() {
        let extension = Info::new();

        let _account = AccountBuilder::new([1u8; 32])
            .with_auth_component(NoAuth)
            .with_component(extension)
            .build()
            .unwrap();
    }

    #[test]
    fn config_slot_set_correctly() {
        use miden_protocol::Felt;

        // Info with description mutable, max_supply_mutable = true
        let info = Info::new()
            .with_description([Word::default(); 6], 2)
            .with_max_supply_mutable(true);
        let account = AccountBuilder::new([2u8; 32])
            .with_auth_component(NoAuth)
            .with_component(info)
            .build()
            .unwrap();
        let word = account.storage().get_item(config_slot()).unwrap();
        assert_eq!(word[0], Felt::from(2u32), "desc_flag should be 2");
        assert_eq!(word[1], Felt::from(0u32), "logo_flag should be 0");
        assert_eq!(word[2], Felt::from(0u32), "extlink_flag should be 0");
        assert_eq!(word[3], Felt::from(1u32), "max_supply_mutable should be 1");

        // Info with defaults (all flags 0)
        let account_default = AccountBuilder::new([3u8; 32])
            .with_auth_component(NoAuth)
            .with_component(Info::new())
            .build()
            .unwrap();
        let word_default = account_default.storage().get_item(config_slot()).unwrap();
        assert_eq!(word_default[0], Felt::from(0u32), "desc_flag should be 0 by default");
        assert_eq!(word_default[3], Felt::from(0u32), "max_supply_mutable should be 0 by default");
    }

    #[test]
    fn name_utf8_roundtrip() {
        let s = "POL Faucet";
        let words = name_from_utf8(s).unwrap();
        let decoded = name_to_utf8(&words).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn name_utf8_max_32_bytes_accepted() {
        let s = "a".repeat(NAME_UTF8_MAX_BYTES);
        assert_eq!(s.len(), 32);
        let words = name_from_utf8(&s).unwrap();
        let decoded = name_to_utf8(&words).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn name_utf8_too_long_errors() {
        let s = "a".repeat(33);
        assert!(matches!(name_from_utf8(&s), Err(NameUtf8Error::TooLong(33))));
    }

    #[test]
    fn field_192_bytes_accepted() {
        let bytes = [0u8; FIELD_MAX_BYTES];
        let words = field_from_bytes(&bytes).unwrap();
        assert_eq!(words.len(), 6);
    }

    #[test]
    fn field_193_bytes_rejected() {
        let bytes = [0u8; 193];
        assert!(matches!(field_from_bytes(&bytes), Err(FieldBytesError::TooLong(193))));
    }

    #[test]
    fn metadata_info_with_name_utf8() {
        let extension = Info::new().with_name_utf8("My Token").unwrap();
        let account = AccountBuilder::new([1u8; 32])
            .with_auth_component(NoAuth)
            .with_component(extension)
            .build()
            .unwrap();
        let name_0 = account.storage().get_item(Info::name_chunk_0_slot()).unwrap();
        let name_1 = account.storage().get_item(Info::name_chunk_1_slot()).unwrap();
        let decoded = name_to_utf8(&[name_0, name_1]).unwrap();
        assert_eq!(decoded, "My Token");
    }

    #[test]
    fn metadata_info_name_only_works() {
        let name = [Word::from([1u32, 2, 3, 4]), Word::from([5u32, 6, 7, 8])];
        let extension = Info::new().with_name(name);

        let account = AccountBuilder::new([1u8; 32])
            .with_auth_component(NoAuth)
            .with_component(extension)
            .build()
            .unwrap();

        let name_0 = account.storage().get_item(Info::name_chunk_0_slot()).unwrap();
        let name_1 = account.storage().get_item(Info::name_chunk_1_slot()).unwrap();
        assert_eq!(name_0, name[0]);
        assert_eq!(name_1, name[1]);
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
