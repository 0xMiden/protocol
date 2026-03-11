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
//! The TokenMetadata component uses the standards library and exposes `get_name`; for owner
//! and mutable fields use a component that re-exports from fungible (e.g. network fungible
//! faucet).
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
//! let metadata = FungibleTokenMetadata::new(/* ... */).unwrap();
//! let account = AccountBuilder::new(seed)
//!     .with_component(metadata)
//!     .with_component(BasicFungibleFaucet)
//!     .build()?;
//! ```

mod schema_commitment;
mod token_metadata;

use alloc::string::String;

use miden_protocol::account::StorageSlotName;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
pub use schema_commitment::{
    AccountBuilderSchemaCommitmentExt,
    AccountSchemaCommitment,
    SCHEMA_COMMITMENT_SLOT_NAME,
};
use thiserror::Error;
pub use token_metadata::TokenMetadata;

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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::account::AccountBuilder;

    use super::{NAME_UTF8_MAX_BYTES, TokenMetadata as InfoType, mutability_config_slot};
    use crate::account::auth::NoAuth;
    use crate::account::faucets::{
        BasicFungibleFaucet,
        Description,
        FungibleTokenMetadata,
        TokenName,
    };

    fn build_faucet_metadata(
        name: TokenName,
        description: Option<Description>,
    ) -> FungibleTokenMetadata {
        FungibleTokenMetadata::new(
            miden_protocol::asset::TokenSymbol::new("TST").unwrap(),
            2,
            miden_protocol::Felt::new(1_000),
            name,
            description,
            None,
            None,
        )
        .unwrap()
    }

    fn build_account_with_metadata(
        metadata: FungibleTokenMetadata,
    ) -> miden_protocol::account::Account {
        AccountBuilder::new([1u8; 32])
            .account_type(miden_protocol::account::AccountType::FungibleFaucet)
            .with_auth_component(NoAuth)
            .with_component(metadata)
            .with_component(BasicFungibleFaucet)
            .build()
            .unwrap()
    }

    #[test]
    fn metadata_info_can_store_name_and_description() {
        let name = TokenName::new("test_name").unwrap();
        let description = Description::new("test description").unwrap();

        let name_words = name.to_words();
        let desc_words = description.to_words();

        let metadata = build_faucet_metadata(name, Some(description));
        let account = build_account_with_metadata(metadata);

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
        let name = TokenName::new("T").unwrap();
        let metadata = build_faucet_metadata(name, None);
        let _account = build_account_with_metadata(metadata);
    }

    #[test]
    fn config_slots_set_correctly() {
        use miden_protocol::Felt;

        let name = TokenName::new("T").unwrap();
        let metadata = build_faucet_metadata(name, Some(Description::new("test").unwrap()))
            .with_description_mutable(true)
            .with_max_supply_mutable(true);
        let account = build_account_with_metadata(metadata);

        let mut_word = account.storage().get_item(mutability_config_slot()).unwrap();
        assert_eq!(mut_word[0], Felt::from(1u32), "desc_mutable should be 1");
        assert_eq!(mut_word[1], Felt::from(0u32), "logo_mutable should be 0");
        assert_eq!(mut_word[2], Felt::from(0u32), "extlink_mutable should be 0");
        assert_eq!(mut_word[3], Felt::from(1u32), "max_supply_mutable should be 1");

        let name_default = TokenName::new("T").unwrap();
        let metadata_default = build_faucet_metadata(name_default, None);
        let account_default = build_account_with_metadata(metadata_default);
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
        let metadata = build_faucet_metadata(name, None);
        let account = build_account_with_metadata(metadata);
        let name_0 = account.storage().get_item(InfoType::name_chunk_0_slot()).unwrap();
        let name_1 = account.storage().get_item(InfoType::name_chunk_1_slot()).unwrap();
        let decoded = TokenName::try_from_words(&[name_0, name_1]).unwrap();
        assert_eq!(decoded.as_str(), "My Token");
        assert_eq!(name_0, name_words[0]);
        assert_eq!(name_1, name_words[1]);
    }
}
