//! Account / contract / faucet metadata
//!
//! All of the following are metadata of the account (or faucet): token_symbol, decimals,
//! max_supply, name, mutability_config, description, logo URI, and external link.
//! Ownership is handled by the `Ownable2Step` component separately.
//!
//! ## Storage layout
//!
//! | Slot name | Contents |
//! |-----------|----------|
//! | `metadata::token_metadata` | `[token_supply, max_supply, decimals, token_symbol]` |
//! | `metadata::name_0` | first 4 felts of name |
//! | `metadata::name_1` | last 4 felts of name |
//! | `metadata::mutability_config` | `[is_desc_mutable, is_logo_mutable, is_extlink_mutable, is_max_supply_mutable]` |
//! | `metadata::description_0..6` | description (7 Words, max 195 bytes) |
//! | `metadata::logo_uri_0..6` | logo URI (7 Words, max 195 bytes) |
//! | `metadata::external_link_0..6` | external link (7 Words, max 195 bytes) |
//!
//! Layout sync: the same layout is defined in MASM at `asm/standards/metadata/fungible.masm`.
//! Any change to slot indices or names must be applied in both Rust and MASM.
//!
//! ## Config Word
//!
//! A single config Word stores per-field boolean flags:
//!
//! **mutability_config**: `[is_desc_mutable, is_logo_mutable, is_extlink_mutable,
//! is_max_supply_mutable]`
//! - Each flag is 0 (immutable) or 1 (mutable / owner can update).
//!
//! Whether a field is *present* is determined by whether its storage words are all zero
//! (absent) or not (present). No separate `initialized_config` is needed.
//!
//! ## MASM modules
//!
//! All metadata procedures (getters, setters) live in `miden::standards::metadata::fungible`,
//! which depends on `ownable2step` for ownership checks. For mutable fields, accounts must
//! also include the `Ownable2Step` component (e.g. network fungible faucet).
//!
//! ## String encoding (UTF-8)
//!
//! All string fields use **7-bytes-per-felt, length-prefixed** encoding. The N felts are
//! serialized into a flat buffer of N × 7 bytes; byte 0 is the string length, followed by UTF-8
//! content, zero-padded. Each 7-byte chunk is stored as a LE u64 with the high byte always zero,
//! so it always fits in a Goldilocks field element.
//!
//! The name slots hold 2 Words (8 felts, capacity 55 bytes, capped at 32).
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
//! let metadata = FungibleTokenMetadataBuilder::new(name, symbol, decimals, max_supply).build().unwrap();
//! let account = AccountBuilder::new(seed)
//!     .with_component(metadata)
//!     .with_component(BasicFungibleFaucet)
//!     .build()?;
//! ```

mod schema_commitment;
mod token_metadata;

use miden_protocol::account::StorageSlotName;
use miden_protocol::utils::sync::LazyLock;
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
pub(crate) static TOKEN_METADATA_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::metadata::token_metadata")
        .expect("storage slot name should be valid")
});

/// Token name (2 Words = 8 felts), split across 2 slots.
///
/// The encoding is not specified; the value is opaque word data. For human-readable names,
/// use [`TokenName::new`](crate::account::faucets::TokenName::new) /
/// [`TokenName::to_words`](crate::account::faucets::TokenName::to_words) /
/// [`TokenName::try_from_words`](crate::account::faucets::TokenName::try_from_words).
pub(crate) static NAME_SLOTS: LazyLock<[StorageSlotName; 2]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::metadata::name_0").expect("valid slot name"),
        StorageSlotName::new("miden::standards::metadata::name_1").expect("valid slot name"),
    ]
});

/// Maximum length of a name in bytes when using the UTF-8 encoding (2 Words = 8 felts × 7 bytes
/// = 56 byte buffer − 1 length byte = 55 capacity, capped at 32).
pub(crate) const NAME_UTF8_MAX_BYTES: usize = 32;

/// Errors when encoding or decoding the metadata name as UTF-8.
#[derive(Debug, Clone, Error)]
pub enum NameUtf8Error {
    /// Name exceeds the maximum of 32 UTF-8 bytes.
    #[error("name must be at most 32 UTF-8 bytes, got {0}")]
    TooLong(usize),
    /// Decoded bytes are not valid UTF-8.
    #[error("name is not valid UTF-8")]
    InvalidUtf8,
}

/// Mutability config slot: `[is_desc_mutable, is_logo_mutable, is_extlink_mutable,
/// is_max_supply_mutable]`.
///
/// Each flag is 0 (immutable) or 1 (mutable / owner can update).
pub(crate) static MUTABILITY_CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::metadata::mutability_config")
        .expect("storage slot name should be valid")
});

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

/// Description (7 Words = 28 felts), split across 7 slots.
pub(crate) static DESCRIPTION_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
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
pub(crate) static LOGO_URI_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
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
pub(crate) static EXTERNAL_LINK_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
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

// SLOT ACCESSORS
// ================================================================================================

/// Returns the [`StorageSlotName`] for token metadata (slot 0).
pub(crate) fn token_metadata_slot() -> &'static StorageSlotName {
    &TOKEN_METADATA_SLOT
}

/// Returns the [`StorageSlotName`] for the mutability config Word.
pub(crate) fn mutability_config_slot() -> &'static StorageSlotName {
    &MUTABILITY_CONFIG_SLOT
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountBuilder;

    use super::{TokenMetadata as InfoType, mutability_config_slot};
    use crate::account::auth::NoAuth;
    use crate::account::faucets::{
        BasicFungibleFaucet,
        Description,
        FungibleTokenMetadata,
        FungibleTokenMetadataBuilder,
        TokenName,
    };

    fn build_faucet_metadata(
        name: TokenName,
        description: Option<Description>,
    ) -> FungibleTokenMetadata {
        let mut builder = FungibleTokenMetadataBuilder::new(
            name,
            miden_protocol::asset::TokenSymbol::new("TST").unwrap(),
            2,
            miden_protocol::Felt::new(1_000),
        );
        if let Some(desc) = description {
            builder = builder.description(desc);
        }
        builder.build().unwrap()
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
        assert_eq!(mut_word[0], Felt::from(1u32), "is_desc_mutable should be 1");
        assert_eq!(mut_word[1], Felt::from(0u32), "is_logo_mutable should be 0");
        assert_eq!(mut_word[2], Felt::from(0u32), "is_extlink_mutable should be 0");
        assert_eq!(mut_word[3], Felt::from(1u32), "is_max_supply_mutable should be 1");

        let name_default = TokenName::new("T").unwrap();
        let metadata_default = build_faucet_metadata(name_default, None);
        let account_default = build_account_with_metadata(metadata_default);
        let mut_default = account_default.storage().get_item(mutability_config_slot()).unwrap();
        assert_eq!(mut_default[0], Felt::from(0u32), "is_desc_mutable should be 0 by default");
        assert_eq!(
            mut_default[3],
            Felt::from(0u32),
            "is_max_supply_mutable should be 0 by default"
        );
    }

    #[test]
    fn name_too_long_rejected() {
        let long_name = "a".repeat(TokenName::MAX_BYTES + 1);
        assert!(TokenName::new(&long_name).is_err());
    }

    #[test]
    fn description_too_long_rejected() {
        let long_desc = "a".repeat(Description::MAX_BYTES + 1);
        assert!(Description::new(&long_desc).is_err());
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
        let s = "a".repeat(TokenName::MAX_BYTES);
        assert_eq!(s.len(), 32);
        let name = TokenName::new(&s).unwrap();
        let words = name.to_words();
        let decoded = TokenName::try_from_words(&words).unwrap();
        assert_eq!(decoded.as_str(), s);
    }

    #[test]
    fn description_max_bytes_accepted() {
        let s = "a".repeat(Description::MAX_BYTES);
        let desc = Description::new(&s).unwrap();
        assert_eq!(desc.to_words().len(), 7);
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
