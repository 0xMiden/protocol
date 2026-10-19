//! The token base URI of a [`NonFungibleFaucet`](super::NonFungibleFaucet).
//!
//! A non-empty token base URI makes the faucet's token metadata public: a token's metadata lives
//! at the base URI followed by its token ID. A faucet without one has private token metadata.

use alloc::vec::Vec;

use miden_protocol::account::component::{FeltSchema, StorageSlotSchema};
use miden_protocol::account::{AccountStorage, StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::faucets::{NonFungibleFaucetError, TokenMetadataError};
use crate::utils::{FixedWidthString, FixedWidthStringError};

// CONSTANTS
// ================================================================================================

/// Storage slot holding the non-fungible faucet's mutability config word
/// `[is_token_base_uri_mutable, 0, 0, 0]`.
///
/// It is separate from the shared token metadata mutability config, whose layout the fungible
/// faucet also uses.
static MUTABILITY_CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::non_fungible::mutability_config")
        .expect("storage slot name should be valid")
});

/// Token base URI (7 Words), split across 7 slots.
static TOKEN_BASE_URI_SLOTS: LazyLock<[StorageSlotName; 7]> = LazyLock::new(|| {
    [
        StorageSlotName::new("miden::standards::faucets::non_fungible::token_base_uri_0")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::non_fungible::token_base_uri_1")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::non_fungible::token_base_uri_2")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::non_fungible::token_base_uri_3")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::non_fungible::token_base_uri_4")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::non_fungible::token_base_uri_5")
            .expect("valid slot name"),
        StorageSlotName::new("miden::standards::faucets::non_fungible::token_base_uri_6")
            .expect("valid slot name"),
    ]
});

/// Returns the [`StorageSlotName`] holding the non-fungible faucet's mutability config word.
pub(super) fn mutability_config_slot() -> &'static StorageSlotName {
    &MUTABILITY_CONFIG_SLOT
}

/// Returns the [`StorageSlotName`] for a token base URI chunk by index (0..=6).
pub(super) fn token_base_uri_slot(index: usize) -> &'static StorageSlotName {
    &TOKEN_BASE_URI_SLOTS[index]
}

// TOKEN BASE URI
// ================================================================================================

/// The base URI of a [`NonFungibleFaucet`](super::NonFungibleFaucet)'s public token metadata (1 to
/// 195 bytes UTF-8), stored in 7 Words.
///
/// A token's metadata lives at the base URI followed by its token ID, see
/// [`NonFungibleFaucet::token_uri`](super::NonFungibleFaucet::token_uri). The base URI is never
/// empty: a faucet without one has private token metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenBaseUri(FixedWidthString<7>);

impl TokenBaseUri {
    /// Maximum byte length for a token base URI (7 Words × 4 felts × 7 bytes − 1 length byte).
    pub const MAX_BYTES: usize = FixedWidthString::<7>::CAPACITY;

    /// Creates a token base URI from a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is empty or longer than [`Self::MAX_BYTES`].
    pub fn new(s: &str) -> Result<Self, FixedWidthStringError> {
        if s.is_empty() {
            return Err(FixedWidthStringError::Empty);
        }
        FixedWidthString::<7>::new(s).map(Self)
    }

    /// Returns the token base URI as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Encodes the token base URI into 7 Words for storage.
    pub fn to_words(&self) -> Vec<Word> {
        self.0.to_words()
    }

    /// Decodes a token base URI from a 7-Word slice, returning `None` for the empty string that
    /// marks private token metadata.
    pub fn try_from_words(words: &[Word]) -> Result<Option<Self>, FixedWidthStringError> {
        let uri = FixedWidthString::<7>::try_from_words(words)?;
        Ok((!uri.as_str().is_empty()).then_some(Self(uri)))
    }
}

// TOKEN BASE URI CONFIG
// ================================================================================================

/// The token base URI of a [`NonFungibleFaucet`](super::NonFungibleFaucet) together with its
/// mutability flag.
#[derive(Debug, Clone)]
pub(super) struct TokenBaseUriConfig {
    /// The base URI of the public token metadata, or `None` if the token metadata is private.
    token_base_uri: Option<TokenBaseUri>,
    is_mutable: bool,
}

impl TokenBaseUriConfig {
    /// Creates the configuration, validating it.
    ///
    /// # Errors
    ///
    /// Returns [`NonFungibleFaucetError::MutableEmptyTokenBaseUri`] if the token base URI is
    /// mutable but not set, since the setter can never switch it from empty to non-empty.
    pub(super) fn new(
        token_base_uri: Option<TokenBaseUri>,
        is_mutable: bool,
    ) -> Result<Self, NonFungibleFaucetError> {
        if token_base_uri.is_none() && is_mutable {
            return Err(NonFungibleFaucetError::MutableEmptyTokenBaseUri);
        }

        Ok(Self { token_base_uri, is_mutable })
    }

    /// Returns the token base URI, or `None` if the token metadata is private.
    pub(super) fn token_base_uri(&self) -> Option<&TokenBaseUri> {
        self.token_base_uri.as_ref()
    }

    /// Returns whether the token base URI can be updated through `set_token_base_uri`.
    pub(super) fn is_mutable(&self) -> bool {
        self.is_mutable
    }

    /// Returns the storage slot schema entries for the mutability config and the token base URI.
    pub(super) fn storage_schema() -> Vec<(StorageSlotName, StorageSlotSchema)> {
        let mut entries = vec![(
            mutability_config_slot().clone(),
            StorageSlotSchema::value(
                "Non-fungible faucet mutability config",
                [
                    FeltSchema::bool("is_token_base_uri_mutable"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )];

        for (i, slot) in TOKEN_BASE_URI_SLOTS.iter().enumerate() {
            entries.push((
                slot.clone(),
                StorageSlotSchema::value(
                    alloc::format!("Token base URI chunk {i}"),
                    core::array::from_fn(|j| FeltSchema::felt(alloc::format!("data_{j}"))),
                ),
            ));
        }

        entries
    }

    /// Consumes `self` and returns the storage slots for the mutability config and the token base
    /// URI. Private token metadata is stored as the empty string.
    pub(super) fn into_storage_slots(self) -> Vec<StorageSlot> {
        let mutability_config_word =
            Word::from([Felt::from(self.is_mutable as u32), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
        let mut slots = vec![StorageSlot::with_value(
            mutability_config_slot().clone(),
            mutability_config_word,
        )];

        let token_base_uri_words = match &self.token_base_uri {
            Some(token_base_uri) => token_base_uri.to_words(),
            None => FixedWidthString::<7>::default().to_words(),
        };
        for (i, word) in token_base_uri_words.into_iter().enumerate() {
            slots.push(StorageSlot::with_value(token_base_uri_slot(i).clone(), word));
        }

        slots
    }

    /// Reads the configuration from the faucet account's `storage`.
    ///
    /// # Errors
    ///
    /// Returns an error if a slot cannot be read, the token base URI cannot be decoded, the
    /// mutability flag is neither 0 nor 1, or the configuration is invalid (see [`Self::new`]).
    pub(super) fn try_from_storage(
        storage: &AccountStorage,
    ) -> Result<Self, NonFungibleFaucetError> {
        let get_item = |slot_name: &StorageSlotName| {
            storage
                .get_item(slot_name)
                .map_err(|err| TokenMetadataError::StorageLookupFailed {
                    slot_name: slot_name.clone(),
                    source: err,
                })
        };

        let mut token_base_uri_words = [Word::empty(); 7];
        for (word, slot_name) in token_base_uri_words.iter_mut().zip(TOKEN_BASE_URI_SLOTS.iter()) {
            *word = get_item(slot_name)?;
        }
        let token_base_uri =
            TokenBaseUri::try_from_words(&token_base_uri_words).map_err(|err| {
                TokenMetadataError::InvalidStringField { field: "token_base_uri", source: err }
            })?;

        let mutability_flag = get_item(mutability_config_slot())?[0].as_canonical_u64();
        let is_mutable = match mutability_flag {
            0 => false,
            1 => true,
            value => {
                return Err(NonFungibleFaucetError::InvalidTokenBaseUriMutabilityFlag { value });
            },
        };

        Self::new(token_base_uri, is_mutable)
    }
}
