//! Generic token metadata helper.
//!
//! [`TokenMetadata`] is a builder-pattern struct used to manage name and optional fields
//! (description, logo_uri, external_link) with their mutability flags in fixed value slots.
//! It is intended to be embedded inside [`FungibleTokenMetadata`] rather than used as a
//! standalone [`AccountComponent`].
//!
//! Ownership is handled by the `Ownable2Step` component.

use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::{AccountStorage, StorageSlot, StorageSlotName};

use super::{
    DESCRIPTION_SLOTS,
    EXTERNAL_LINK_SLOTS,
    LOGO_URI_SLOTS,
    NAME_SLOTS,
    mutability_config_slot,
};
use crate::account::faucets::{Description, ExternalLink, LogoURI, TokenName};

// TOKEN METADATA
// ================================================================================================

/// A helper that stores name, mutability config, and optional fields in fixed value slots.
///
/// Designed to be embedded in [`FungibleTokenMetadata`] to avoid duplication. Slot names are
/// shared via the static accessors (e.g. [`name_chunk_0_slot`]).
///
/// ## Storage Layout
///
/// - Slot 0–1: name (2 Words = 8 felts)
/// - Slot 2: mutability_config `[desc_mutable, logo_mutable, extlink_mutable,
///   is_max_supply_mutable]`
/// - Slot 3–9: description (7 Words)
/// - Slot 10–16: logo_uri (7 Words)
/// - Slot 17–23: external_link (7 Words)
///
/// [`FungibleTokenMetadata`]: crate::account::faucets::FungibleTokenMetadata
/// [`name_chunk_0_slot`]: TokenMetadata::name_chunk_0_slot
#[derive(Debug, Clone, Default)]
pub struct TokenMetadata {
    name: Option<TokenName>,
    description: Option<Description>,
    logo_uri: Option<LogoURI>,
    external_link: Option<ExternalLink>,
    is_description_mutable: bool,
    is_logo_uri_mutable: bool,
    is_external_link_mutable: bool,
    is_max_supply_mutable: bool,
}

impl TokenMetadata {
    /// Creates a new empty token metadata (all fields absent, all flags false).
    pub fn new() -> Self {
        Self::default()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Sets the token name.
    pub fn with_name(mut self, name: TokenName) -> Self {
        self.name = Some(name);
        self
    }

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

    /// Returns the token name if set.
    pub fn name(&self) -> Option<&TokenName> {
        self.name.as_ref()
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

    /// Returns the [`StorageSlotName`] for a description chunk by index (0..7).
    pub fn description_slot(index: usize) -> &'static StorageSlotName {
        &DESCRIPTION_SLOTS[index]
    }

    /// Returns the [`StorageSlotName`] for a logo URI chunk by index (0..7).
    pub fn logo_uri_slot(index: usize) -> &'static StorageSlotName {
        &LOGO_URI_SLOTS[index]
    }

    /// Returns the [`StorageSlotName`] for an external link chunk by index (0..7).
    pub fn external_link_slot(index: usize) -> &'static StorageSlotName {
        &EXTERNAL_LINK_SLOTS[index]
    }

    // STORAGE
    // --------------------------------------------------------------------------------------------

    /// Reads the name and optional metadata fields from account storage.
    ///
    /// Returns `(name, description, logo_uri, external_link)` where each is `Some` only if
    /// at least one word is non-zero. Decoding errors cause the field to be returned as `None`.
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

    /// Returns the storage slots for this metadata (name, mutability config, and all fields).
    pub fn storage_slots(&self) -> Vec<StorageSlot> {
        let mut slots: Vec<StorageSlot> = Vec::new();

        let name_words = self
            .name
            .as_ref()
            .map(|n| n.to_words())
            .unwrap_or_else(|| (0..2).map(|_| Word::default()).collect());
        slots.push(StorageSlot::with_value(
            TokenMetadata::name_chunk_0_slot().clone(),
            name_words[0],
        ));
        slots.push(StorageSlot::with_value(
            TokenMetadata::name_chunk_1_slot().clone(),
            name_words[1],
        ));

        let mutability_config_word = Word::from([
            miden_protocol::Felt::from(self.is_description_mutable as u32),
            miden_protocol::Felt::from(self.is_logo_uri_mutable as u32),
            miden_protocol::Felt::from(self.is_external_link_mutable as u32),
            miden_protocol::Felt::from(self.is_max_supply_mutable as u32),
        ]);
        slots.push(StorageSlot::with_value(
            mutability_config_slot().clone(),
            mutability_config_word,
        ));

        let desc_words: Vec<Word> = self
            .description
            .as_ref()
            .map(|d| d.to_words())
            .unwrap_or_else(|| (0..7).map(|_| Word::default()).collect());
        for (i, word) in desc_words.iter().enumerate() {
            slots.push(StorageSlot::with_value(TokenMetadata::description_slot(i).clone(), *word));
        }

        let logo_words: Vec<Word> = self
            .logo_uri
            .as_ref()
            .map(|l| l.to_words())
            .unwrap_or_else(|| (0..7).map(|_| Word::default()).collect());
        for (i, word) in logo_words.iter().enumerate() {
            slots.push(StorageSlot::with_value(TokenMetadata::logo_uri_slot(i).clone(), *word));
        }

        let link_words: Vec<Word> = self
            .external_link
            .as_ref()
            .map(|e| e.to_words())
            .unwrap_or_else(|| (0..7).map(|_| Word::default()).collect());
        for (i, word) in link_words.iter().enumerate() {
            slots
                .push(StorageSlot::with_value(TokenMetadata::external_link_slot(i).clone(), *word));
        }

        slots
    }
}
