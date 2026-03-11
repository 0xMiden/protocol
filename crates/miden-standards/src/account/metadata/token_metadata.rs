//! Generic metadata component for non-faucet accounts.
//!
//! [`TokenMetadata`] is a builder-pattern struct that stores name, config, and optional
//! fields (description, logo_uri, external_link, owner) in fixed value slots. For faucet
//! accounts, prefer [`FungibleTokenMetadata`](crate::account::faucets::FungibleTokenMetadata)
//! which embeds all metadata in a single component.

use alloc::vec::Vec;

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent,
    AccountId,
    AccountStorage,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::{Felt, Word};

use super::{
    DESCRIPTION_SLOTS,
    EXTERNAL_LINK_SLOTS,
    LOGO_URI_SLOTS,
    NAME_SLOTS,
    mutability_config_slot,
    owner_config_slot,
};
use crate::account::components::metadata_info_component_library;
use crate::account::faucets::{Description, ExternalLink, LogoURI, TokenName};

// TOKEN METADATA
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
    /// `set_description`).
    pub fn with_owner(mut self, owner: AccountId) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Sets whether the max supply can be updated by the owner via
    /// `set_max_supply`. If `false` (default), the max supply is immutable.
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
        // for get_owner and verify_owner (used in set_* mutations).
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
/// MASM library (`metadata_info_component_library`). Use this when adding generic metadata as a
/// separate component (e.g. for non-faucet accounts).
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
