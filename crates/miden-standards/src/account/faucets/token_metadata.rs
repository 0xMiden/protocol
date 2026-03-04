use alloc::boxed::Box;
use alloc::string::String;

use miden_protocol::account::{AccountStorage, StorageSlot, StorageSlotName};
use miden_protocol::asset::{FungibleAsset, TokenSymbol};
use miden_protocol::{Felt, Word};

use super::FungibleFaucetError;
use crate::account::metadata::{self, FieldBytesError, NameUtf8Error};

// ENCODING CONSTANTS
// ================================================================================================

/// Number of data bytes packed into each felt (7 bytes = 56 bits, always < Goldilocks prime).
const BYTES_PER_FELT: usize = 7;

// TOKEN NAME
// ================================================================================================

/// Token display name (max 32 bytes UTF-8).
///
/// Internally stores the un-encoded string for cheap access via [`as_str`](Self::as_str).
/// The invariant that the string can be encoded into 2 Words (8 felts × 7 bytes/felt) is
/// enforced at construction time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenName(Box<str>);

impl TokenName {
    /// Maximum byte length for a token name (2 Words = 8 felts × 7 bytes, capacity 55,
    /// capped at 32).
    pub const MAX_BYTES: usize = metadata::NAME_UTF8_MAX_BYTES;

    /// Creates a token name from a UTF-8 string (at most 32 bytes).
    pub fn new(s: &str) -> Result<Self, NameUtf8Error> {
        if s.len() > Self::MAX_BYTES {
            return Err(NameUtf8Error::TooLong(s.len()));
        }
        Ok(Self(s.into()))
    }

    /// Returns the name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encodes the name into 2 Words for storage (7 bytes/felt, length-prefixed,
    /// zero-padded).
    pub fn to_words(&self) -> [Word; 2] {
        let felts = encode_utf8_to_felts::<8>(self.0.as_bytes());
        [
            Word::from([felts[0], felts[1], felts[2], felts[3]]),
            Word::from([felts[4], felts[5], felts[6], felts[7]]),
        ]
    }

    /// Decodes a token name from 2 Words (7 bytes/felt, length-prefixed).
    pub fn try_from_words(words: &[Word; 2]) -> Result<Self, NameUtf8Error> {
        let felts: [Felt; 8] = [
            words[0][0],
            words[0][1],
            words[0][2],
            words[0][3],
            words[1][0],
            words[1][1],
            words[1][2],
            words[1][3],
        ];
        let s = decode_felts_to_utf8::<8>(&felts).map_err(|_| NameUtf8Error::InvalidUtf8)?;
        if s.len() > Self::MAX_BYTES {
            return Err(NameUtf8Error::TooLong(s.len()));
        }
        Ok(Self(s.into()))
    }
}

// DESCRIPTION
// ================================================================================================

/// Token description (max [`FIELD_MAX_BYTES`](metadata::FIELD_MAX_BYTES) bytes UTF-8).
///
/// Internally stores the un-encoded string. The invariant that it can be encoded into 7 Words
/// (28 felts, 7 bytes/felt, length-prefixed) is enforced at construction time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description(Box<str>);

impl Description {
    /// Maximum byte length for a description (7 Words = 28 felts × 7 bytes − 1 length byte).
    pub const MAX_BYTES: usize = metadata::FIELD_MAX_BYTES;

    /// Creates a description from a UTF-8 string.
    pub fn new(s: &str) -> Result<Self, FieldBytesError> {
        if s.len() > Self::MAX_BYTES {
            return Err(FieldBytesError::TooLong(s.len()));
        }
        Ok(Self(s.into()))
    }

    /// Returns the description as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encodes the description into 7 Words for storage (7 bytes/felt, length-prefixed).
    pub fn to_words(&self) -> [Word; 7] {
        encode_field_to_words(self.0.as_bytes())
    }

    /// Decodes a description from 7 Words (7 bytes/felt, length-prefixed).
    pub fn try_from_words(words: &[Word; 7]) -> Result<Self, FieldBytesError> {
        let s = decode_field_from_words(words)?;
        Ok(Self(s.into()))
    }
}

// LOGO URI
// ================================================================================================

/// Token logo URI (max [`FIELD_MAX_BYTES`](metadata::FIELD_MAX_BYTES) bytes UTF-8).
///
/// Internally stores the un-encoded string. The invariant that it can be encoded into 7 Words
/// (28 felts, 7 bytes/felt, length-prefixed) is enforced at construction time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoURI(Box<str>);

impl LogoURI {
    /// Maximum byte length for a logo URI (7 Words = 28 felts × 7 bytes − 1 length byte).
    pub const MAX_BYTES: usize = metadata::FIELD_MAX_BYTES;

    /// Creates a logo URI from a UTF-8 string.
    pub fn new(s: &str) -> Result<Self, FieldBytesError> {
        if s.len() > Self::MAX_BYTES {
            return Err(FieldBytesError::TooLong(s.len()));
        }
        Ok(Self(s.into()))
    }

    /// Returns the logo URI as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encodes the logo URI into 7 Words for storage (7 bytes/felt, length-prefixed).
    pub fn to_words(&self) -> [Word; 7] {
        encode_field_to_words(self.0.as_bytes())
    }

    /// Decodes a logo URI from 7 Words (7 bytes/felt, length-prefixed).
    pub fn try_from_words(words: &[Word; 7]) -> Result<Self, FieldBytesError> {
        let s = decode_field_from_words(words)?;
        Ok(Self(s.into()))
    }
}

// EXTERNAL LINK
// ================================================================================================

/// Token external link (max [`FIELD_MAX_BYTES`](metadata::FIELD_MAX_BYTES) bytes UTF-8).
///
/// Internally stores the un-encoded string. The invariant that it can be encoded into 7 Words
/// (28 felts, 7 bytes/felt, length-prefixed) is enforced at construction time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLink(Box<str>);

impl ExternalLink {
    /// Maximum byte length for an external link (7 Words = 28 felts × 7 bytes − 1 length byte).
    pub const MAX_BYTES: usize = metadata::FIELD_MAX_BYTES;

    /// Creates an external link from a UTF-8 string.
    pub fn new(s: &str) -> Result<Self, FieldBytesError> {
        if s.len() > Self::MAX_BYTES {
            return Err(FieldBytesError::TooLong(s.len()));
        }
        Ok(Self(s.into()))
    }

    /// Returns the external link as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encodes the external link into 7 Words for storage (7 bytes/felt, length-prefixed).
    pub fn to_words(&self) -> [Word; 7] {
        encode_field_to_words(self.0.as_bytes())
    }

    /// Decodes an external link from 7 Words (7 bytes/felt, length-prefixed).
    pub fn try_from_words(words: &[Word; 7]) -> Result<Self, FieldBytesError> {
        let s = decode_field_from_words(words)?;
        Ok(Self(s.into()))
    }
}

// ENCODING HELPERS
// ================================================================================================

/// Encodes a UTF-8 byte slice into `N` felts using 7-bytes-per-felt, length-prefixed encoding.
///
/// ## Buffer layout (`N × 7` bytes)
///
/// ```text
/// Byte 0:          string length (u8)
/// Bytes 1..1+len:  UTF-8 content
/// Remaining:       zero-padded
///
/// Felt 0: buffer[0..7]   (length byte + first 6 data bytes)
/// Felt 1: buffer[7..14]  (next 7 data bytes)
/// ...
/// ```
///
/// Each 7-byte chunk is stored as a little-endian `u64` with the high byte always zero,
/// so the value is always < 2^56 and fits safely in a Goldilocks field element.
///
/// # Panics
///
/// Panics (debug-only) if `bytes.len() + 1 > N * BYTES_PER_FELT` (content + length byte
/// exceeds buffer capacity).
fn encode_utf8_to_felts<const N: usize>(bytes: &[u8]) -> [Felt; N] {
    let buf_len = N * BYTES_PER_FELT;
    debug_assert!(bytes.len() < buf_len);

    let mut buf = [0u8; 256]; // large enough for any field (max 28 * 7 = 196)
    buf[0] = bytes.len() as u8;
    buf[1..1 + bytes.len()].copy_from_slice(bytes);

    let mut felts = [Felt::ZERO; N];
    for (i, felt) in felts.iter_mut().enumerate() {
        let start = i * BYTES_PER_FELT;
        let mut le_bytes = [0u8; 8];
        le_bytes[..BYTES_PER_FELT].copy_from_slice(&buf[start..start + BYTES_PER_FELT]);
        // High byte is always 0 ⇒ value < 2^56, safe for Goldilocks.
        *felt = Felt::try_from(u64::from_le_bytes(le_bytes)).expect("7 bytes always fit in a Felt");
    }
    felts
}

/// Decodes `N` felts (7-bytes-per-felt, length-prefixed) back to a UTF-8 string.
fn decode_felts_to_utf8<const N: usize>(felts: &[Felt; N]) -> Result<String, FieldBytesError> {
    let buf_len = N * BYTES_PER_FELT;
    let mut buf = [0u8; 256];
    for (i, felt) in felts.iter().enumerate() {
        let v = felt.as_int();
        let le = v.to_le_bytes();
        // Reject values that use the high byte (> 7 bytes of data).
        if le[BYTES_PER_FELT] != 0 {
            return Err(FieldBytesError::InvalidUtf8);
        }
        buf[i * BYTES_PER_FELT..][..BYTES_PER_FELT].copy_from_slice(&le[..BYTES_PER_FELT]);
    }
    let len = buf[0] as usize;
    if len + 1 > buf_len {
        return Err(FieldBytesError::InvalidUtf8);
    }
    String::from_utf8(buf[1..1 + len].to_vec()).map_err(|_| FieldBytesError::InvalidUtf8)
}

/// Encodes a byte slice into 7 Words (28 felts, 7 bytes/felt, length-prefixed, zero-padded).
///
/// # Panics
///
/// Panics (debug-only) if `bytes.len() > FIELD_MAX_BYTES`. Callers must validate length first.
fn encode_field_to_words(bytes: &[u8]) -> [Word; 7] {
    debug_assert!(bytes.len() <= metadata::FIELD_MAX_BYTES);
    let felts = encode_utf8_to_felts::<28>(bytes);
    [
        Word::from([felts[0], felts[1], felts[2], felts[3]]),
        Word::from([felts[4], felts[5], felts[6], felts[7]]),
        Word::from([felts[8], felts[9], felts[10], felts[11]]),
        Word::from([felts[12], felts[13], felts[14], felts[15]]),
        Word::from([felts[16], felts[17], felts[18], felts[19]]),
        Word::from([felts[20], felts[21], felts[22], felts[23]]),
        Word::from([felts[24], felts[25], felts[26], felts[27]]),
    ]
}

/// Decodes 7 Words (28 felts, 7 bytes/felt, length-prefixed) back to a UTF-8 string.
fn decode_field_from_words(words: &[Word; 7]) -> Result<String, FieldBytesError> {
    let mut felts = [Felt::ZERO; 28];
    for (i, word) in words.iter().enumerate() {
        felts[i * 4..i * 4 + 4].copy_from_slice(word.as_slice());
    }
    decode_felts_to_utf8::<28>(&felts)
}

// TOKEN METADATA
// ================================================================================================

/// Token metadata for fungible faucet accounts.
///
/// This struct encapsulates the metadata associated with a fungible token faucet:
/// - `token_supply`: The current amount of tokens issued by the faucet.
/// - `max_supply`: The maximum amount of tokens that can be issued.
/// - `decimals`: The number of decimal places for token amounts.
/// - `symbol`: The token symbol.
///
/// The metadata is stored in a single storage slot as:
/// `[token_supply, max_supply, decimals, symbol]`
///
/// `name` and optional `description`/`logo_uri`/`external_link` are not serialized into that
/// slot. They are kept here as convenience accessors and for use when constructing the
/// [`TokenMetadata`](crate::account::metadata::TokenMetadata) storage slots via
/// [`BasicFungibleFaucet::with_info`](super::BasicFungibleFaucet::with_info) or
/// [`NetworkFungibleFaucet::with_info`](super::NetworkFungibleFaucet::with_info).
#[derive(Debug, Clone)]
pub struct FungibleTokenMetadata {
    token_supply: Felt,
    max_supply: Felt,
    decimals: u8,
    symbol: TokenSymbol,
    name: TokenName,
    description: Option<Description>,
    logo_uri: Option<LogoURI>,
    external_link: Option<ExternalLink>,
}

impl FungibleTokenMetadata {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of decimals supported.
    pub const MAX_DECIMALS: u8 = 12;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`FungibleTokenMetadata`] with the specified metadata and zero token supply.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The decimals parameter exceeds [`Self::MAX_DECIMALS`].
    /// - The max supply parameter exceeds [`FungibleAsset::MAX_AMOUNT`].
    pub fn new(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
        name: TokenName,
        description: Option<Description>,
        logo_uri: Option<LogoURI>,
        external_link: Option<ExternalLink>,
    ) -> Result<Self, FungibleFaucetError> {
        Self::with_supply(
            symbol,
            decimals,
            max_supply,
            Felt::ZERO,
            name,
            description,
            logo_uri,
            external_link,
        )
    }

    /// Creates a new [`FungibleTokenMetadata`] with the specified metadata and token supply.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The decimals parameter exceeds [`Self::MAX_DECIMALS`].
    /// - The max supply parameter exceeds [`FungibleAsset::MAX_AMOUNT`].
    /// - The token supply exceeds the max supply.
    pub fn with_supply(
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

        Ok(Self {
            token_supply,
            max_supply,
            decimals,
            symbol,
            name,
            description,
            logo_uri,
            external_link,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the token metadata is stored.
    /// Returns the storage slot name for token metadata (canonical slot shared with metadata
    /// module).
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
    pub fn symbol(&self) -> TokenSymbol {
        self.symbol
    }

    /// Returns the token name (for Info component when building an account).
    pub fn name(&self) -> &TokenName {
        &self.name
    }

    /// Returns the optional description (for Info component when building an account).
    pub fn description(&self) -> Option<&Description> {
        self.description.as_ref()
    }

    /// Returns the optional logo URI (for Info component when building an account).
    pub fn logo_uri(&self) -> Option<&LogoURI> {
        self.logo_uri.as_ref()
    }

    /// Returns the optional external link (for Info component when building an account).
    pub fn external_link(&self) -> Option<&ExternalLink> {
        self.external_link.as_ref()
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
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl TryFrom<Word> for FungibleTokenMetadata {
    type Error = FungibleFaucetError;

    /// Parses token metadata from a Word.
    ///
    /// The Word is expected to be in the format: `[token_supply, max_supply, decimals, symbol]`.
    ///
    /// **Note:** The name is set to an empty string and optional fields (description,
    /// logo_uri, external_link) are `None`, because these are stored in separate
    /// storage slots (via [`TokenMetadata`](crate::account::metadata::TokenMetadata)),
    /// not in the metadata Word itself.
    fn try_from(word: Word) -> Result<Self, Self::Error> {
        let [token_supply, max_supply, decimals, token_symbol] = *word;

        let symbol =
            TokenSymbol::try_from(token_symbol).map_err(FungibleFaucetError::InvalidTokenSymbol)?;

        let decimals = decimals.as_canonical_u64().try_into().map_err(|_| {
            FungibleFaucetError::TooManyDecimals {
                actual: decimals.as_canonical_u64(),
                max: Self::MAX_DECIMALS,
            }
        })?;

        let name = TokenName::new("").expect("empty string should be valid");
        Self::with_supply(symbol, decimals, max_supply, token_supply, name, None, None, None)
    }
}

impl From<FungibleTokenMetadata> for Word {
    fn from(metadata: FungibleTokenMetadata) -> Self {
        Word::new([
            metadata.token_supply,
            metadata.max_supply,
            Felt::from(metadata.decimals),
            metadata.symbol.into(),
        ])
    }
}

impl From<FungibleTokenMetadata> for StorageSlot {
    fn from(metadata: FungibleTokenMetadata) -> Self {
        StorageSlot::with_value(FungibleTokenMetadata::metadata_slot().clone(), metadata.into())
    }
}

impl TryFrom<&StorageSlot> for FungibleTokenMetadata {
    type Error = FungibleFaucetError;

    /// Tries to create [`FungibleTokenMetadata`] from a storage slot.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The slot name does not match the expected metadata slot name.
    /// - The slot value cannot be parsed as valid token metadata.
    fn try_from(slot: &StorageSlot) -> Result<Self, Self::Error> {
        if slot.name() != Self::metadata_slot() {
            return Err(FungibleFaucetError::SlotNameMismatch {
                expected: Self::metadata_slot().clone(),
                actual: slot.name().clone(),
            });
        }
        FungibleTokenMetadata::try_from(slot.value())
    }
}

impl TryFrom<&AccountStorage> for FungibleTokenMetadata {
    type Error = FungibleFaucetError;

    /// Tries to create [`FungibleTokenMetadata`] from account storage.
    fn try_from(storage: &AccountStorage) -> Result<Self, Self::Error> {
        let metadata_word =
            storage.get_item(FungibleTokenMetadata::metadata_slot()).map_err(|err| {
                FungibleFaucetError::StorageLookupFailed {
                    slot_name: FungibleTokenMetadata::metadata_slot().clone(),
                    source: err,
                }
            })?;

        FungibleTokenMetadata::try_from(metadata_word)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::asset::TokenSymbol;
    use miden_protocol::{Felt, Word};

    use super::*;

    #[test]
    fn token_metadata_new() {
        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 8u8;
        let max_supply = Felt::new(1_000_000);
        let name = TokenName::new("TEST").unwrap();

        let metadata = FungibleTokenMetadata::new(
            symbol,
            decimals,
            max_supply,
            name.clone(),
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(metadata.symbol(), symbol);
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

        let metadata = FungibleTokenMetadata::with_supply(
            symbol,
            decimals,
            max_supply,
            token_supply,
            name,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(metadata.symbol(), symbol);
        assert_eq!(metadata.decimals(), decimals);
        assert_eq!(metadata.max_supply(), max_supply);
        assert_eq!(metadata.token_supply(), token_supply);
    }

    #[test]
    fn token_metadata_with_name_and_description() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(123);
        let name = TokenName::new("polygon").unwrap();
        let description = Description::new("A polygon token").unwrap();

        let metadata = FungibleTokenMetadata::new(
            symbol,
            decimals,
            max_supply,
            name.clone(),
            Some(description.clone()),
            None,
            None,
        )
        .unwrap();

        assert_eq!(metadata.symbol(), symbol);
        assert_eq!(metadata.name(), &name);
        assert_eq!(metadata.description(), Some(&description));
        let word: Word = metadata.into();
        let restored = FungibleTokenMetadata::try_from(word).unwrap();
        assert_eq!(restored.symbol(), symbol);
        assert!(restored.description().is_none());
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

        let result =
            FungibleTokenMetadata::new(symbol, decimals, max_supply, name, None, None, None);
        assert!(matches!(result, Err(FungibleFaucetError::TooManyDecimals { .. })));
    }

    #[test]
    fn token_metadata_max_supply_too_large() {
        use miden_protocol::asset::FungibleAsset;

        let symbol = TokenSymbol::new("TEST").unwrap();
        let decimals = 8u8;
        let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT + 1);
        let name = TokenName::new("TEST").unwrap();

        let result =
            FungibleTokenMetadata::new(symbol, decimals, max_supply, name, None, None, None);
        assert!(matches!(result, Err(FungibleFaucetError::MaxSupplyTooLarge { .. })));
    }

    #[test]
    fn token_metadata_to_word() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(123);
        let name = TokenName::new("POL").unwrap();

        let metadata =
            FungibleTokenMetadata::new(symbol, decimals, max_supply, name, None, None, None)
                .unwrap();
        let word: Word = metadata.into();

        assert_eq!(word[0], Felt::ZERO);
        assert_eq!(word[1], max_supply);
        assert_eq!(word[2], Felt::from(decimals));
        assert_eq!(word[3], Felt::from(symbol));
    }

    #[test]
    fn token_metadata_from_storage_slot() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(123);
        let name = TokenName::new("POL").unwrap();

        let original =
            FungibleTokenMetadata::new(symbol, decimals, max_supply, name, None, None, None)
                .unwrap();
        let slot: StorageSlot = original.into();

        let restored = FungibleTokenMetadata::try_from(&slot).unwrap();

        assert_eq!(restored.symbol(), symbol);
        assert_eq!(restored.decimals(), decimals);
        assert_eq!(restored.max_supply(), max_supply);
        assert_eq!(restored.token_supply(), Felt::ZERO);
    }

    #[test]
    fn token_metadata_roundtrip_with_supply() {
        let symbol = TokenSymbol::new("POL").unwrap();
        let decimals = 2u8;
        let max_supply = Felt::new(1000);
        let token_supply = Felt::new(500);
        let name = TokenName::new("POL").unwrap();

        let original = FungibleTokenMetadata::with_supply(
            symbol,
            decimals,
            max_supply,
            token_supply,
            name,
            None,
            None,
            None,
        )
        .unwrap();
        let word: Word = original.into();
        let restored = FungibleTokenMetadata::try_from(word).unwrap();

        assert_eq!(restored.symbol(), symbol);
        assert_eq!(restored.decimals(), decimals);
        assert_eq!(restored.max_supply(), max_supply);
        assert_eq!(restored.token_supply(), token_supply);
    }
}
