use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::fmt;

use miden_crypto::merkle::smt::LeafIndex;
use miden_crypto_derive::WordWrapper;

use crate::account::{AccountId, AssetCallbackFlag};
use crate::asset::vault::AssetClass;
use crate::asset::{Asset, AssetComposition, FungibleAsset, NonFungibleAsset};
use crate::crypto::merkle::smt::SMT_DEPTH;
use crate::errors::AssetError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word};

/// The unique identifier of an [`Asset`] in the [`AssetVault`](crate::asset::AssetVault).
///
/// Its [`Word`] layout is:
/// ```text
/// [
///   asset_class_suffix (64 bits),
///   asset_class_prefix (64 bits),
///   [faucet_id_suffix (56 bits) | reserved (6 bits) | composition (2 bits)],
///   faucet_id_prefix (64 bits)
/// ]
/// ```
///
/// The composition is the discriminator between assets and so it is placed at a static offset much
/// like the version in an account ID. This makes it slightly easier to change the asset metadata in
/// the future without affecting identification of previous assets.
///
/// Use [`AssetVaultKey::hash`] to produce the corresponding [`AssetVaultKeyHash`] that is used as
/// the key in the asset vault's underlying SMT. Hashing ensures a uniform distribution across
/// leaves regardless of how faucet IDs or asset classes are chosen.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AssetVaultKey {
    /// The asset class of the vault key.
    asset_class: AssetClass,

    /// The ID of the faucet that issued the asset.
    faucet_id: AccountId,

    /// The composition of the asset.
    composition: AssetComposition,
}

impl AssetVaultKey {
    /// The serialized size of an [`AssetVaultKey`] in bytes.
    ///
    /// Serialized as its [`Word`] representation (4 field elements).
    pub const SERIALIZED_SIZE: usize = Word::SERIALIZED_SIZE;

    // BIT LAYOUT CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The metadata byte occupies the lower 8 bits of the third element of the key word.
    pub(in crate::asset) const METADATA_BYTE_MASK: u8 = 0xff;

    /// Bits 0-1 of the metadata byte encode the [`AssetComposition`]. The composition occupies
    /// the lowest bits so its position remains stable as new metadata bits are added, since it
    /// identifies the asset's type.
    pub(in crate::asset) const COMPOSITION_MASK: u8 = 0b11;

    /// Bits 2-7 of the metadata byte are reserved and must be zero.
    pub(in crate::asset) const METADATA_RESERVED_MASK: u8 = 0b1111_1100;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an [`AssetVaultKey`] from its parts with the given [`AssetComposition`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the asset class limbs are not zero when `composition` is [`AssetComposition::Fungible`].
    /// - the composition is [`AssetComposition::Custom`], which is disallowed until its support is
    ///   enabled in the tx kernel.
    pub fn new(
        asset_class: AssetClass,
        faucet_id: AccountId,
        composition: AssetComposition,
    ) -> Result<Self, AssetError> {
        // For now, reject custom composition.
        if composition.is_custom() {
            return Err(AssetError::UnsupportedAssetComposition(AssetComposition::Custom));
        }

        if composition.is_fungible() && !asset_class.is_empty() {
            return Err(AssetError::FungibleAssetClassMustBeZero(asset_class));
        }

        Ok(Self { asset_class, faucet_id, composition })
    }

    /// Constructs a fungible asset's key from a faucet ID.
    pub fn new_fungible(faucet_id: AccountId) -> Self {
        Self::new(AssetClass::default(), faucet_id, AssetComposition::Fungible).expect(
            "passing AssetComposition::Fungible together with AssetClass::default should be valid",
        )
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the word representation of the vault key.
    ///
    /// See the type-level documentation for details.
    pub fn to_word(&self) -> Word {
        let faucet_suffix = self.faucet_id.suffix().as_canonical_u64();
        // The lower 8 bits of the faucet suffix are guaranteed to be zero and so it is used to
        // encode the asset metadata.
        debug_assert!(
            faucet_suffix & Self::METADATA_BYTE_MASK as u64 == 0,
            "lower 8 bits of faucet suffix must be zero",
        );
        let metadata_byte = self.composition.as_u8();
        let faucet_id_suffix_and_metadata = faucet_suffix | metadata_byte as u64;
        let faucet_id_suffix_and_metadata = Felt::try_from(faucet_id_suffix_and_metadata)
            .expect("highest bit should still be zero resulting in a valid felt");

        Word::new([
            self.asset_class.suffix(),
            self.asset_class.prefix(),
            faucet_id_suffix_and_metadata,
            self.faucet_id.prefix().as_felt(),
        ])
    }

    /// Returns the [`AssetClass`] of the vault key that distinguishes different assets issued by
    /// the same faucet.
    pub fn asset_class(&self) -> AssetClass {
        self.asset_class
    }

    /// Returns the [`AccountId`] of the faucet that issued the asset.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// Returns the [`AssetCallbackFlag`] of the faucet that issued the asset.
    pub fn callback_flag(&self) -> AssetCallbackFlag {
        self.faucet_id.asset_callback_flag()
    }

    /// Returns the [`AssetComposition`] of the vault key.
    pub fn composition(&self) -> AssetComposition {
        self.composition
    }

    /// Hashes this raw vault key to produce the [`AssetVaultKeyHash`] used as the key in the asset
    /// vault's underlying SMT.
    pub fn hash(&self) -> AssetVaultKeyHash {
        AssetVaultKeyHash::from_raw(Hasher::hash_elements(self.to_word().as_elements()))
    }
}

// ASSET VAULT KEY HASH
// ================================================================================================

/// A hashed [`AssetVaultKey`].
///
/// This is produced by hashing an [`AssetVaultKey`] and is used as the actual key in the
/// underlying SMT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, WordWrapper)]
pub struct AssetVaultKeyHash(Word);

impl AssetVaultKeyHash {
    /// Returns the leaf index in the SMT for this hashed key.
    pub fn to_leaf_index(&self) -> LeafIndex<SMT_DEPTH> {
        self.0.into()
    }
}

impl From<AssetVaultKeyHash> for Word {
    fn from(key: AssetVaultKeyHash) -> Self {
        key.0
    }
}

impl From<AssetVaultKey> for AssetVaultKeyHash {
    fn from(key: AssetVaultKey) -> Self {
        key.hash()
    }
}

// CONVERSIONS
// ================================================================================================

impl From<AssetVaultKey> for Word {
    fn from(vault_key: AssetVaultKey) -> Self {
        vault_key.to_word()
    }
}

impl Ord for AssetVaultKey {
    /// Implements comparison based on the [`Word`] representation.
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.to_word().cmp(&other.to_word())
    }
}

impl PartialOrd for AssetVaultKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<Word> for AssetVaultKey {
    type Error = AssetError;

    /// Attempts to convert the provided [`Word`] into an [`AssetVaultKey`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the asset class limbs are not zero when asset composition is
    ///   [`AssetComposition::Fungible`].
    /// - the metadata byte has reserved bits set.
    /// - the composition encoded in the metadata byte is invalid.
    fn try_from(key: Word) -> Result<Self, Self::Error> {
        let asset_class_suffix = key[0];
        let asset_class_prefix = key[1];
        let faucet_id_suffix_and_metadata = key[2];
        let faucet_id_prefix = key[3];

        let raw = faucet_id_suffix_and_metadata.as_canonical_u64();
        let metadata_byte = (raw & Self::METADATA_BYTE_MASK as u64) as u8;

        // Make sure the reserved bits of the metadata are zero.
        if metadata_byte & Self::METADATA_RESERVED_MASK != 0 {
            return Err(AssetError::ReservedAssetMetadata(metadata_byte));
        }

        let composition = AssetComposition::try_from(metadata_byte & Self::COMPOSITION_MASK)?;

        let faucet_id_suffix = Felt::try_from(raw & !(Self::METADATA_BYTE_MASK as u64))
            .expect("clearing lower bits should not produce an invalid felt");

        let asset_class = AssetClass::new(asset_class_suffix, asset_class_prefix);
        let faucet_id = AccountId::try_from_elements(faucet_id_suffix, faucet_id_prefix)
            .map_err(|err| AssetError::InvalidFaucetAccountId(Box::new(err)))?;

        Self::new(asset_class, faucet_id, composition)
    }
}

impl fmt::Display for AssetVaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_word().to_hex())
    }
}

impl From<Asset> for AssetVaultKey {
    fn from(asset: Asset) -> Self {
        asset.vault_key()
    }
}

impl From<FungibleAsset> for AssetVaultKey {
    fn from(fungible_asset: FungibleAsset) -> Self {
        fungible_asset.vault_key()
    }
}

impl From<NonFungibleAsset> for AssetVaultKey {
    fn from(non_fungible_asset: NonFungibleAsset) -> Self {
        non_fungible_asset.vault_key()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AssetVaultKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.to_word().write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for AssetVaultKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let word: Word = source.read()?;
        Self::try_from(word).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::asset::AssetComposition;
    use crate::asset::tests::{asset_metadata, set_asset_metadata};
    use crate::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    };

    #[test]
    fn asset_vault_key_word_roundtrip() -> anyhow::Result<()> {
        let fungible_faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
        let nonfungible_faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET)?;

        // Fungible: asset_class must be zero.
        let key =
            AssetVaultKey::new(AssetClass::default(), fungible_faucet, AssetComposition::Fungible)?;
        assert_eq!(key.composition(), AssetComposition::Fungible);
        let roundtripped = AssetVaultKey::try_from(key.to_word())?;
        assert_eq!(key, roundtripped);
        assert_eq!(key, AssetVaultKey::read_from_bytes(&key.to_bytes())?);

        // Non-fungible: asset_class can be non-zero.
        let key = AssetVaultKey::new(
            AssetClass::new(Felt::from(42u32), Felt::from(99u32)),
            nonfungible_faucet,
            AssetComposition::None,
        )?;
        assert_eq!(key.composition(), AssetComposition::None);
        let roundtripped = AssetVaultKey::try_from(key.to_word())?;
        assert_eq!(key, roundtripped);
        assert_eq!(key, AssetVaultKey::read_from_bytes(&key.to_bytes())?);

        Ok(())
    }

    #[test]
    fn decoding_word_with_reserved_bits_set_fails() -> anyhow::Result<()> {
        let key = FungibleAsset::mock(42).vault_key();
        let valid_metadata = asset_metadata(key);
        // Set the reserved bits so the reserved-bits check fires.
        let word = set_asset_metadata(key, valid_metadata | AssetVaultKey::METADATA_RESERVED_MASK);

        let err = AssetVaultKey::try_from(word).unwrap_err();
        assert_matches!(err, AssetError::ReservedAssetMetadata(_));

        Ok(())
    }

    #[test]
    fn decoding_word_with_invalid_composition_value_fails() -> anyhow::Result<()> {
        let key = FungibleAsset::mock(42).vault_key();
        // Set all composition bits — value 3 is the invalid bit pattern within the 2-bit field.
        let invalid_metadata = AssetVaultKey::COMPOSITION_MASK;
        let word = set_asset_metadata(key, invalid_metadata);

        let err = AssetVaultKey::try_from(word).unwrap_err();
        assert_matches!(err, AssetError::UnknownAssetComposition(_));

        Ok(())
    }
}
