use alloc::boxed::Box;
use alloc::string::ToString;
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
///   [faucet_id_suffix (56 bits) | reserved (2 bits) | composition (2 bits) | version (4 bits)],
///   faucet_id_prefix (64 bits)
/// ]
/// ```
///
/// The version determines how the remainder of the asset is decoded and so it is placed at a
/// static offset so it can be read first independent of the version. Version 0 is invalid, which
/// guarantees that an empty word is not a valid asset ID.
///
/// Use [`AssetId::hash`] to produce the corresponding [`AssetIdHash`] that is used as
/// the key in the asset vault's underlying SMT. Hashing ensures a uniform distribution across
/// leaves regardless of how faucet IDs or asset classes are chosen.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AssetId {
    /// The asset class of the asset ID.
    asset_class: AssetClass,

    /// The ID of the faucet that issued the asset.
    faucet_id: AccountId,

    /// The composition of the asset.
    composition: AssetComposition,
}

impl AssetId {
    /// The serialized size of an [`AssetId`] with [`AssetComposition::Fungible`] in bytes.
    ///
    /// The asset class of a fungible asset is always empty and so it is not serialized.
    const FUNGIBLE_SERIALIZED_SIZE: usize =
        AssetComposition::SERIALIZED_SIZE + AccountId::SERIALIZED_SIZE;

    /// The serialized size of an [`AssetId`] with any other [`AssetComposition`] in bytes.
    const NON_FUNGIBLE_SERIALIZED_SIZE: usize =
        Self::FUNGIBLE_SERIALIZED_SIZE + AssetClass::SERIALIZED_SIZE;

    // BIT LAYOUT CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The metadata byte occupies the lower 8 bits of the third element of the asset ID word.
    pub(in crate::asset) const METADATA_BYTE_MASK: u8 = 0xff;

    /// Version 1 of the asset ID encoding.
    pub(in crate::asset) const VERSION_1: u8 = 1;

    /// Bits 0-3 of the metadata byte encode the version.
    pub(in crate::asset) const VERSION_MASK: u8 = 0b1111;

    /// Bits 4-5 of the metadata byte encode the [`AssetComposition`].
    pub(in crate::asset) const COMPOSITION_SHIFT: u8 = 4;

    /// Bits 6-7 of the metadata byte are reserved and must be zero.
    pub(in crate::asset) const METADATA_RESERVED_MASK: u8 = 0b1100_0000;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an [`AssetId`] from its parts with the given [`AssetComposition`].
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

    /// Constructs a fungible asset's ID from a faucet ID.
    pub fn new_fungible(faucet_id: AccountId) -> Self {
        Self::new(AssetClass::default(), faucet_id, AssetComposition::Fungible).expect(
            "passing AssetComposition::Fungible together with AssetClass::default should be valid",
        )
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the word representation of the asset ID.
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
        let metadata_byte = Self::encode_metadata(self.composition);
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

    /// Returns the [`AssetClass`] of the asset ID that distinguishes different assets issued by
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

    /// Returns the [`AssetComposition`] of the asset ID.
    pub fn composition(&self) -> AssetComposition {
        self.composition
    }

    /// Hashes this raw asset ID to produce the [`AssetIdHash`] used as the key in the asset
    /// vault's underlying SMT.
    pub fn hash(&self) -> AssetIdHash {
        AssetIdHash::from_raw(Hasher::hash_elements(self.to_word().as_elements()))
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Encodes the given composition into a metadata byte of the current version.
    pub(in crate::asset) fn encode_metadata(composition: AssetComposition) -> u8 {
        (composition.as_u8() << Self::COMPOSITION_SHIFT) | Self::VERSION_1
    }
}

// ASSET ID HASH
// ================================================================================================

/// A hashed [`AssetId`].
///
/// This is produced by hashing an [`AssetId`] and is used as the actual key in the
/// underlying SMT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, WordWrapper)]
pub struct AssetIdHash(Word);

impl AssetIdHash {
    /// Returns the leaf index in the SMT for this hashed key.
    pub fn to_leaf_index(&self) -> LeafIndex<SMT_DEPTH> {
        self.0.into()
    }
}

impl From<AssetIdHash> for Word {
    fn from(id_hash: AssetIdHash) -> Self {
        id_hash.0
    }
}

impl From<AssetId> for AssetIdHash {
    fn from(id: AssetId) -> Self {
        id.hash()
    }
}

// CONVERSIONS
// ================================================================================================

impl From<AssetId> for Word {
    fn from(asset_id: AssetId) -> Self {
        asset_id.to_word()
    }
}

impl Ord for AssetId {
    /// Implements comparison based on the [`Word`] representation.
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.to_word().cmp(&other.to_word())
    }
}

impl PartialOrd for AssetId {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<Word> for AssetId {
    type Error = AssetError;

    /// Attempts to convert the provided [`Word`] into an [`AssetId`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the version encoded in the metadata byte is unknown.
    /// - the metadata byte has reserved bits set.
    /// - the composition encoded in the metadata byte is invalid.
    /// - the asset class limbs are not zero when asset composition is
    ///   [`AssetComposition::Fungible`].
    fn try_from(id: Word) -> Result<Self, Self::Error> {
        let asset_class_suffix = id[0];
        let asset_class_prefix = id[1];
        let faucet_id_suffix_and_metadata = id[2];
        let faucet_id_prefix = id[3];

        let raw = faucet_id_suffix_and_metadata.as_canonical_u64();
        let metadata_byte = (raw & Self::METADATA_BYTE_MASK as u64) as u8;

        // The version defines how the rest of the metadata is decoded, so check it first.
        let version = metadata_byte & Self::VERSION_MASK;
        if version != Self::VERSION_1 {
            return Err(AssetError::UnknownAssetIdVersion(version));
        }

        // Make sure the reserved bits of the metadata are zero.
        if metadata_byte & Self::METADATA_RESERVED_MASK != 0 {
            return Err(AssetError::ReservedAssetMetadata(metadata_byte));
        }

        let composition = AssetComposition::try_from(metadata_byte >> Self::COMPOSITION_SHIFT)?;

        let faucet_id_suffix = Felt::try_from(raw & !(Self::METADATA_BYTE_MASK as u64))
            .expect("clearing lower bits should not produce an invalid felt");

        let asset_class = AssetClass::new(asset_class_suffix, asset_class_prefix);
        let faucet_id = AccountId::try_from_elements(faucet_id_suffix, faucet_id_prefix)
            .map_err(|err| AssetError::InvalidFaucetAccountId(Box::new(err)))?;

        Self::new(asset_class, faucet_id, composition)
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_word().to_hex())
    }
}

impl From<Asset> for AssetId {
    fn from(asset: Asset) -> Self {
        asset.id()
    }
}

impl From<FungibleAsset> for AssetId {
    fn from(fungible_asset: FungibleAsset) -> Self {
        fungible_asset.id()
    }
}

impl From<NonFungibleAsset> for AssetId {
    fn from(non_fungible_asset: NonFungibleAsset) -> Self {
        non_fungible_asset.id()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AssetId {
    /// Serializes the ID from its parts rather than from its [`Word`] representation. Because the
    /// asset class of a fungible asset is always empty, it is not written, saving
    /// [`AssetClass::SERIALIZED_SIZE`] bytes per fungible ID.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Lead with the asset composition byte.
        target.write(self.composition);
        target.write(self.faucet_id);

        if !self.composition.is_fungible() {
            target.write(self.asset_class);
        }
    }

    fn get_size_hint(&self) -> usize {
        if self.composition.is_fungible() {
            Self::FUNGIBLE_SERIALIZED_SIZE
        } else {
            Self::NON_FUNGIBLE_SERIALIZED_SIZE
        }
    }
}

impl Deserializable for AssetId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let composition: AssetComposition = source.read()?;
        let faucet_id: AccountId = source.read()?;
        let asset_class = if composition.is_fungible() {
            AssetClass::default()
        } else {
            source.read()?
        };

        Self::new(asset_class, faucet_id, composition)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::AssetComposition;
    use crate::asset::tests::{asset_metadata, set_asset_metadata};
    use crate::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    };

    #[test]
    fn asset_id_word_roundtrip() -> anyhow::Result<()> {
        let fungible_faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
        let nonfungible_faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET)?;

        // Fungible: asset_class must be zero.
        let id = AssetId::new(AssetClass::default(), fungible_faucet, AssetComposition::Fungible)?;
        assert_eq!(id.composition(), AssetComposition::Fungible);
        let roundtripped = AssetId::try_from(id.to_word())?;
        assert_eq!(id, roundtripped);
        assert_eq!(id, AssetId::read_from_bytes(&id.to_bytes())?);
        assert_eq!(id.to_bytes().len(), AssetId::FUNGIBLE_SERIALIZED_SIZE);
        assert_eq!(id.to_bytes().len(), id.get_size_hint());

        // Non-fungible: asset_class can be non-zero.
        let id = AssetId::new(
            AssetClass::new(Felt::from(42u32), Felt::from(99u32)),
            nonfungible_faucet,
            AssetComposition::None,
        )?;
        assert_eq!(id.composition(), AssetComposition::None);
        let roundtripped = AssetId::try_from(id.to_word())?;
        assert_eq!(id, roundtripped);
        assert_eq!(id, AssetId::read_from_bytes(&id.to_bytes())?);
        assert_eq!(id.to_bytes().len(), AssetId::NON_FUNGIBLE_SERIALIZED_SIZE);
        assert_eq!(id.to_bytes().len(), id.get_size_hint());

        Ok(())
    }

    /// Version 0 is never valid, so the all-zero word cannot decode into an asset ID.
    #[rstest::rstest]
    #[case::version_zero(0, AssetError::UnknownAssetIdVersion(0))]
    #[case::unknown_version(AssetId::VERSION_1 + 1, AssetError::UnknownAssetIdVersion(2))]
    #[case::reserved_bits_set(
        AssetId::encode_metadata(AssetComposition::Fungible) | AssetId::METADATA_RESERVED_MASK,
        AssetError::ReservedAssetMetadata(0b1101_0001)
    )]
    // Composition value 3 is the unused bit pattern within the 2-bit field.
    #[case::unknown_composition(
        0b0011_0000 | AssetId::VERSION_1,
        AssetError::UnknownAssetComposition(0b11)
    )]
    fn decoding_word_with_invalid_metadata_fails(
        #[case] metadata: u8,
        #[case] expected_err: AssetError,
    ) -> anyhow::Result<()> {
        let word = set_asset_metadata(FungibleAsset::mock(42).id(), metadata);

        let err = AssetId::try_from(word).unwrap_err();
        assert_eq!(err.to_string(), expected_err.to_string());

        Ok(())
    }

    #[test]
    fn metadata_encodes_version_and_composition() -> anyhow::Result<()> {
        let fungible =
            AssetId::new_fungible(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?);
        assert_eq!(asset_metadata(fungible), 0b0001_0001);

        let non_fungible = AssetId::new(
            AssetClass::new(Felt::from(42u32), Felt::from(99u32)),
            AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET)?,
            AssetComposition::None,
        )?;
        assert_eq!(asset_metadata(non_fungible), 0b0000_0001);

        Ok(())
    }
}
