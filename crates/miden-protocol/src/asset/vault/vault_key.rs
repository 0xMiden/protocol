use alloc::boxed::Box;
use alloc::string::ToString;
use core::fmt;

use miden_crypto::merkle::smt::LeafIndex;

use crate::account::AccountId;
use crate::account::AccountType::{self};
use crate::asset::vault::AssetId;
use crate::asset::{Asset, AssetCallbackFlag, AssetComposition, FungibleAsset, NonFungibleAsset};
use crate::crypto::merkle::smt::SMT_DEPTH;
use crate::errors::AssetError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Word};

/// The unique identifier of an [`Asset`] in the [`AssetVault`](crate::asset::AssetVault).
///
/// Its [`Word`] layout is:
/// ```text
/// [
///   asset_id_suffix (64 bits),
///   asset_id_prefix (64 bits),
///   [faucet_id_suffix (56 bits) | reserved (5 bits) | callback_flag (1 bit) | composition (2 bits)],
///   faucet_id_prefix (64 bits)
/// ]
/// ```
///
/// The composition is the discriminator between assets and so it is placed at a static offset much
/// like the version in an account ID. This makes it slightly easier to change the asset metadata in
/// the future without affecting identification of previous assets.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AssetVaultKey {
    /// The asset ID of the vault key.
    asset_id: AssetId,

    /// The ID of the faucet that issued the asset.
    faucet_id: AccountId,

    /// The composition of the asset.
    composition: AssetComposition,

    /// Determines whether callbacks are enabled.
    callback_flag: AssetCallbackFlag,
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

    /// Bit 2 of the metadata byte encodes the [`AssetCallbackFlag`].
    pub(in crate::asset) const CALLBACK_FLAG_MASK: u8 = 0b1 << Self::CALLBACK_FLAG_SHIFT;
    pub(in crate::asset) const CALLBACK_FLAG_SHIFT: u8 = 2;

    /// Bits 3-7 of the metadata byte are reserved and must be zero.
    pub(in crate::asset) const RESERVED_BITS_MASK: u8 = 0b1111_1000;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an [`AssetVaultKey`] for a native asset with callbacks disabled.
    ///
    /// The [`AssetComposition`] is inferred from the faucet's account type.
    ///
    /// # Errors
    ///
    /// See [`Self::new`] for the error conditions.
    pub fn new_native(
        asset_id: AssetId,
        faucet_id: AccountId,
        composition: AssetComposition,
    ) -> Result<Self, AssetError> {
        Self::new(asset_id, faucet_id, composition, AssetCallbackFlag::Disabled)
    }

    /// Creates an [`AssetVaultKey`] from its parts with the given [`AssetComposition`] and
    /// [`AssetCallbackFlag`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided ID is not of type
    ///   [`AccountType::FungibleFaucet`](crate::account::AccountType::FungibleFaucet) or
    ///   [`AccountType::NonFungibleFaucet`](crate::account::AccountType::NonFungibleFaucet).
    /// - the asset ID limbs are not zero when `composition` is [`AssetComposition::Fungible`].
    /// - the composition is inconsistent with the faucet's account type (except for
    ///   [`AssetComposition::Custom`], which is allowed for either faucet type).
    pub fn new(
        asset_id: AssetId,
        faucet_id: AccountId,
        composition: AssetComposition,
        callback_flag: AssetCallbackFlag,
    ) -> Result<Self, AssetError> {
        if !faucet_id.is_faucet() {
            return Err(AssetError::InvalidFaucetAccountId(Box::from(format!(
                "expected account ID of type faucet, found account type {}",
                faucet_id.account_type()
            ))));
        }

        // For now, reject custom composition.
        if composition.is_custom() {
            return Err(AssetError::UnsupportedAssetComposition(AssetComposition::Custom));
        }

        // TODO(asset_composition): This will go away once we remove account type.
        let expected = match faucet_id.account_type() {
            AccountType::FungibleFaucet => AssetComposition::Fungible,
            AccountType::NonFungibleFaucet => AssetComposition::None,
            _ => unreachable!("checked above that the account is a faucet"),
        };
        if composition != expected && !composition.is_custom() {
            return Err(AssetError::AssetCompositionMismatch {
                faucet_id,
                expected,
                actual: composition,
            });
        }

        if composition.is_fungible() && !asset_id.is_empty() {
            return Err(AssetError::FungibleAssetIdMustBeZero(asset_id));
        }

        Ok(Self {
            asset_id,
            faucet_id,
            composition,
            callback_flag,
        })
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
        let metadata_byte =
            self.composition.as_u8() | (self.callback_flag.as_u8() << Self::CALLBACK_FLAG_SHIFT);
        let faucet_id_suffix_and_metadata = faucet_suffix | metadata_byte as u64;
        let faucet_id_suffix_and_metadata = Felt::try_from(faucet_id_suffix_and_metadata)
            .expect("highest bit should still be zero resulting in a valid felt");

        Word::new([
            self.asset_id.suffix(),
            self.asset_id.prefix(),
            faucet_id_suffix_and_metadata,
            self.faucet_id.prefix().as_felt(),
        ])
    }

    /// Returns the [`AssetId`] of the vault key that distinguishes different assets issued by the
    /// same faucet.
    pub fn asset_id(&self) -> AssetId {
        self.asset_id
    }

    /// Returns the [`AccountId`] of the faucet that issued the asset.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// Returns the [`AssetCallbackFlag`] flag of the vault key.
    pub fn callback_flag(&self) -> AssetCallbackFlag {
        self.callback_flag
    }

    /// Returns the [`AssetComposition`] of the vault key.
    pub fn composition(&self) -> AssetComposition {
        self.composition
    }

    /// Constructs a fungible asset's key from a faucet ID.
    ///
    /// Returns `None` if the provided ID is not of type
    /// [`AccountType::FungibleFaucet`](crate::account::AccountType::FungibleFaucet)
    pub fn new_fungible(faucet_id: AccountId) -> Option<Self> {
        if matches!(faucet_id.account_type(), AccountType::FungibleFaucet) {
            let asset_id = AssetId::new(Felt::ZERO, Felt::ZERO);
            Some(
                Self::new_native(asset_id, faucet_id, AssetComposition::Fungible)
                    .expect("we should have account type fungible faucet"),
            )
        } else {
            None
        }
    }

    /// Returns the leaf index of a vault key.
    pub fn to_leaf_index(&self) -> LeafIndex<SMT_DEPTH> {
        LeafIndex::<SMT_DEPTH>::from(self.to_word())
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
    /// - the faucet ID in the key is invalid or not of a faucet type.
    /// - the asset ID limbs are not zero when `faucet_id` is of type
    ///   [`AccountType::FungibleFaucet`](crate::account::AccountType::FungibleFaucet).
    /// - the metadata byte has reserved bits set.
    /// - the composition encoded in the metadata byte is invalid.
    /// - the composition is inconsistent with the faucet's account type.
    fn try_from(key: Word) -> Result<Self, Self::Error> {
        let asset_id_suffix = key[0];
        let asset_id_prefix = key[1];
        let faucet_id_suffix_and_metadata = key[2];
        let faucet_id_prefix = key[3];

        let raw = faucet_id_suffix_and_metadata.as_canonical_u64();
        let metadata_byte = (raw & Self::METADATA_BYTE_MASK as u64) as u8;

        // Make sure the reserved bits of the metadata are zero.
        if metadata_byte & Self::RESERVED_BITS_MASK != 0 {
            return Err(AssetError::ReservedAssetMetadata(metadata_byte));
        }

        let callback_flag = AssetCallbackFlag::try_from(
            (metadata_byte & Self::CALLBACK_FLAG_MASK) >> Self::CALLBACK_FLAG_SHIFT,
        )?;
        let composition = AssetComposition::try_from(metadata_byte & Self::COMPOSITION_MASK)?;

        let faucet_id_suffix = Felt::try_from(raw & !(Self::METADATA_BYTE_MASK as u64))
            .expect("clearing lower bits should not produce an invalid felt");

        let asset_id = AssetId::new(asset_id_suffix, asset_id_prefix);
        let faucet_id = AccountId::try_from_elements(faucet_id_suffix, faucet_id_prefix)
            .map_err(|err| AssetError::InvalidFaucetAccountId(Box::new(err)))?;

        Self::new(asset_id, faucet_id, composition, callback_flag)
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
    use rstest::rstest;

    use super::*;
    use crate::asset::tests::{asset_metadata, set_asset_metadata};
    use crate::asset::{AssetCallbackFlag, AssetComposition};
    use crate::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    };

    #[rstest]
    fn asset_vault_key_word_roundtrip(
        #[values(AssetCallbackFlag::Disabled, AssetCallbackFlag::Enabled)]
        callback_flag: AssetCallbackFlag,
    ) -> anyhow::Result<()> {
        let fungible_faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
        let nonfungible_faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET)?;

        // Fungible: asset_id must be zero.
        let key = AssetVaultKey::new(
            AssetId::default(),
            fungible_faucet,
            AssetComposition::Fungible,
            callback_flag,
        )?;
        assert_eq!(key.composition(), AssetComposition::Fungible);
        let roundtripped = AssetVaultKey::try_from(key.to_word())?;
        assert_eq!(key, roundtripped);
        assert_eq!(key, AssetVaultKey::read_from_bytes(&key.to_bytes())?);

        // Non-fungible: asset_id can be non-zero.
        let key = AssetVaultKey::new(
            AssetId::new(Felt::from(42u32), Felt::from(99u32)),
            nonfungible_faucet,
            AssetComposition::None,
            callback_flag,
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
        let word = set_asset_metadata(key, valid_metadata | AssetVaultKey::RESERVED_BITS_MASK);

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
