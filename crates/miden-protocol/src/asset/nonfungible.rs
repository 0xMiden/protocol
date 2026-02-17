use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;

use super::vault::AssetVaultKey;
use super::{AccountIdPrefix, AccountType, Asset, AssetError, Felt, Hasher, Word};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use crate::{FieldElement, WORD_SIZE};

/// Position of the faucet_id inside the [`NonFungibleAsset`] word having fields in BigEndian.
const FAUCET_ID_POS_BE: usize = 3;

// NON-FUNGIBLE ASSET
// ================================================================================================

/// A commitment to a non-fungible asset.
///
/// The commitment is constructed as follows:
///
/// - Hash the asset data producing `[hash0, hash1, hash2, hash3]`.
/// - Replace the value of `hash3` with the prefix of the faucet id (`faucet_id_prefix`) producing
///   `[hash0, hash1, hash2, faucet_id_prefix]`.
/// - This layout ensures that fungible and non-fungible assets are distinguishable by interpreting
///   the 3rd element of an asset as an [`AccountIdPrefix`] and checking its type.
///
/// [`NonFungibleAsset`] itself does not contain the actual asset data. The container for this data
/// is [`NonFungibleAssetDetails`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NonFungibleAsset(Word);

impl PartialOrd for NonFungibleAsset {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NonFungibleAsset {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl NonFungibleAsset {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The serialized size of a [`NonFungibleAsset`] in bytes.
    ///
    /// Currently represented as a word.
    pub const SERIALIZED_SIZE: usize = Felt::ELEMENT_BYTES * WORD_SIZE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a non-fungible asset created from the specified asset details.
    ///
    /// # Errors
    /// Returns an error if the provided faucet ID is not for a non-fungible asset faucet.
    pub fn new(details: &NonFungibleAssetDetails) -> Result<Self, AssetError> {
        let data_hash = Hasher::hash(details.asset_data());
        Self::from_parts(details.faucet_id(), data_hash)
    }

    /// Return a non-fungible asset created from the specified faucet and using the provided
    /// hash of the asset's data.
    ///
    /// Hash of the asset's data is expected to be computed from the binary representation of the
    /// asset's data.
    ///
    /// # Errors
    /// Returns an error if the provided faucet ID is not for a non-fungible asset faucet.
    pub fn from_parts(faucet_id: AccountIdPrefix, mut data_hash: Word) -> Result<Self, AssetError> {
        if !matches!(faucet_id.account_type(), AccountType::NonFungibleFaucet) {
            return Err(AssetError::NonFungibleFaucetIdTypeMismatch(faucet_id));
        }

        data_hash[FAUCET_ID_POS_BE] = Felt::from(faucet_id);

        Ok(Self(data_hash))
    }

    /// Creates a new [NonFungibleAsset] without checking its validity.
    ///
    /// # Safety
    /// This function requires that the provided value is a valid word encoding of a
    /// [NonFungibleAsset].
    pub unsafe fn new_unchecked(value: Word) -> NonFungibleAsset {
        NonFungibleAsset(value)
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the vault key of the [`NonFungibleAsset`].
    ///
    /// This is the same as the asset with the following modifications, in this order:
    /// - Swaps the faucet ID at index 0 and `hash0` at index 3.
    /// - Sets the fungible bit for `hash0` to `0`.
    ///
    /// # Rationale
    ///
    /// This means `hash0` will be used as the leaf index in the asset SMT which ensures that a
    /// non-fungible faucet's assets generally end up in different leaves as the key is not based on
    /// the faucet ID.
    ///
    /// It also ensures that there is never any collision in the leaf index between a non-fungible
    /// asset and a fungible asset, as the former's vault key always has the fungible bit set to `0`
    /// and the latter's vault key always has the bit set to `1`.
    pub fn vault_key(&self) -> AssetVaultKey {
        let mut vault_key = self.0;

        // Swap prefix of faucet ID with hash0.
        vault_key.swap(0, FAUCET_ID_POS_BE);

        // Set the fungible bit to zero.
        vault_key[3] =
            AccountIdPrefix::clear_fungible_bit(self.faucet_id_prefix().version(), vault_key[3]);

        AssetVaultKey::new_unchecked(vault_key)
    }

    /// Return ID prefix of the faucet which issued this asset.
    pub fn faucet_id_prefix(&self) -> AccountIdPrefix {
        AccountIdPrefix::new_unchecked(self.0[FAUCET_ID_POS_BE])
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Validates this non-fungible asset.
    /// # Errors
    /// Returns an error if:
    /// - The faucet_id is not a valid non-fungible faucet ID.
    /// - The most significant bit of the asset is not ZERO.
    fn validate(&self) -> Result<(), AssetError> {
        let faucet_id = AccountIdPrefix::try_from(self.0[FAUCET_ID_POS_BE])
            .map_err(|err| AssetError::InvalidFaucetAccountId(Box::new(err)))?;

        let account_type = faucet_id.account_type();
        if !matches!(account_type, AccountType::NonFungibleFaucet) {
            return Err(AssetError::NonFungibleFaucetIdTypeMismatch(faucet_id));
        }

        Ok(())
    }
}

impl From<NonFungibleAsset> for Word {
    fn from(asset: NonFungibleAsset) -> Self {
        asset.0
    }
}

impl From<NonFungibleAsset> for Asset {
    fn from(asset: NonFungibleAsset) -> Self {
        Asset::NonFungible(asset)
    }
}

impl TryFrom<Word> for NonFungibleAsset {
    type Error = AssetError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        let asset = Self(value);
        asset.validate()?;
        Ok(asset)
    }
}

impl fmt::Display for NonFungibleAsset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NonFungibleAsset {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // All assets should serialize their faucet ID at the first position to allow them to be
        // easily distinguishable during deserialization.
        target.write(self.faucet_id_prefix());
        target.write(self.0[2]);
        target.write(self.0[1]);
        target.write(self.0[0]);
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for NonFungibleAsset {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let faucet_id_prefix: AccountIdPrefix = source.read()?;

        Self::deserialize_with_faucet_id_prefix(faucet_id_prefix, source)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

impl NonFungibleAsset {
    /// Deserializes a [`NonFungibleAsset`] from an [`AccountIdPrefix`] and the remaining data from
    /// the given `source`.
    pub(super) fn deserialize_with_faucet_id_prefix<R: ByteReader>(
        faucet_id_prefix: AccountIdPrefix,
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let hash_2: Felt = source.read()?;
        let hash_1: Felt = source.read()?;
        let hash_0: Felt = source.read()?;

        // The last felt in the data_hash will be replaced by the faucet id, so we can set it to
        // zero here.
        NonFungibleAsset::from_parts(
            faucet_id_prefix,
            Word::from([hash_0, hash_1, hash_2, Felt::ZERO]),
        )
        .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// NON-FUNGIBLE ASSET DETAILS
// ================================================================================================

/// Details about a non-fungible asset.
///
/// Unlike [NonFungibleAsset] struct, this struct contains full details of a non-fungible asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonFungibleAssetDetails {
    faucet_id: AccountIdPrefix,
    asset_data: Vec<u8>,
}

impl NonFungibleAssetDetails {
    /// Returns asset details instantiated from the specified faucet ID and asset data.
    ///
    /// # Errors
    /// Returns an error if the provided faucet ID is not for a non-fungible asset faucet.
    pub fn new(faucet_id: AccountIdPrefix, asset_data: Vec<u8>) -> Result<Self, AssetError> {
        if !matches!(faucet_id.account_type(), AccountType::NonFungibleFaucet) {
            return Err(AssetError::NonFungibleFaucetIdTypeMismatch(faucet_id));
        }

        Ok(Self { faucet_id, asset_data })
    }

    /// Returns ID of the faucet which issued this asset.
    pub fn faucet_id(&self) -> AccountIdPrefix {
        self.faucet_id
    }

    /// Returns asset data in binary format.
    pub fn asset_data(&self) -> &[u8] {
        &self.asset_data
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::account::AccountId;
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
    };

    #[test]
    fn test_non_fungible_asset_serde() {
        for non_fungible_account_id in [
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
        ] {
            let account_id = AccountId::try_from(non_fungible_account_id).unwrap();
            let details = NonFungibleAssetDetails::new(account_id.prefix(), vec![1, 2, 3]).unwrap();
            let non_fungible_asset = NonFungibleAsset::new(&details).unwrap();
            assert_eq!(
                non_fungible_asset,
                NonFungibleAsset::read_from_bytes(&non_fungible_asset.to_bytes()).unwrap()
            );
        }

        let account = AccountId::try_from(ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET).unwrap();
        let details = NonFungibleAssetDetails::new(account.prefix(), vec![4, 5, 6, 7]).unwrap();
        let asset = NonFungibleAsset::new(&details).unwrap();
        let mut asset_bytes = asset.to_bytes();

        let fungible_faucet_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET).unwrap();

        // Set invalid Faucet ID Prefix.
        asset_bytes[0..8].copy_from_slice(&fungible_faucet_id.prefix().to_bytes());

        let err = NonFungibleAsset::read_from_bytes(&asset_bytes).unwrap_err();
        assert_matches!(err, DeserializationError::InvalidValue(msg) if msg.contains("must be of type NonFungibleFaucet"));
    }
}
