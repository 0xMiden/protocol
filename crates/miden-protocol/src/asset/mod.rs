use super::account::AccountType;
use super::errors::{AssetError, TokenSymbolError};
use super::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use super::{Felt, Hasher, Word, ZERO};
use crate::account::AccountIdPrefix;

mod fungible;
use alloc::boxed::Box;

pub use fungible::FungibleAsset;

mod nonfungible;

pub use nonfungible::{NonFungibleAsset, NonFungibleAssetDetails};

mod token_symbol;
pub use token_symbol::TokenSymbol;

mod vault;
pub use vault::{AssetVault, AssetVaultKey, AssetWitness, PartialVault};

// ASSET
// ================================================================================================

/// A fungible or a non-fungible asset.
///
/// All assets are encoded using a single word (4 elements) such that it is easy to determine the
/// type of an asset both inside and outside Miden VM. Specifically:
///
/// Element 1 of the asset will be:
/// - ZERO for a fungible asset.
/// - non-ZERO for a non-fungible asset.
///
/// Element 3 of both asset types is an [`AccountIdPrefix`] or equivalently, the prefix of an
/// [`AccountId`](crate::account::AccountId), which can be used to distinguish assets
/// based on [`AccountIdPrefix::account_type`].
///
/// For element 3 of the vault keys of assets, the bit at index 5 (referred to as the
/// "fungible bit" will be):
/// - `1` for a fungible asset.
/// - `0` for a non-fungible asset.
///
/// The above properties guarantee that there can never be a collision between a fungible and a
/// non-fungible asset.
///
/// The methodology for constructing fungible and non-fungible assets is described below.
///
/// # Fungible assets
///
/// - A fungible asset's data layout is: `[amount, 0, faucet_id_suffix, faucet_id_prefix]`.
/// - A fungible asset's vault key layout is: `[0, 0, faucet_id_suffix, faucet_id_prefix]`.
///
/// The most significant elements of a fungible asset are set to the prefix (`faucet_id_prefix`) and
/// suffix (`faucet_id_suffix`) of the ID of the faucet which issues the asset. This guarantees the
/// properties described above (the fungible bit is `1`).
///
/// The least significant element is set to the amount of the asset. This amount cannot be greater
/// than [`FungibleAsset::MAX_AMOUNT`] and thus fits into a felt.
///
/// Elements 1 and 2 are set to ZERO.
///
/// It is impossible to find a collision between two fungible assets issued by different faucets as
/// the faucet_id is included in the description of the asset and this is guaranteed to be different
/// for each faucet as per the faucet creation logic.
///
/// # Non-fungible assets
///
/// - A non-fungible asset's data layout is: `[hash0, hash1, hash2, faucet_id_prefix]`.
/// - A non-fungible asset's vault key layout is: `[faucet_id_prefix, hash1, hash2, hash0']`, where
///   `hash0'` is equivalent to `hash0` with the fungible bit set to `0`. See
///   [`NonFungibleAsset::vault_key`] for more details.
///
/// The 4 elements of non-fungible assets are computed as follows:
/// - First the asset data is hashed. This compresses an asset of an arbitrary length to 4 field
///   elements: `[hash0, hash1, hash2, hash3]`.
/// - `hash3` is then replaced with the prefix of the faucet ID (`faucet_id_prefix`) which issues
///   the asset: `[hash0, hash1, hash2, faucet_id_prefix]`.
///
/// It is impossible to find a collision between two non-fungible assets issued by different faucets
/// as the faucet_id is included in the description of the non-fungible asset and this is guaranteed
/// to be different as per the faucet creation logic. Collision resistance for non-fungible assets
/// issued by the same faucet is ~2^95.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Asset {
    Fungible(FungibleAsset),
    NonFungible(NonFungibleAsset),
}

impl Asset {
    /// Creates a new [Asset] without checking its validity.
    pub(crate) fn new_unchecked(value: Word) -> Asset {
        if is_not_a_non_fungible_asset(value) {
            Asset::Fungible(FungibleAsset::new_unchecked(value))
        } else {
            Asset::NonFungible(unsafe { NonFungibleAsset::new_unchecked(value) })
        }
    }

    /// Returns true if this asset is the same as the specified asset.
    ///
    /// Two assets are defined to be the same if:
    /// - For fungible assets, if they were issued by the same faucet.
    /// - For non-fungible assets, if the assets are identical.
    pub fn is_same(&self, other: &Self) -> bool {
        use Asset::*;
        match (self, other) {
            (Fungible(l), Fungible(r)) => l.is_from_same_faucet(r),
            (NonFungible(l), NonFungible(r)) => l == r,
            _ => false,
        }
    }

    /// Returns true if this asset is a fungible asset.
    pub const fn is_fungible(&self) -> bool {
        matches!(self, Self::Fungible(_))
    }

    /// Returns true if this asset is a non fungible asset.
    pub const fn is_non_fungible(&self) -> bool {
        matches!(self, Self::NonFungible(_))
    }

    /// Returns the prefix of the faucet ID which issued this asset.
    ///
    /// To get the full [`AccountId`](crate::account::AccountId) of a fungible asset the asset
    /// must be matched on.
    pub fn faucet_id_prefix(&self) -> AccountIdPrefix {
        match self {
            Self::Fungible(asset) => asset.faucet_id_prefix(),
            Self::NonFungible(asset) => asset.faucet_id_prefix(),
        }
    }

    /// Returns the key which is used to store this asset in the account vault.
    pub fn vault_key(&self) -> AssetVaultKey {
        match self {
            Self::Fungible(asset) => asset.vault_key(),
            Self::NonFungible(asset) => asset.vault_key(),
        }
    }

    /// Returns the inner [`FungibleAsset`].
    ///
    /// # Panics
    ///
    /// Panics if the asset is non-fungible.
    pub fn unwrap_fungible(&self) -> FungibleAsset {
        match self {
            Asset::Fungible(asset) => *asset,
            Asset::NonFungible(_) => panic!("the asset is non-fungible"),
        }
    }

    /// Returns the inner [`NonFungibleAsset`].
    ///
    /// # Panics
    ///
    /// Panics if the asset is fungible.
    pub fn unwrap_non_fungible(&self) -> NonFungibleAsset {
        match self {
            Asset::Fungible(_) => panic!("the asset is fungible"),
            Asset::NonFungible(asset) => *asset,
        }
    }
}

impl From<Asset> for Word {
    fn from(asset: Asset) -> Self {
        match asset {
            Asset::Fungible(asset) => asset.into(),
            Asset::NonFungible(asset) => asset.into(),
        }
    }
}

impl From<&Asset> for Word {
    fn from(value: &Asset) -> Self {
        (*value).into()
    }
}

impl TryFrom<&Word> for Asset {
    type Error = AssetError;

    fn try_from(value: &Word) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<Word> for Asset {
    type Error = AssetError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        // Return an error if element 3 is not a valid account ID prefix, which cannot be checked by
        // is_not_a_non_fungible_asset.
        // Keep in mind serialized assets do _not_ carry the suffix required to reconstruct the full
        // account identifier.
        let prefix = AccountIdPrefix::try_from(value[3])
            .map_err(|err| AssetError::InvalidFaucetAccountId(Box::from(err)))?;
        match prefix.account_type() {
            AccountType::FungibleFaucet => FungibleAsset::try_from(value).map(Asset::from),
            AccountType::NonFungibleFaucet => NonFungibleAsset::try_from(value).map(Asset::from),
            _ => Err(AssetError::InvalidFaucetAccountIdPrefix(prefix)),
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Asset {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Asset::Fungible(fungible_asset) => fungible_asset.write_into(target),
            Asset::NonFungible(non_fungible_asset) => non_fungible_asset.write_into(target),
        }
    }

    fn get_size_hint(&self) -> usize {
        match self {
            Asset::Fungible(fungible_asset) => fungible_asset.get_size_hint(),
            Asset::NonFungible(non_fungible_asset) => non_fungible_asset.get_size_hint(),
        }
    }
}

impl Deserializable for Asset {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Both asset types have their faucet ID prefix as the first element, so we can use it to
        // inspect what type of asset it is.
        let faucet_id_prefix: AccountIdPrefix = source.read()?;

        match faucet_id_prefix.account_type() {
            AccountType::FungibleFaucet => {
                FungibleAsset::deserialize_with_faucet_id_prefix(faucet_id_prefix, source)
                    .map(Asset::from)
            },
            AccountType::NonFungibleFaucet => {
                NonFungibleAsset::deserialize_with_faucet_id_prefix(faucet_id_prefix, source)
                    .map(Asset::from)
            },
            other_type => Err(DeserializationError::InvalidValue(format!(
                "failed to deserialize asset: expected an account ID prefix of type faucet, found {other_type:?}"
            ))),
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns `true` if asset in [Word] is not a non-fungible asset.
///
/// Note: this does not mean that the word is a fungible asset as the word may contain a value
/// which is not a valid asset.
fn is_not_a_non_fungible_asset(asset: Word) -> bool {
    match AccountIdPrefix::try_from(asset[3]) {
        Ok(prefix) => {
            matches!(prefix.account_type(), AccountType::FungibleFaucet)
        },
        Err(_err) => {
            #[cfg(debug_assertions)]
            panic!("invalid account ID prefix passed to is_not_a_non_fungible_asset: {_err}");
            #[cfg(not(debug_assertions))]
            false
        },
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use miden_crypto::Word;
    use miden_crypto::utils::{Deserializable, Serializable};

    use super::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
    use crate::account::{AccountId, AccountIdPrefix};
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
    };

    #[test]
    fn test_asset_serde() {
        for fungible_account_id in [
            ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
        ] {
            let account_id = AccountId::try_from(fungible_account_id).unwrap();
            let fungible_asset: Asset = FungibleAsset::new(account_id, 10).unwrap().into();
            assert_eq!(fungible_asset, Asset::read_from_bytes(&fungible_asset.to_bytes()).unwrap());
        }

        for non_fungible_account_id in [
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
        ] {
            let account_id = AccountId::try_from(non_fungible_account_id).unwrap();
            let details = NonFungibleAssetDetails::new(account_id.prefix(), vec![1, 2, 3]).unwrap();
            let non_fungible_asset: Asset = NonFungibleAsset::new(&details).unwrap().into();
            assert_eq!(
                non_fungible_asset,
                Asset::read_from_bytes(&non_fungible_asset.to_bytes()).unwrap()
            );
        }
    }

    #[test]
    fn test_new_unchecked() {
        for fungible_account_id in [
            ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
        ] {
            let account_id = AccountId::try_from(fungible_account_id).unwrap();
            let fungible_asset: Asset = FungibleAsset::new(account_id, 10).unwrap().into();
            assert_eq!(fungible_asset, Asset::new_unchecked(Word::from(&fungible_asset)));
        }

        for non_fungible_account_id in [
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
        ] {
            let account_id = AccountId::try_from(non_fungible_account_id).unwrap();
            let details = NonFungibleAssetDetails::new(account_id.prefix(), vec![1, 2, 3]).unwrap();
            let non_fungible_asset: Asset = NonFungibleAsset::new(&details).unwrap().into();
            assert_eq!(non_fungible_asset, Asset::new_unchecked(Word::from(non_fungible_asset)));
        }
    }

    /// This test asserts that account ID's prefix is serialized in the first felt of assets.
    /// Asset deserialization relies on that fact and if this changes the serialization must
    /// be updated.
    #[test]
    fn test_account_id_prefix_is_in_first_serialized_felt() {
        for asset in [FungibleAsset::mock(300), NonFungibleAsset::mock(&[0xaa, 0xbb])] {
            let serialized_asset = asset.to_bytes();
            let prefix = AccountIdPrefix::read_from_bytes(&serialized_asset).unwrap();
            assert_eq!(prefix, asset.faucet_id_prefix());
        }
    }
}
