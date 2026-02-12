use alloc::boxed::Box;
use alloc::string::ToString;
use core::fmt;

use super::vault::AssetVaultKey;
use super::{AccountType, Asset, AssetError, Felt, Word, ZERO, is_not_a_non_fungible_asset};
use crate::account::{AccountId, AccountIdPrefix};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// FUNGIBLE ASSET
// ================================================================================================
/// A fungible asset.
///
/// A fungible asset consists of a faucet ID of the faucet which issued the asset as well as the
/// asset amount. Asset amount is guaranteed to be 2^63 - 1 or smaller.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FungibleAsset {
    faucet_id: AccountId,
    amount: u64,
}

impl FungibleAsset {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// Specifies the maximum amount a fungible asset can represent.
    ///
    /// This number was chosen so that it can be represented as a positive and negative number in a
    /// field element. See `account_delta.masm` for more details on how this number was chosen.
    pub const MAX_AMOUNT: u64 = 2u64.pow(63) - 2u64.pow(31);

    /// The serialized size of a [`FungibleAsset`] in bytes.
    ///
    /// Currently an account ID (15 bytes) plus an amount (u64).
    pub const SERIALIZED_SIZE: usize = AccountId::SERIALIZED_SIZE + core::mem::size_of::<u64>();

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a fungible asset instantiated with the provided faucet ID and amount.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The faucet_id is not a valid fungible faucet ID.
    /// - The provided amount is greater than 2^63 - 1.
    pub const fn new(faucet_id: AccountId, amount: u64) -> Result<Self, AssetError> {
        let asset = Self { faucet_id, amount };
        asset.validate()
    }

    /// Creates a new [FungibleAsset] without checking its validity.
    pub(crate) fn new_unchecked(value: Word) -> FungibleAsset {
        FungibleAsset {
            faucet_id: AccountId::new_unchecked([value[3], value[2]]),
            amount: value[0].as_int(),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Return ID of the faucet which issued this asset.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// Return ID prefix of the faucet which issued this asset.
    pub fn faucet_id_prefix(&self) -> AccountIdPrefix {
        self.faucet_id.prefix()
    }

    /// Returns the amount of this asset.
    pub fn amount(&self) -> u64 {
        self.amount
    }

    /// Returns true if this and the other assets were issued from the same faucet.
    pub fn is_from_same_faucet(&self, other: &Self) -> bool {
        self.faucet_id == other.faucet_id
    }

    /// Returns the key which is used to store this asset in the account vault.
    pub fn vault_key(&self) -> AssetVaultKey {
        AssetVaultKey::from_account_id(self.faucet_id)
            .expect("faucet ID should be of type fungible")
    }

    // OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Adds two fungible assets together and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The assets were not issued by the same faucet.
    /// - The total value of assets is greater than or equal to 2^63.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Self) -> Result<Self, AssetError> {
        if self.faucet_id != other.faucet_id {
            return Err(AssetError::FungibleAssetInconsistentFaucetIds {
                original_issuer: self.faucet_id,
                other_issuer: other.faucet_id,
            });
        }

        let amount = self
            .amount
            .checked_add(other.amount)
            .expect("even MAX_AMOUNT + MAX_AMOUNT should not overflow u64");
        if amount > Self::MAX_AMOUNT {
            return Err(AssetError::FungibleAssetAmountTooBig(amount));
        }

        Ok(Self { faucet_id: self.faucet_id, amount })
    }

    /// Subtracts a fungible asset from another and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The assets were not issued by the same faucet.
    /// - The final amount would be negative.
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, other: Self) -> Result<Self, AssetError> {
        if self.faucet_id != other.faucet_id {
            return Err(AssetError::FungibleAssetInconsistentFaucetIds {
                original_issuer: self.faucet_id,
                other_issuer: other.faucet_id,
            });
        }

        let amount = self.amount.checked_sub(other.amount).ok_or(
            AssetError::FungibleAssetAmountNotSufficient {
                minuend: self.amount,
                subtrahend: other.amount,
            },
        )?;

        Ok(FungibleAsset { faucet_id: self.faucet_id, amount })
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Validates this fungible asset.
    /// # Errors
    /// Returns an error if:
    /// - The faucet_id is not a valid fungible faucet ID.
    /// - The provided amount is greater than 2^63 - 1.
    const fn validate(self) -> Result<Self, AssetError> {
        let account_type = self.faucet_id.account_type();
        if !matches!(account_type, AccountType::FungibleFaucet) {
            return Err(AssetError::FungibleFaucetIdTypeMismatch(self.faucet_id));
        }

        if self.amount > Self::MAX_AMOUNT {
            return Err(AssetError::FungibleAssetAmountTooBig(self.amount));
        }

        Ok(self)
    }
}

impl From<FungibleAsset> for Word {
    fn from(asset: FungibleAsset) -> Self {
        let mut result = Word::empty();
        result[0] = Felt::new(asset.amount);
        result[2] = asset.faucet_id.suffix();
        result[3] = asset.faucet_id.prefix().as_felt();
        debug_assert!(is_not_a_non_fungible_asset(result));
        result
    }
}

impl From<FungibleAsset> for Asset {
    fn from(asset: FungibleAsset) -> Self {
        Asset::Fungible(asset)
    }
}

impl TryFrom<Word> for FungibleAsset {
    type Error = AssetError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        if value[1] != ZERO {
            return Err(AssetError::FungibleAssetExpectedZero(value));
        }
        let faucet_id = AccountId::try_from([value[3], value[2]])
            .map_err(|err| AssetError::InvalidFaucetAccountId(Box::new(err)))?;
        let amount = value[0].as_int();
        Self::new(faucet_id, amount)
    }
}

impl fmt::Display for FungibleAsset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for FungibleAsset {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // All assets should serialize their faucet ID at the first position to allow them to be
        // distinguishable during deserialization.
        target.write(self.faucet_id);
        target.write(self.amount);
    }

    fn get_size_hint(&self) -> usize {
        self.faucet_id.get_size_hint() + self.amount.get_size_hint()
    }
}

impl Deserializable for FungibleAsset {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let faucet_id_prefix: AccountIdPrefix = source.read()?;
        FungibleAsset::deserialize_with_faucet_id_prefix(faucet_id_prefix, source)
    }
}

impl FungibleAsset {
    /// Deserializes a [`FungibleAsset`] from an [`AccountIdPrefix`] and the remaining data from the
    /// given `source`.
    pub(super) fn deserialize_with_faucet_id_prefix<R: ByteReader>(
        faucet_id_prefix: AccountIdPrefix,
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        // The 8 bytes of the prefix have already been read, so we only need to read the remaining 7
        // bytes of the account ID's 15 total bytes.
        let suffix_bytes: [u8; 7] = source.read()?;
        // Convert prefix back to bytes so we can call the TryFrom<[u8; 15]> impl.
        let prefix_bytes: [u8; 8] = faucet_id_prefix.into();
        let mut id_bytes: [u8; 15] = [0; 15];
        id_bytes[..8].copy_from_slice(&prefix_bytes);
        id_bytes[8..].copy_from_slice(&suffix_bytes);

        let faucet_id = AccountId::try_from(id_bytes)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;

        let amount: u64 = source.read()?;
        FungibleAsset::new(faucet_id, amount)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountId;
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
    };

    #[test]
    fn test_fungible_asset_serde() {
        for fungible_account_id in [
            ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
        ] {
            let account_id = AccountId::try_from(fungible_account_id).unwrap();
            let fungible_asset = FungibleAsset::new(account_id, 10).unwrap();
            assert_eq!(
                fungible_asset,
                FungibleAsset::read_from_bytes(&fungible_asset.to_bytes()).unwrap()
            );
        }

        let account_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3).unwrap();
        let asset = FungibleAsset::new(account_id, 50).unwrap();
        let mut asset_bytes = asset.to_bytes();
        assert_eq!(asset_bytes.len(), asset.get_size_hint());
        assert_eq!(asset.get_size_hint(), FungibleAsset::SERIALIZED_SIZE);

        let non_fungible_faucet_id =
            AccountId::try_from(ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET).unwrap();

        // Set invalid Faucet ID.
        asset_bytes[0..15].copy_from_slice(&non_fungible_faucet_id.to_bytes());
        let err = FungibleAsset::read_from_bytes(&asset_bytes).unwrap_err();
        assert!(matches!(err, DeserializationError::InvalidValue(_)));
    }
}
