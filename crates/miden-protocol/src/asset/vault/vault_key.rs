use alloc::boxed::Box;
use alloc::string::ToString;
use core::fmt;

use miden_core::LexicographicWord;
use miden_crypto::merkle::smt::LeafIndex;

use crate::account::AccountId;
use crate::account::AccountType::{self};
use crate::asset::vault::AssetId;
use crate::asset::{Asset, AssetCallbackFlag, FungibleAsset, NonFungibleAsset};
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
///   [faucet_id_suffix (56 bits) | 7 zero bits | callbacks_enabled (1 bit)],
///   faucet_id_prefix (64 bits)
/// ]
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AssetVaultKey {
    /// The asset ID of the vault key.
    asset_id: AssetId,

    /// The ID of the faucet that issued the asset.
    faucet_id: AccountId,

    /// Determines whether callbacks are enabled.
    callback_flag: AssetCallbackFlag,
}

impl AssetVaultKey {
    /// The serialized size of an [`AssetVaultKey`] in bytes.
    ///
    /// Serialized as its [`Word`] representation (4 field elements).
    pub const SERIALIZED_SIZE: usize = Word::SERIALIZED_SIZE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an [`AssetVaultKey`] for a native asset with callbacks disabled.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided ID is not of type
    ///   [`AccountType::FungibleFaucet`](crate::account::AccountType::FungibleFaucet) or
    ///   [`AccountType::NonFungibleFaucet`](crate::account::AccountType::NonFungibleFaucet)
    /// - the asset ID limbs are not zero when `faucet_id` is of type
    ///   [`AccountType::FungibleFaucet`](crate::account::AccountType::FungibleFaucet).
    pub fn new_native(asset_id: AssetId, faucet_id: AccountId) -> Result<Self, AssetError> {
        Self::new(asset_id, faucet_id, AssetCallbackFlag::Disabled)
    }

    /// Creates an [`AssetVaultKey`] from its parts with the given [`AssetCallbackFlag`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided ID is not of type
    ///   [`AccountType::FungibleFaucet`](crate::account::AccountType::FungibleFaucet) or
    ///   [`AccountType::NonFungibleFaucet`](crate::account::AccountType::NonFungibleFaucet)
    /// - the asset ID limbs are not zero when `faucet_id` is of type
    ///   [`AccountType::FungibleFaucet`](crate::account::AccountType::FungibleFaucet).
    pub fn new(
        asset_id: AssetId,
        faucet_id: AccountId,
        callback_flag: AssetCallbackFlag,
    ) -> Result<Self, AssetError> {
        if !faucet_id.is_faucet() {
            return Err(AssetError::InvalidFaucetAccountId(Box::from(format!(
                "expected account ID of type faucet, found account type {}",
                faucet_id.account_type()
            ))));
        }

        if matches!(faucet_id.account_type(), AccountType::FungibleFaucet) && !asset_id.is_empty() {
            return Err(AssetError::FungibleAssetIdMustBeZero(asset_id));
        }

        Ok(Self { asset_id, faucet_id, callback_flag })
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
        debug_assert!(faucet_suffix & 0xff == 0, "lower 8 bits of faucet suffix must be zero");
        let faucet_id_suffix_and_metadata = faucet_suffix | self.callback_flag.as_u8() as u64;
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

    /// Constructs a fungible asset's key from a faucet ID.
    ///
    /// Returns `None` if the provided ID is not of type
    /// [`AccountType::FungibleFaucet`](crate::account::AccountType::FungibleFaucet)
    pub fn new_fungible(faucet_id: AccountId) -> Option<Self> {
        if matches!(faucet_id.account_type(), AccountType::FungibleFaucet) {
            let asset_id = AssetId::new(Felt::ZERO, Felt::ZERO);
            Some(
                Self::new_native(asset_id, faucet_id)
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
    /// Implements comparison based on [`LexicographicWord`].
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        LexicographicWord::new(self.to_word()).cmp(&LexicographicWord::new(other.to_word()))
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
    fn try_from(key: Word) -> Result<Self, Self::Error> {
        let asset_id_suffix = key[0];
        let asset_id_prefix = key[1];
        let faucet_id_suffix_and_metadata = key[2];
        let faucet_id_prefix = key[3];

        let raw = faucet_id_suffix_and_metadata.as_canonical_u64();
        let callback_flag = AssetCallbackFlag::try_from((raw & 0xff) as u8)?;
        let faucet_id_suffix = Felt::try_from(raw & 0xffff_ffff_ffff_ff00)
            .expect("clearing lower bits should not produce an invalid felt");

        let asset_id = AssetId::new(asset_id_suffix, asset_id_prefix);
        let faucet_id = AccountId::try_from_elements(faucet_id_suffix, faucet_id_prefix)
            .map_err(|err| AssetError::InvalidFaucetAccountId(Box::new(err)))?;

        Self::new(asset_id, faucet_id, callback_flag)
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
    use super::*;
    use crate::asset::AssetCallbackFlag;
    use crate::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    };

    #[test]
    fn asset_vault_key_word_roundtrip() -> anyhow::Result<()> {
        let fungible_faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
        let nonfungible_faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET)?;

        for callback_flag in [AssetCallbackFlag::Disabled, AssetCallbackFlag::Enabled] {
            // Fungible: asset_id must be zero.
            let key = AssetVaultKey::new(AssetId::default(), fungible_faucet, callback_flag)?;

            let roundtripped = AssetVaultKey::try_from(key.to_word())?;
            assert_eq!(key, roundtripped);
            assert_eq!(key, AssetVaultKey::read_from_bytes(&key.to_bytes())?);

            // Non-fungible: asset_id can be non-zero.
            let key = AssetVaultKey::new(
                AssetId::new(Felt::from(42u32), Felt::from(99u32)),
                nonfungible_faucet,
                callback_flag,
            )?;

            let roundtripped = AssetVaultKey::try_from(key.to_word())?;
            assert_eq!(key, roundtripped);
            assert_eq!(key, AssetVaultKey::read_from_bytes(&key.to_bytes())?);
        }

        Ok(())
    }
}
