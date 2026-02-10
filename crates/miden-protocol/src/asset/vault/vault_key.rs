use alloc::boxed::Box;
use alloc::string::String;

use miden_core::LexicographicWord;
use miden_crypto::merkle::smt::LeafIndex;
use miden_processor::SMT_DEPTH;
use miden_protocol_macros::WordWrapper;

use crate::account::AccountId;
use crate::account::AccountType::{self};
use crate::asset::vault::AssetId;
use crate::asset::{Asset, FungibleAsset, NonFungibleAsset};
use crate::errors::AssetError;
use crate::{Felt, FieldElement, Hasher, Word};

/// The unique identifier of an [`Asset`] in the [`AssetVault`](crate::asset::AssetVault).
///
/// Note that the asset vault key is not used directly as the key in an asset vault. See
/// the derived [`AssetVaultKeyHash`] for details.
///
/// Its [`Word`] layout is:
/// ```text
/// [
///   asset_id_suffix (64 bits),
///   asset_id_prefix (64 bits),
///   faucet_id_suffix (56 bits),
///   faucet_id_prefix (64 bits)
/// ]
/// ```
///
/// See the [`Asset`] documentation for the differences between fungible and non-fungible assets.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AssetVaultKey {
    /// The asset ID of the vault key.
    asset_id: AssetId,

    /// The ID of the faucet that issued the asset.
    faucet_id: AccountId,

    /// The cached hash of the vault key's word representation for use in the asset vault.
    key_hash: AssetVaultKeyHash,
}

impl AssetVaultKey {
    /// Creates an [`AssetVaultKey`] from its parts.
    pub fn new(asset_id: AssetId, faucet_id: AccountId) -> Self {
        let word = vault_key_to_word(asset_id, faucet_id);
        let key_hash = Hasher::hash_elements(word.as_elements());
        let key_hash = AssetVaultKeyHash::from_raw(key_hash);

        Self { asset_id, faucet_id, key_hash }
    }

    /// Returns the word representation of the vault key.
    ///
    /// See the type-level documentation for details.
    pub fn to_word(self) -> Word {
        vault_key_to_word(self.asset_id, self.faucet_id)
    }

    /// Returns the [`AssetVaultKeyHash`] of the vault key for use in the asset vault.
    pub fn as_hashed_key(self) -> AssetVaultKeyHash {
        self.key_hash
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

    /// Constructs a fungible asset's key from a faucet ID.
    ///
    /// Returns `None` if the provided ID is not of type
    /// [`AccountType::FungibleFaucet`](crate::account::AccountType::FungibleFaucet)
    pub fn new_fungible(faucet_id: AccountId) -> Option<Self> {
        if matches!(faucet_id.account_type(), AccountType::FungibleFaucet) {
            let asset_id = AssetId::new(Felt::ZERO, Felt::ZERO);
            Some(Self::new(asset_id, faucet_id))
        } else {
            None
        }
    }

    /// Returns `true` if the asset key is for a fungible asset, `false` otherwise.
    fn is_fungible(&self) -> bool {
        matches!(self.faucet_id.account_type(), AccountType::FungibleFaucet)
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
    /// - the faucet ID in the key is invalid.
    fn try_from(key: Word) -> Result<Self, Self::Error> {
        let asset_id_suffix = key[0];
        let asset_id_prefix = key[1];
        let faucet_id_suffix = key[2];
        let faucet_id_prefix = key[3];

        let asset_id = AssetId::new(asset_id_suffix, asset_id_prefix);
        let faucet_id = AccountId::try_from([faucet_id_prefix, faucet_id_suffix])
            .map_err(|err| AssetError::InvalidFaucetAccountId(Box::new(err)))?;

        Ok(Self::new(asset_id, faucet_id))
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

fn vault_key_to_word(asset_id: AssetId, faucet_id: AccountId) -> Word {
    Word::new([
        asset_id.suffix(),
        asset_id.prefix(),
        faucet_id.suffix(),
        faucet_id.prefix().as_felt(),
    ])
}

// ASSET VAULT KEY HASH
// ================================================================================================

/// The key of an asset in the [`AssetVault`](crate::asset::AssetVault).
///
/// The hash combines the asset ID and faucet ID into a single hashed value to ensure that assets
/// from the _same_ faucet with _different_ IDs map to different leaves, while assets sharing both
/// IDs produce identical keys.
///
/// This ensures that non-fungible assets issued by the same faucet are stored in different leaves,
/// while fungible assets issued by the same faucet are stored in the same leaf.
#[derive(Debug, Clone, Copy, WordWrapper, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssetVaultKeyHash(Word);

impl AssetVaultKeyHash {
    /// Returns the leaf index of a vault key.
    pub fn to_leaf_index(&self) -> LeafIndex<SMT_DEPTH> {
        LeafIndex::<SMT_DEPTH>::from(self.0)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::Felt;

    use super::*;
    use crate::account::{AccountIdVersion, AccountStorageMode, AccountType};

    fn make_non_fungible_key(prefix: u64) -> AssetVaultKey {
        let word = [Felt::new(prefix), Felt::new(11), Felt::new(22), Felt::new(33)].into();
        AssetVaultKey::new_unchecked(word)
    }

    #[test]
    fn test_faucet_id_for_fungible_asset() {
        let id = AccountId::dummy(
            [0xff; 15],
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        );

        let key =
            AssetVaultKey::new_fungible(id).expect("Expected AssetVaultKey for FungibleFaucet");

        // faucet_id_prefix() should match AccountId prefix
        assert_eq!(key.faucet_id_prefix(), id.prefix());

        // faucet_id() should return the same account id
        assert_eq!(key.faucet_id().unwrap(), id);
    }

    #[test]
    fn test_faucet_id_for_non_fungible_asset() {
        let id = AccountId::dummy(
            [0xff; 15],
            AccountIdVersion::Version0,
            AccountType::NonFungibleFaucet,
            AccountStorageMode::Public,
        );

        let prefix_value = id.prefix().as_u64();
        let key = make_non_fungible_key(prefix_value);

        // faucet_id_prefix() should match AccountId prefix
        assert_eq!(key.faucet_id_prefix(), id.prefix());

        // faucet_id() should return the None
        assert_eq!(key.faucet_id(), None);
    }
}
