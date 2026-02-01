use core::fmt;

use miden_crypto::merkle::smt::LeafIndex;
use miden_processor::SMT_DEPTH;

use crate::Word;
use crate::account::AccountType::FungibleFaucet;
use crate::account::{AccountId, AccountIdPrefix};
use crate::asset::{Asset, FungibleAsset, NonFungibleAsset};

/// The key of an [`Asset`] in the asset vault.
///
/// The layout of an asset key is:
/// - Fungible asset key: `[0, 0, faucet_id_suffix, faucet_id_prefix]`.
/// - Non-fungible asset key: `[faucet_id_prefix, hash1, hash2, hash0']`, where `hash0'` is
///   equivalent to `hash0` with the fungible bit set to `0`. See [`NonFungibleAsset::vault_key`]
///   for more details.
///
/// For details on the layout of an asset, see the documentation of [`Asset`].
///
/// ## Guarantees
///
/// This type guarantees that it contains a valid fungible or non-fungible asset key:
/// - For fungible assets
///   - The felt at index 3 has the fungible bit set to 1 and it is a valid account ID prefix.
///   - The felt at index 2 is a valid account ID suffix.
/// - For non-fungible assets
///   - The felt at index 3 has the fungible bit set to 0.
///   - The felt at index 0 is a valid account ID prefix.
///
/// The fungible bit is the bit in the [`AccountId`] that encodes whether the ID is a faucet.
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub struct AssetVaultKey(Word);

impl AssetVaultKey {
    /// Creates a new [`AssetVaultKey`] from the given [`Word`] **without performing validation**.
    ///
    /// ## Warning
    ///
    /// This function **does not check** whether the provided `Word` represents a valid
    /// fungible or non-fungible asset key.
    pub fn new_unchecked(value: Word) -> Self {
        Self(value)
    }

    /// Returns an [`AccountIdPrefix`] from the asset key.
    pub fn faucet_id_prefix(&self) -> AccountIdPrefix {
        if self.is_fungible() {
            AccountIdPrefix::new_unchecked(self.0[3])
        } else {
            AccountIdPrefix::new_unchecked(self.0[0])
        }
    }

    /// Returns the [`AccountId`] from the asset key if it is a fungible asset, `None` otherwise.
    pub fn faucet_id(&self) -> Option<AccountId> {
        if self.is_fungible() {
            Some(AccountId::new_unchecked([self.0[3], self.0[2]]))
        } else {
            None
        }
    }

    /// Returns the leaf index of a vault key.
    pub fn to_leaf_index(&self) -> LeafIndex<SMT_DEPTH> {
        LeafIndex::<SMT_DEPTH>::from(self.0)
    }

    /// Constructs a fungible asset's key from a faucet ID.
    ///
    /// Returns `None` if the provided ID is not of type
    /// [`AccountType::FungibleFaucet`](crate::account::AccountType::FungibleFaucet)
    pub fn from_account_id(faucet_id: AccountId) -> Option<Self> {
        match faucet_id.account_type() {
            FungibleFaucet => {
                let mut key = Word::empty();
                key[2] = faucet_id.suffix();
                key[3] = faucet_id.prefix().as_felt();
                Some(AssetVaultKey::new_unchecked(key))
            },
            _ => None,
        }
    }

    /// Returns a reference to the inner [Word] of this key.
    pub fn as_word(&self) -> &Word {
        &self.0
    }

    /// Returns `true` if the asset key is for a fungible asset, `false` otherwise.
    fn is_fungible(&self) -> bool {
        self.0[0].as_int() == 0 && self.0[1].as_int() == 0
    }
}

impl fmt::Display for AssetVaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// CONVERSIONS
// ================================================================================================

impl From<AssetVaultKey> for Word {
    fn from(vault_key: AssetVaultKey) -> Self {
        vault_key.0
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
            AssetVaultKey::from_account_id(id).expect("Expected AssetVaultKey for FungibleFaucet");

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
