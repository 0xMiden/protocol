use alloc::boxed::Box;
use core::fmt;

use miden_core::LexicographicWord;
use miden_crypto::merkle::smt::LeafIndex;
use miden_processor::SMT_DEPTH;

use crate::account::AccountId;
use crate::account::AccountType::{self};
use crate::asset::vault::AssetId;
use crate::asset::{Asset, FungibleAsset, NonFungibleAsset};
use crate::errors::AssetError;
use crate::{Felt, FieldElement, Word};

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
}

impl AssetVaultKey {
    /// Creates an [`AssetVaultKey`] from its parts.
    pub fn new(asset_id: AssetId, faucet_id: AccountId) -> Self {
        Self { asset_id, faucet_id }
    }

    /// Returns the word representation of the vault key.
    ///
    /// See the type-level documentation for details.
    pub fn to_word(self) -> Word {
        vault_key_to_word(self.asset_id, self.faucet_id)
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

impl fmt::Display for AssetVaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The faucet ID Display impl includes the 0x prefix.
        // Write asset ID limbs manually to avoid 0x prefix from asset ID display impl.
        write!(
            f,
            "{}{:016x}{:016x}",
            self.faucet_id,
            self.asset_id.prefix().as_int(),
            self.asset_id.suffix().as_int()
        )
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

#[cfg(test)]
mod tests {
    use std::string::ToString;

    use super::*;
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET;

    #[test]
    fn asset_vault_key_to_hex() {
        let key = AssetVaultKey::new(
            AssetId::new(1u32.into(), 2u32.into()),
            ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into().unwrap(),
        );

        assert_eq!(
            key.to_string(),
            "0xfa0000000000bba00000cd000000dd00000000000000020000000000000001"
        )
    }
}
