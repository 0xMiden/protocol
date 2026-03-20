use alloc::vec::Vec;

use miden_crypto::SequentialCommit;

use crate::asset::{Asset, FungibleAsset, NonFungibleAsset};
use crate::errors::NoteError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, MAX_ASSETS_PER_NOTE, WORD_SIZE, Word};

// NOTE ASSETS
// ================================================================================================

/// An asset container for a note.
///
/// A note can contain between 0 and 255 assets. No duplicates are allowed, but the order of assets
/// is unspecified.
///
/// All the assets in a note can be reduced to a single commitment which is computed by
/// sequentially hashing the assets. Note that the same list of assets can result in two different
/// commitments if the asset ordering is different.
#[derive(Debug, Default, Clone)]
pub struct NoteAssets {
    assets: Vec<Asset>,
    commitment: Word,
}

impl NoteAssets {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of assets which can be carried by a single note.
    pub const MAX_NUM_ASSETS: usize = MAX_ASSETS_PER_NOTE;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns new [NoteAssets] constructed from the provided list of assets.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The list contains more than 256 assets.
    /// - There are duplicate assets in the list.
    pub fn new(assets: Vec<Asset>) -> Result<Self, NoteError> {
        if assets.len() > Self::MAX_NUM_ASSETS {
            return Err(NoteError::TooManyAssets(assets.len()));
        }

        // make sure all provided assets are unique
        for (i, asset) in assets.iter().enumerate().skip(1) {
            // for all assets except the first one, check if the asset is the same as any other
            // asset in the list, and if so return an error
            if assets[..i].iter().any(|a| a.is_same(asset)) {
                return Err(match asset {
                    Asset::Fungible(asset) => NoteError::DuplicateFungibleAsset(asset.faucet_id()),
                    Asset::NonFungible(asset) => NoteError::DuplicateNonFungibleAsset(*asset),
                });
            }
        }

        let commitment = to_commitment(&assets);

        Ok(Self { assets, commitment })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a commitment to the note's assets.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// Returns the number of assets.
    pub fn num_assets(&self) -> usize {
        self.assets.len()
    }

    /// Returns true if the number of assets is 0.
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    /// Returns an iterator over all assets.
    pub fn iter(&self) -> core::slice::Iter<'_, Asset> {
        self.assets.iter()
    }

    /// Returns all assets represented as a vector of field elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Returns an iterator over all [`FungibleAsset`].
    pub fn iter_fungible(&self) -> impl Iterator<Item = FungibleAsset> {
        self.assets.iter().filter_map(|asset| match asset {
            Asset::Fungible(fungible_asset) => Some(*fungible_asset),
            Asset::NonFungible(_) => None,
        })
    }

    /// Returns iterator over all [`NonFungibleAsset`].
    pub fn iter_non_fungible(&self) -> impl Iterator<Item = NonFungibleAsset> {
        self.assets.iter().filter_map(|asset| match asset {
            Asset::Fungible(_) => None,
            Asset::NonFungible(non_fungible_asset) => Some(*non_fungible_asset),
        })
    }

    /// Consumes self and returns the underlying vector of assets.
    pub fn into_vec(self) -> Vec<Asset> {
        self.assets
    }
}

impl PartialEq for NoteAssets {
    fn eq(&self, other: &Self) -> bool {
        self.assets == other.assets
    }
}

impl Eq for NoteAssets {}

impl SequentialCommit for NoteAssets {
    type Commitment = Word;

    /// Returns all assets represented as a vector of field elements.
    fn to_elements(&self) -> Vec<Felt> {
        to_elements(&self.assets)
    }

    /// Computes the commitment to the assets.
    fn to_commitment(&self) -> Self::Commitment {
        to_commitment(&self.assets)
    }
}

fn to_elements(assets: &[Asset]) -> Vec<Felt> {
    let mut elements = Vec::with_capacity(assets.len() * 2 * WORD_SIZE);
    elements.extend(assets.iter().flat_map(Asset::as_elements));
    elements
}

fn to_commitment(assets: &[Asset]) -> Word {
    Hasher::hash_elements(&to_elements(assets))
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteAssets {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        const _: () = assert!(NoteAssets::MAX_NUM_ASSETS <= u8::MAX as usize);
        debug_assert!(self.assets.len() <= NoteAssets::MAX_NUM_ASSETS);
        target.write_u8(self.assets.len().try_into().expect("Asset number must fit into `u8`"));
        target.write_many(&self.assets);
    }

    fn get_size_hint(&self) -> usize {
        // Size of the serialized asset count prefix.
        let u8_size = 0u8.get_size_hint();

        let assets_size: usize = self.assets.iter().map(|asset| asset.get_size_hint()).sum();

        u8_size + assets_size
    }
}

impl Deserializable for NoteAssets {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = source.read_u8()?;
        let assets = source.read_many_iter::<Asset>(count.into())?.collect::<Result<_, _>>()?;
        Self::new(assets).map_err(|e| DeserializationError::InvalidValue(format!("{e:?}")))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::NoteAssets;
    use crate::account::AccountId;
    use crate::asset::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    };

    #[test]
    fn iter_fungible_asset() {
        let faucet_id_1 = AccountId::try_from(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET).unwrap();
        let faucet_id_2 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET).unwrap();
        let details = NonFungibleAssetDetails::new(account_id, vec![1, 2, 3]).unwrap();

        let asset1 = Asset::Fungible(FungibleAsset::new(faucet_id_1, 100).unwrap());
        let asset2 = Asset::Fungible(FungibleAsset::new(faucet_id_2, 50).unwrap());
        let non_fungible_asset = Asset::NonFungible(NonFungibleAsset::new(&details).unwrap());

        // Create NoteAsset from assets
        let assets = NoteAssets::new([asset1, asset2, non_fungible_asset].to_vec()).unwrap();

        let mut fungible_assets = assets.iter_fungible();
        assert_eq!(fungible_assets.next().unwrap(), asset1.unwrap_fungible());
        assert_eq!(fungible_assets.next().unwrap(), asset2.unwrap_fungible());
        assert_eq!(fungible_assets.next(), None);
    }
}
