use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use miden_crypto::merkle::InnerNodeInfo;
use miden_crypto::merkle::smt::SmtProof;

use super::asset_id::AssetId;
use crate::Word;
use crate::asset::Asset;
use crate::errors::AssetError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// A witness of an asset in an [`AssetVault`](super::AssetVault).
///
/// It proves inclusion of a certain asset in the vault.
///
/// ## Guarantees
///
/// This type guarantees that the raw ID-value pairs it contains are all present in the
/// contained SMT proof (under their hashed form). Note that the inverse is not necessarily true:
/// the proof may contain more entries than the witness because to prove inclusion of a given raw
/// ID A an [`SmtLeaf::Multiple`](miden_crypto::merkle::smt::SmtLeaf::Multiple) may be present
/// that contains both SMT keys hash(A) and hash(B). However, B may not be present in the ID-value
/// pairs and this is a valid state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetWitness {
    proof: SmtProof,
    /// Raw [`AssetId`]s -> asset value words, kept consistent with the proof's leaf entries.
    entries: BTreeMap<AssetId, Word>,
}

impl AssetWitness {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AssetWitness`] from an SMT proof and a set of raw asset IDs.
    ///
    /// For each ID, looks up its hashed form in the proof and records the resulting value.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - any ID's hashed form is not present in the proof.
    /// - any of the resulting `(asset_id, value)` pairs do not form a valid asset.
    pub fn new(
        proof: SmtProof,
        ids: impl IntoIterator<Item = AssetId>,
    ) -> Result<Self, AssetError> {
        let mut entries = BTreeMap::new();

        for id in ids {
            let value = proof
                .get(&id.hash().as_word())
                .ok_or(AssetError::AssetWitnessMissingId { id })?;

            // Validate that the (id, value) pair forms a valid asset (and skip empty entries).
            if !value.is_empty() {
                Asset::new(id, value)
                    .map_err(|err| AssetError::AssetWitnessInvalid(Box::new(err)))?;
            }

            entries.insert(id, value);
        }

        Ok(Self { proof, entries })
    }

    /// Creates a new [`AssetWitness`] from an SMT proof and a set of ID-value pairs without
    /// validating that the pairs form valid assets.
    ///
    /// Prefer [`AssetWitness::new`] whenever possible. See the type-level docs for the invariants
    /// callers must uphold.
    pub fn new_unchecked(
        proof: SmtProof,
        id_values: impl IntoIterator<Item = (AssetId, Word)>,
    ) -> Self {
        let entries: BTreeMap<AssetId, Word> = id_values.into_iter().collect();

        #[cfg(debug_assertions)]
        for (id, value) in &entries {
            debug_assert_eq!(
                proof.get(&id.hash().as_word()),
                Some(*value),
                "AssetWitness::new_unchecked: (id, value) pair does not match the proof",
            );
        }

        Self { proof, entries }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the underlying [`SmtProof`].
    pub fn proof(&self) -> &SmtProof {
        &self.proof
    }

    /// Returns `true` if this [`AssetWitness`] authenticates the provided [`AssetId`], i.e.
    /// if its leaf index matches, `false` otherwise.
    pub fn authenticates_asset_id(&self, asset_id: AssetId) -> bool {
        self.proof.leaf().index() == asset_id.hash().to_leaf_index()
    }

    /// Searches for an [`Asset`] in the witness with the given `asset_id`.
    pub fn find(&self, asset_id: AssetId) -> Option<Asset> {
        let value = self.entries.get(&asset_id).copied()?;
        if value.is_empty() {
            None
        } else {
            Some(Asset::new(asset_id, value).expect("asset witness should track valid assets"))
        }
    }

    /// Returns an iterator over the [`Asset`]s in this witness.
    pub fn assets(&self) -> impl Iterator<Item = Asset> + '_ {
        self.entries.iter().filter_map(|(id, value)| {
            if value.is_empty() {
                None
            } else {
                Some(Asset::new(*id, *value).expect("asset witness should track valid assets"))
            }
        })
    }

    /// Returns an iterator over the raw `(asset_id, value)` pairs tracked by this witness.
    pub(super) fn entries(&self) -> impl Iterator<Item = (&AssetId, &Word)> {
        self.entries.iter()
    }

    /// Decomposes the witness into its underlying [`SmtProof`] and the raw `(asset_id, value)`
    /// entries it tracks.
    pub(super) fn into_parts(self) -> (SmtProof, BTreeMap<AssetId, Word>) {
        (self.proof, self.entries)
    }

    /// Returns an iterator over every inner node of this witness' merkle path.
    pub fn authenticated_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.proof
            .path()
            .authenticated_nodes(self.proof.leaf().index().position(), self.proof.leaf().hash())
            .expect("leaf index is u64 and should be less than 2^SMT_DEPTH")
    }
}

impl From<AssetWitness> for SmtProof {
    fn from(witness: AssetWitness) -> Self {
        witness.proof
    }
}

impl Serializable for AssetWitness {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.proof);
        target.write_usize(self.entries.len());
        target.write_many(self.entries.keys());
    }
}

impl Deserializable for AssetWitness {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let proof: SmtProof = source.read()?;
        let num_ids: usize = source.read()?;
        let ids = source.read_many_iter::<AssetId>(num_ids)?.collect::<Result<Vec<_>, _>>()?;

        Self::new(proof, ids).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_crypto::merkle::smt::Smt;

    use super::*;
    use crate::asset::{AssetVault, FungibleAsset, NonFungibleAsset};
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
    };

    /// Tests that constructing an asset witness fails if the (asset_id, value) pair stored in the
    /// proof is inconsistent (here: a non-fungible value under a fungible asset ID).
    #[test]
    fn create_asset_witness_fails_on_asset_id_mismatch() -> anyhow::Result<()> {
        let fungible_asset = FungibleAsset::mock(500);
        let non_fungible_asset = NonFungibleAsset::mock(&[1]);

        // Manually build a proof at the fungible asset's hashed ID but with a non-fungible value.
        let fungible_id = fungible_asset.id();
        let inconsistent_smt = Smt::with_entries([(
            fungible_id.hash().as_word(),
            non_fungible_asset.to_value_word(),
        )])?;
        let proof = inconsistent_smt.open(&fungible_id.hash().as_word());

        let err = AssetWitness::new(proof, [fungible_id]).unwrap_err();

        assert_matches!(err, AssetError::AssetWitnessInvalid(source) => {
            assert_matches!(*source, AssetError::FungibleAssetValueMostSignificantElementsMustBeZero(_));
        });

        Ok(())
    }

    /// Tests that constructing an asset witness fails if the provided raw asset ID is not actually
    /// present (in hashed form) in the SMT proof.
    #[test]
    fn create_asset_witness_fails_on_missing_id() -> anyhow::Result<()> {
        let asset_in_vault =
            FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3.try_into()?, 200)?;
        let other_id =
            FungibleAsset::new(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?, 100)?.id();

        let vault = AssetVault::new(&[asset_in_vault.into()])?;
        let proof = vault.open(asset_in_vault.id()).proof().clone();

        // The proof was opened at `asset_in_vault`'s hashed ID, so a separate `other_id` won't
        // be found in it.
        let err = AssetWitness::new(proof, [other_id]).unwrap_err();
        assert_matches!(err, AssetError::AssetWitnessMissingId { id } => {
            assert_eq!(id, other_id);
        });

        Ok(())
    }

    #[test]
    fn asset_witness_authenticates_asset_id() -> anyhow::Result<()> {
        let fungible_asset0 =
            FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3.try_into()?, 200)?;
        let fungible_asset1 =
            FungibleAsset::new(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?, 100)?;

        let vault = AssetVault::new(&[fungible_asset0.into()])?;
        let witness0 = vault.open(fungible_asset0.id());

        assert!(witness0.authenticates_asset_id(fungible_asset0.id()));
        assert!(!witness0.authenticates_asset_id(fungible_asset1.id()));

        Ok(())
    }
}
