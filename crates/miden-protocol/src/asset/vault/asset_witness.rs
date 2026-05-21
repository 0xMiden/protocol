use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use miden_crypto::merkle::InnerNodeInfo;
use miden_crypto::merkle::smt::SmtProof;

use super::vault_key::AssetVaultKey;
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
/// This type guarantees that the raw key-value pairs it contains are all present in the
/// contained SMT proof (under their hashed form). Note that the inverse is not necessarily true:
/// the proof may contain more entries than the witness because to prove inclusion of a given raw
/// key A an [`SmtLeaf::Multiple`](miden_crypto::merkle::smt::SmtLeaf::Multiple) may be present
/// that contains both keys hash(A) and hash(B). However, B may not be present in the key-value
/// pairs and this is a valid state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetWitness {
    proof: SmtProof,
    /// Raw [`AssetVaultKey`]s -> asset value words, kept consistent with the proof's leaf entries.
    entries: BTreeMap<AssetVaultKey, Word>,
}

impl AssetWitness {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AssetWitness`] from an SMT proof and a set of raw vault keys.
    ///
    /// For each key, looks up its hashed form in the proof and records the resulting value.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - any key's hashed form is not present in the proof.
    /// - any of the resulting `(vault_key, value)` pairs do not form a valid asset.
    pub fn new(
        proof: SmtProof,
        keys: impl IntoIterator<Item = AssetVaultKey>,
    ) -> Result<Self, AssetError> {
        let mut entries = BTreeMap::new();

        for key in keys {
            let value = proof
                .get(&key.hash().as_word())
                .ok_or(AssetError::AssetWitnessMissingKey { key })?;

            // Validate that the (key, value) pair forms a valid asset (and skip empty entries).
            if !value.is_empty() {
                Asset::from_key_value(key, value)
                    .map_err(|err| AssetError::AssetWitnessInvalid(Box::new(err)))?;
            }

            entries.insert(key, value);
        }

        Ok(Self { proof, entries })
    }

    /// Creates a new [`AssetWitness`] from an SMT proof and a set of key-value pairs without
    /// validating that the pairs form valid assets.
    ///
    /// Prefer [`AssetWitness::new`] whenever possible. See the type-level docs for the invariants
    /// callers must uphold.
    ///
    /// # Caller precondition
    ///
    /// For each `(key, value)` pair, `proof.get(&key.hash().as_word())` must return `Some(value)`.
    /// In other words, each provided pair must agree with what the proof asserts at the hashed
    /// key. Passing a mismatched pair lets downstream consumers of [`Self::find`] /
    /// [`Self::assets`] disagree with consumers of the underlying [`SmtProof`]. This
    /// precondition is checked in debug builds via [`debug_assert!`].
    pub fn new_unchecked(
        proof: SmtProof,
        key_values: impl IntoIterator<Item = (AssetVaultKey, Word)>,
    ) -> Self {
        let entries: BTreeMap<AssetVaultKey, Word> = key_values.into_iter().collect();

        #[cfg(debug_assertions)]
        for (key, value) in &entries {
            debug_assert_eq!(
                proof.get(&key.hash().as_word()),
                Some(*value),
                "AssetWitness::new_unchecked: (key, value) pair does not match the proof",
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

    /// Returns `true` if this [`AssetWitness`] authenticates the provided [`AssetVaultKey`], i.e.
    /// if its leaf index matches, `false` otherwise.
    pub fn authenticates_asset_vault_key(&self, vault_key: AssetVaultKey) -> bool {
        self.proof.leaf().index() == vault_key.to_leaf_index()
    }

    /// Searches for an [`Asset`] in the witness with the given `vault_key`.
    pub fn find(&self, vault_key: AssetVaultKey) -> Option<Asset> {
        let value = self.entries.get(&vault_key).copied()?;
        if value.is_empty() {
            None
        } else {
            Some(
                Asset::from_key_value(vault_key, value)
                    .expect("asset witness should track valid assets"),
            )
        }
    }

    /// Returns an iterator over the [`Asset`]s in this witness.
    pub fn assets(&self) -> impl Iterator<Item = Asset> + '_ {
        self.entries.iter().filter_map(|(key, value)| {
            if value.is_empty() {
                None
            } else {
                Some(
                    Asset::from_key_value(*key, *value)
                        .expect("asset witness should track valid assets"),
                )
            }
        })
    }

    /// Returns an iterator over the raw `(vault_key, value)` pairs tracked by this witness.
    pub(super) fn entries(&self) -> impl Iterator<Item = (&AssetVaultKey, &Word)> {
        self.entries.iter()
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
        let num_keys: usize = source.read()?;
        let keys: Vec<AssetVaultKey> = (0..num_keys)
            .map(|_| source.read::<AssetVaultKey>())
            .collect::<Result<_, _>>()?;

        Self::new(proof, keys).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::asset::{AssetVault, FungibleAsset, NonFungibleAsset};
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
    };

    /// Tests that constructing an asset witness fails if the (vault_key, value) pair stored in the
    /// proof is inconsistent (here: a non-fungible value under a fungible vault key).
    #[test]
    fn create_asset_witness_fails_on_vault_key_mismatch() -> anyhow::Result<()> {
        let fungible_asset = FungibleAsset::mock(500);
        let non_fungible_asset = NonFungibleAsset::mock(&[1]);

        // Manually build a proof at the fungible asset's hashed key but with a non-fungible value.
        let fungible_key = fungible_asset.vault_key();
        let inconsistent_smt = miden_crypto::merkle::smt::Smt::with_entries([(
            fungible_key.hash().as_word(),
            non_fungible_asset.to_value_word(),
        )])?;
        let proof = inconsistent_smt.open(&fungible_key.hash().as_word());

        let err = AssetWitness::new(proof, [fungible_key]).unwrap_err();

        assert_matches!(err, AssetError::AssetWitnessInvalid(source) => {
            assert_matches!(*source, AssetError::FungibleAssetValueMostSignificantElementsMustBeZero(_));
        });

        Ok(())
    }

    /// Tests that constructing an asset witness fails if the provided raw key is not actually
    /// present (in hashed form) in the SMT proof.
    #[test]
    fn create_asset_witness_fails_on_missing_key() -> anyhow::Result<()> {
        let asset_in_vault =
            FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3.try_into()?, 200)?;
        let other_key =
            FungibleAsset::new(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?, 100)?.vault_key();

        let vault = AssetVault::new(&[asset_in_vault.into()])?;
        let proof = vault.open(asset_in_vault.vault_key()).proof().clone();

        // The proof was opened at `asset_in_vault`'s hashed key, so a separate `other_key` won't
        // be found in it.
        let err = AssetWitness::new(proof, [other_key]).unwrap_err();
        assert_matches!(err, AssetError::AssetWitnessMissingKey { key } => {
            assert_eq!(key, other_key);
        });

        Ok(())
    }

    #[test]
    fn asset_witness_authenticates_asset_vault_key() -> anyhow::Result<()> {
        let fungible_asset0 =
            FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3.try_into()?, 200)?;
        let fungible_asset1 =
            FungibleAsset::new(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?, 100)?;

        let vault = AssetVault::new(&[fungible_asset0.into()])?;
        let witness0 = vault.open(fungible_asset0.vault_key());

        assert!(witness0.authenticates_asset_vault_key(fungible_asset0.vault_key()));
        assert!(!witness0.authenticates_asset_vault_key(fungible_asset1.vault_key()));

        Ok(())
    }
}
