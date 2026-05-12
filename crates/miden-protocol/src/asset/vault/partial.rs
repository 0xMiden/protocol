use alloc::collections::BTreeMap;
use alloc::string::ToString;

use miden_crypto::merkle::smt::{LeafIndex, PartialSmt, SMT_DEPTH, SmtLeaf, SmtProof};
use miden_crypto::merkle::{InnerNodeInfo, MerkleError};

use super::{AssetVault, AssetVaultKey};
use crate::Word;
use crate::asset::{Asset, AssetWitness};
use crate::errors::PartialAssetVaultError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// A partial representation of an [`AssetVault`], containing only proofs for a subset of assets.
///
/// Partial vault is used to provide verifiable access to specific assets in a vault
/// without the need to provide the full vault data. It contains all required data for loading
/// vault data into the transaction kernel for transaction execution.
///
/// ## Guarantees
///
/// This type guarantees that the raw key-value pairs it contains are all present in the contained
/// partial SMT (under their hashed form). Note that the inverse is not necessarily true: the SMT
/// may contain more entries than the map because to prove inclusion of a given raw key A an
/// [`SmtLeaf::Multiple`] may be present that contains both keys hash(A) and hash(B). However, B
/// may not be present in the key-value pairs and this is a valid state.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PartialVault {
    /// An SMT with a partial view into an account's full [`AssetVault`], keyed by hashed
    /// [`AssetVaultKey`]s.
    partial_smt: PartialSmt,
    /// Raw [`AssetVaultKey`]s -> asset value words, kept consistent with `partial_smt`.
    entries: BTreeMap<AssetVaultKey, Word>,
}

impl PartialVault {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a [`PartialVault`] from an [`AssetVault`] root.
    ///
    /// For conversion from an [`AssetVault`], prefer [`Self::new_minimal`] to be more explicit.
    pub fn new(root: Word) -> Self {
        PartialVault {
            partial_smt: PartialSmt::new(root),
            entries: BTreeMap::new(),
        }
    }

    /// Returns a new [`PartialVault`] with all provided witnesses added to it.
    pub fn with_witnesses(
        witnesses: impl IntoIterator<Item = AssetWitness>,
    ) -> Result<Self, PartialAssetVaultError> {
        let mut entries = BTreeMap::new();

        let partial_smt = PartialSmt::from_proofs(witnesses.into_iter().map(|witness| {
            entries.extend(witness.entries().map(|(key, value)| (*key, *value)));
            SmtProof::from(witness)
        }))
        .map_err(PartialAssetVaultError::FailedToAddProof)?;

        Ok(PartialVault { partial_smt, entries })
    }

    /// Converts an [`AssetVault`] into a partial vault representation.
    ///
    /// The resulting [`PartialVault`] will contain the _full_ merkle paths and entries of the
    /// original asset vault.
    pub fn new_full(vault: AssetVault) -> Self {
        let partial_smt = PartialSmt::from(vault.asset_tree);
        let entries = vault.entries;

        PartialVault { partial_smt, entries }
    }

    /// Converts an [`AssetVault`] into a partial vault representation.
    ///
    /// The resulting [`PartialVault`] will represent the root of the asset vault, but not track any
    /// key-value pairs, which means it is the most _minimal_ representation of the asset vault.
    pub fn new_minimal(vault: &AssetVault) -> Self {
        PartialVault::new(vault.root())
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the partial vault.
    pub fn root(&self) -> Word {
        self.partial_smt.root()
    }

    /// Returns an iterator over all inner nodes in the Sparse Merkle Tree proofs.
    ///
    /// This is useful for reconstructing parts of the Sparse Merkle Tree or for
    /// verification purposes.
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.partial_smt.inner_nodes()
    }

    /// Returns an iterator over all leaves of the underlying [`PartialSmt`].
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.partial_smt.leaves()
    }

    /// Returns an iterator over the raw `(vault_key, value)` pairs tracked by this partial vault.
    pub fn entries(&self) -> impl Iterator<Item = (&AssetVaultKey, &Word)> {
        self.entries.iter()
    }

    /// Returns an opening of the leaf associated with `vault_key`.
    ///
    /// The `vault_key` can be obtained with [`Asset::vault_key`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial vault.
    pub fn open(&self, vault_key: AssetVaultKey) -> Result<AssetWitness, PartialAssetVaultError> {
        let smt_proof = self
            .partial_smt
            .open(&vault_key.to_smt_key())
            .map_err(PartialAssetVaultError::UntrackedAsset)?;
        let value = self.entries.get(&vault_key).copied().unwrap_or_default();

        // SAFETY: The key-value pair is guaranteed to be present in the proof since we open its
        // hashed form, and the partial vault only tracks valid assets.
        Ok(AssetWitness::new_unchecked(smt_proof, [(vault_key, value)]))
    }

    /// Returns the [`Asset`] associated with the given `vault_key`.
    ///
    /// The return value is `None` if the asset does not exist in the vault.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get(&self, vault_key: AssetVaultKey) -> Result<Option<Asset>, MerkleError> {
        let value = self.partial_smt.get_value(&vault_key.to_smt_key())?;
        if value.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                Asset::from_key_value(vault_key, value)
                    .expect("partial vault should only track valid assets"),
            ))
        }
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds an [`AssetWitness`] to this [`PartialVault`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the new root after the insertion of the leaf and the path does not match the existing root
    ///   (except when the first leaf is added).
    pub fn add(&mut self, witness: AssetWitness) -> Result<(), PartialAssetVaultError> {
        self.entries.extend(witness.entries().map(|(key, value)| (*key, *value)));
        self.partial_smt
            .add_proof(SmtProof::from(witness))
            .map_err(PartialAssetVaultError::FailedToAddProof)
    }
}

impl Serializable for PartialVault {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.partial_smt);
        target.write_usize(self.entries.len());
        target.write_many(self.entries.keys());
    }
}

impl Deserializable for PartialVault {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let partial_smt: PartialSmt = source.read()?;
        let num_entries: usize = source.read()?;
        let mut entries = BTreeMap::new();

        for _ in 0..num_entries {
            let key: AssetVaultKey = source.read()?;
            let value = partial_smt.get_value(&key.to_smt_key()).map_err(|err| {
                DeserializationError::InvalidValue(alloc::format!(
                    "failed to find vault key {key} in partial SMT: {err}"
                ))
            })?;

            // Validate the (key, value) pair forms a valid asset (or is empty).
            if !value.is_empty() {
                Asset::from_key_value(key, value)
                    .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
            }

            entries.insert(key, value);
        }

        Ok(PartialVault { partial_smt, entries })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::asset::FungibleAsset;

    #[test]
    fn partial_vault_open_returns_correct_asset_after_full_conversion() -> anyhow::Result<()> {
        let asset = FungibleAsset::mock(500);
        let vault = AssetVault::new(&[asset])?;
        let partial = PartialVault::new_full(vault.clone());

        let key = asset.vault_key();
        let witness = partial.open(key)?;

        assert!(witness.authenticates_asset_vault_key(key));
        assert_eq!(witness.find(key), Some(asset));
        assert_eq!(partial.root(), vault.root());

        Ok(())
    }

    #[test]
    fn partial_vault_open_fails_for_untracked_key() -> anyhow::Result<()> {
        let asset = FungibleAsset::mock(500);
        let vault = AssetVault::new(&[asset])?;
        // `new_minimal` carries the root but no entries.
        let partial = PartialVault::new_minimal(&vault);

        let err = partial.open(asset.vault_key()).unwrap_err();
        assert_matches!(err, PartialAssetVaultError::UntrackedAsset(_));

        Ok(())
    }
}
