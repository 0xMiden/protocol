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

    /// Constructs a [`PartialVault`] from a [`PartialSmt`] and the raw [`AssetVaultKey`]s whose
    /// values are looked up from the SMT.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - any key's hashed form is not present in the partial SMT.
    /// - any of the resulting `(vault_key, value)` pairs does not form a valid asset.
    fn from_partial_smt_and_keys(
        partial_smt: PartialSmt,
        keys: impl IntoIterator<Item = AssetVaultKey>,
    ) -> Result<Self, PartialAssetVaultError> {
        let mut entries = BTreeMap::new();

        for key in keys {
            let value = partial_smt
                .get_value(&key.hash().as_word())
                .map_err(PartialAssetVaultError::UntrackedAsset)?;

            if !value.is_empty() {
                Asset::from_key_value(key, value).map_err(|source| {
                    PartialAssetVaultError::InvalidAssetForKey { key, value, source }
                })?;
            }

            entries.insert(key, value);
        }

        Ok(Self { partial_smt, entries })
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
            .open(&vault_key.hash().as_word())
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
        let value = self.partial_smt.get_value(&vault_key.hash().as_word())?;
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
        // Collect entries first so that, if `add_proof` fails, no partial state escapes into
        // `self.entries`. The type-level guarantee (entries are a subset of partial_smt) must
        // hold even after an error.
        let new_entries: alloc::vec::Vec<_> =
            witness.entries().map(|(key, value)| (*key, *value)).collect();
        self.partial_smt
            .add_proof(SmtProof::from(witness))
            .map_err(PartialAssetVaultError::FailedToAddProof)?;
        self.entries.extend(new_entries);
        Ok(())
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
        let keys = source
            .read_many_iter::<AssetVaultKey>(num_entries)?
            .collect::<Result<alloc::vec::Vec<_>, _>>()?;

        Self::from_partial_smt_and_keys(partial_smt, keys)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use assert_matches::assert_matches;

    use super::*;
    use crate::asset::{FungibleAsset, NonFungibleAsset};
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET;

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

    #[test]
    fn partial_vault_with_witnesses_round_trips() -> anyhow::Result<()> {
        let fungible = FungibleAsset::mock(500);
        let non_fungible = NonFungibleAsset::mock(&[1, 2, 3]);
        let vault = AssetVault::new(&[fungible, non_fungible])?;

        let witnesses = [vault.open(fungible.vault_key()), vault.open(non_fungible.vault_key())];
        let partial = PartialVault::with_witnesses(witnesses)?;

        assert_eq!(partial.root(), vault.root());
        assert_eq!(partial.entries().count(), 2);

        // Round-trip serialization preserves equality.
        let bytes = partial.to_bytes();
        let roundtripped = PartialVault::read_from_bytes(&bytes)?;
        assert_eq!(partial, roundtripped);

        Ok(())
    }

    #[test]
    fn partial_vault_with_witnesses_fails_on_root_mismatch() -> anyhow::Result<()> {
        // Two single-asset vaults rooted at different SMT roots.
        let asset_a = FungibleAsset::mock(500);
        let asset_b: Asset =
            FungibleAsset::new(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?, 100)?.into();
        let vault_a = AssetVault::new(&[asset_a])?;
        let vault_b = AssetVault::new(&[asset_b])?;
        assert_ne!(vault_a.root(), vault_b.root());

        let witness_a = vault_a.open(asset_a.vault_key());
        let witness_b = vault_b.open(asset_b.vault_key());

        let err = PartialVault::with_witnesses([witness_a, witness_b]).unwrap_err();
        assert_matches!(err, PartialAssetVaultError::FailedToAddProof(_));

        Ok(())
    }

    #[test]
    fn partial_vault_add_extends_with_new_witness() -> anyhow::Result<()> {
        let fungible = FungibleAsset::mock(500);
        let non_fungible = NonFungibleAsset::mock(&[7, 8, 9]);
        let vault = AssetVault::new(&[fungible, non_fungible])?;

        let mut partial = PartialVault::with_witnesses([vault.open(fungible.vault_key())])?;
        assert_eq!(partial.entries().count(), 1);

        partial.add(vault.open(non_fungible.vault_key()))?;

        assert_eq!(partial.root(), vault.root());
        assert_eq!(partial.entries().count(), 2);
        assert_eq!(partial.open(fungible.vault_key())?.find(fungible.vault_key()), Some(fungible));
        assert_eq!(
            partial.open(non_fungible.vault_key())?.find(non_fungible.vault_key()),
            Some(non_fungible),
        );

        Ok(())
    }

    #[test]
    fn partial_vault_add_is_atomic_on_failure() -> anyhow::Result<()> {
        // Build two distinct vaults so the second witness's root disagrees with the first.
        let asset_a = FungibleAsset::mock(500);
        let asset_b: Asset =
            FungibleAsset::new(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?, 100)?.into();
        let vault_a = AssetVault::new(&[asset_a])?;
        let vault_b = AssetVault::new(&[asset_b])?;

        let mut partial = PartialVault::with_witnesses([vault_a.open(asset_a.vault_key())])?;
        let entries_before: Vec<_> = partial.entries().map(|(k, v)| (*k, *v)).collect();
        let root_before = partial.root();

        let err = partial.add(vault_b.open(asset_b.vault_key())).unwrap_err();
        assert_matches!(err, PartialAssetVaultError::FailedToAddProof(_));

        // Atomicity: failed `add` must not leak entries or shift the root.
        let entries_after: Vec<_> = partial.entries().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(entries_before, entries_after);
        assert_eq!(partial.root(), root_before);

        Ok(())
    }
}
