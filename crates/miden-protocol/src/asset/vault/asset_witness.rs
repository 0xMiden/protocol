use alloc::string::ToString;

use miden_crypto::merkle::InnerNodeInfo;
use miden_crypto::merkle::smt::{SmtLeaf, SmtProof};

use super::vault_key::AssetVaultKey;
use crate::asset::Asset;
use crate::errors::AssetError;
use crate::utils::serde::{Deserializable, DeserializationError, Serializable};

/// A witness of an asset in an [`AssetVault`](super::AssetVault).
///
/// It proves inclusion of a certain asset in the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetWitness(SmtProof);

impl AssetWitness {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AssetWitness`] from an SMT proof.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - any of the entries in the SMT leaf is not a valid asset.
    /// - any of the entries' vault keys does not match the expected vault key of the asset.
    pub fn new(smt_proof: SmtProof) -> Result<Self, AssetError> {
        for (vault_key, asset) in smt_proof.leaf().entries() {
            let asset = Asset::try_from(asset)?;
            if *vault_key != asset.vault_key().into() {
                return Err(AssetError::AssetVaultKeyMismatch {
                    actual: *vault_key,
                    expected: asset.vault_key().into(),
                });
            }
        }

        Ok(Self(smt_proof))
    }

    /// Creates a new [`AssetWitness`] from an SMT proof without checking that the proof contains
    /// valid assets.
    ///
    /// Prefer [`AssetWitness::new`] whenever possible.
    pub fn new_unchecked(smt_proof: SmtProof) -> Self {
        Self(smt_proof)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns `true` if this [`AssetWitness`] authenticates the provided [`AssetVaultKey`], i.e.
    /// if its leaf index matches, `false` otherwise.
    pub fn authenticates_asset_vault_key(&self, vault_key: AssetVaultKey) -> bool {
        self.0.leaf().index() == vault_key.to_leaf_index()
    }

    /// Searches for an [`Asset`] in the witness with the given `vault_key`.
    pub fn find(&self, vault_key: AssetVaultKey) -> Option<Asset> {
        self.assets().find(|asset| asset.vault_key() == vault_key)
    }

    /// Returns an iterator over the [`Asset`]s in this witness.
    pub fn assets(&self) -> impl Iterator<Item = Asset> {
        // TODO: Avoid cloning the vector by not calling SmtLeaf::entries.
        // Once SmtLeaf::entries returns a slice (i.e. once
        // https://github.com/0xMiden/crypto/pull/521 is available), replace this match statement.
        let entries = match self.0.leaf() {
            SmtLeaf::Empty(_) => &[],
            SmtLeaf::Single(kv_pair) => core::slice::from_ref(kv_pair),
            SmtLeaf::Multiple(kv_pairs) => kv_pairs,
        };

        entries.iter().map(|(_key, value)| {
            Asset::try_from(value).expect("asset witness should track valid assets")
        })
    }

    /// Returns an iterator over every inner node of this witness' merkle path.
    pub fn authenticated_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.0
            .path()
            .authenticated_nodes(self.0.leaf().index().value(), self.0.leaf().hash())
            .expect("leaf index is u64 and should be less than 2^SMT_DEPTH")
    }
}

impl From<AssetWitness> for SmtProof {
    fn from(witness: AssetWitness) -> Self {
        witness.0
    }
}

impl Serializable for AssetWitness {
    fn write_into<W: miden_core::utils::ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }
}

impl Deserializable for AssetWitness {
    fn read_from<R: miden_core::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let proof = SmtProof::read_from(source)?;
        Self::new(proof).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_crypto::merkle::smt::Smt;

    use super::*;
    use crate::Word;
    use crate::asset::{AssetVault, FungibleAsset, NonFungibleAsset};
    use crate::testing::account_id::{
        ACCOUNT_ID_NETWORK_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
    };

    /// Tests that constructing an asset witness fails if any asset in the smt proof is invalid.
    #[test]
    fn create_asset_witness_fails_on_invalid_asset() -> anyhow::Result<()> {
        let invalid_asset = Word::from([0, 0, 0, 5u32]);
        let smt = Smt::with_entries([(invalid_asset, invalid_asset)])?;
        let proof = smt.open(&invalid_asset);

        let err = AssetWitness::new(proof).unwrap_err();

        assert_matches!(err, AssetError::InvalidFaucetAccountId(_));

        Ok(())
    }

    /// Tests that constructing an asset witness fails if the vault key is from a fungible asset and
    /// the asset is a non-fungible one.
    #[test]
    fn create_asset_witness_fails_on_vault_key_mismatch() -> anyhow::Result<()> {
        let fungible_asset = FungibleAsset::mock(500);
        let non_fungible_asset = NonFungibleAsset::mock(&[1]);

        let smt =
            Smt::with_entries([(fungible_asset.vault_key().into(), non_fungible_asset.into())])?;
        let proof = smt.open(&fungible_asset.vault_key().into());

        let err = AssetWitness::new(proof).unwrap_err();

        assert_matches!(err, AssetError::AssetVaultKeyMismatch { actual, expected } => {
            assert_eq!(actual, fungible_asset.vault_key().into());
            assert_eq!(expected, non_fungible_asset.vault_key().into());
        });

        Ok(())
    }

    #[test]
    fn asset_witness_authenticates_asset_vault_key() -> anyhow::Result<()> {
        let fungible_asset0 =
            FungibleAsset::new(ACCOUNT_ID_NETWORK_FUNGIBLE_FAUCET.try_into()?, 200)?;
        let fungible_asset1 =
            FungibleAsset::new(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?, 100)?;

        let vault = AssetVault::new(&[fungible_asset0.into()])?;
        let witness0 = vault.open(fungible_asset0.vault_key());

        assert!(witness0.authenticates_asset_vault_key(fungible_asset0.vault_key()));
        assert!(!witness0.authenticates_asset_vault_key(fungible_asset1.vault_key()));

        Ok(())
    }
}
