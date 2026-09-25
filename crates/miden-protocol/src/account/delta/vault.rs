use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::string::ToString;
use alloc::vec::Vec;

use super::{
    AccountDeltaError,
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::account::delta::AssetDeltaOperation;
use crate::asset::{Asset, AssetId};
use crate::{Felt, Word};

// ASSET DELTA
// ================================================================================================

/// The change of a single asset in an [`AccountVaultDelta`].
///
/// The asset is the magnitude of the change while the operation gives its direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetDelta {
    delta_op: AssetDeltaOperation,
    asset: Asset,
}

impl AssetDelta {
    /// Creates a new [`AssetDelta`] by which the vault changed under the given operation.
    pub fn new(delta_op: AssetDeltaOperation, asset: Asset) -> Self {
        Self { delta_op, asset }
    }

    /// Returns the operation of this delta.
    pub fn delta_op(&self) -> AssetDeltaOperation {
        self.delta_op
    }

    /// Returns the asset by which the vault changed.
    pub fn asset(&self) -> Asset {
        self.asset
    }

    /// Returns the ID of the asset by which the vault changed.
    pub fn asset_id(&self) -> AssetId {
        self.asset.id()
    }
}

// ACCOUNT VAULT DELTA
// ================================================================================================

/// [`AccountVaultDelta`] stores the difference between the initial and final account vault states.
///
/// The difference is represented as a map of [`AssetDelta`]s keyed by the ID of the asset they
/// change. The [`AssetId`] orders the assets in the same way as the in-kernel account delta.
///
/// ## Purpose
///
/// The purpose of a vault delta is to represent the changes to the vault that a transaction results
/// in and provide a way to commit to and sign these changes. Unlike an
/// [`AccountVaultPatch`](crate::account::AccountVaultPatch), a delta cannot be applied to an
/// account and multiple deltas cannot be merged, since that isn't necessary for signing.
///
/// ## Limitations
///
/// The delta does not include the functionality to merge or split assets. This would mainly be
/// needed to merge deltas, which isn't supported. Additionally, once custom assets are supported,
/// their merge and split logic will be defined in the issuing faucet, and the delta would not be
/// able to (easily) invoke this logic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountVaultDelta {
    delta: BTreeMap<AssetId, AssetDelta>,
}

impl AccountVaultDelta {
    /// Domain separator for assets in delta and patch commitments.
    pub(in crate::account) const DOMAIN: Felt = Felt::new_unchecked(1);

    /// Maximum number of added or removed assets in a vault delta.
    pub const MAX_ASSETS_PER_DELTA_OP: u16 = 1024;

    /// Validates and creates an [`AccountVaultDelta`] from the given asset deltas.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the same asset is changed by more than one delta.
    /// - the number of added or removed assets exceeds [`Self::MAX_ASSETS_PER_DELTA_OP`].
    pub fn new(
        asset_deltas: impl IntoIterator<Item = AssetDelta>,
    ) -> Result<Self, AccountDeltaError> {
        let mut delta = BTreeMap::new();
        let mut num_added_assets = 0usize;
        let mut num_removed_assets = 0usize;

        for asset_delta in asset_deltas {
            match asset_delta.delta_op() {
                AssetDeltaOperation::Add => num_added_assets += 1,
                AssetDeltaOperation::Remove => num_removed_assets += 1,
            }

            match delta.entry(asset_delta.asset_id()) {
                Entry::Vacant(entry) => {
                    entry.insert(asset_delta);
                },
                Entry::Occupied(_) => {
                    return Err(AccountDeltaError::DuplicateAssetDelta(asset_delta.asset_id()));
                },
            }
        }

        Self::validate_asset_count(AssetDeltaOperation::Add, num_added_assets)?;
        Self::validate_asset_count(AssetDeltaOperation::Remove, num_removed_assets)?;

        Ok(Self { delta })
    }

    /// Returns true if this vault delta contains no updates.
    pub fn is_empty(&self) -> bool {
        self.delta.is_empty()
    }

    /// Returns the number of assets changed in this delta.
    pub fn num_assets(&self) -> usize {
        self.delta.len()
    }

    /// Returns an iterator over the asset deltas, sorted by asset ID.
    pub fn iter(&self) -> impl Iterator<Item = &AssetDelta> {
        self.delta.values()
    }

    /// Returns an iterator over the added assets in this delta.
    pub fn added_assets(&self) -> impl Iterator<Item = Asset> + '_ {
        self.filter_by_op(AssetDeltaOperation::Add)
    }

    /// Returns an iterator over the removed assets in this delta.
    pub fn removed_assets(&self) -> impl Iterator<Item = Asset> + '_ {
        self.filter_by_op(AssetDeltaOperation::Remove)
    }

    /// Appends the vault delta to the given `elements` from which the delta commitment will be
    /// computed.
    pub(super) fn append_delta_elements(&self, elements: &mut Vec<Felt>) {
        self.append_asset_section(AssetDeltaOperation::Add, elements);
        self.append_asset_section(AssetDeltaOperation::Remove, elements);
    }

    // HELPER FUNCTIONS
    // ---------------------------------------------------------------------------------------------

    /// Returns the number of assets changed by the given operation.
    ///
    /// The count fits in a `u16` since it is bounded by [`Self::MAX_ASSETS_PER_DELTA_OP`].
    fn num_assets_by_op(&self, delta_op: AssetDeltaOperation) -> u16 {
        let num_assets = self.filter_by_op(delta_op).count();
        u16::try_from(num_assets).expect("number of changed assets is validated on construction")
    }

    /// Counts the number of added assets.
    fn num_added_assets(&self) -> u16 {
        self.num_assets_by_op(AssetDeltaOperation::Add)
    }

    /// Counts the number of removed assets.
    fn num_removed_assets(&self) -> u16 {
        self.num_assets_by_op(AssetDeltaOperation::Remove)
    }

    /// Returns an error if the given number of assets exceeds
    /// [`Self::MAX_ASSETS_PER_DELTA_OP`].
    fn validate_asset_count(
        delta_op: AssetDeltaOperation,
        num_ops: usize,
    ) -> Result<(), AccountDeltaError> {
        if num_ops > usize::from(Self::MAX_ASSETS_PER_DELTA_OP) {
            return Err(AccountDeltaError::TooManyVaultAssetDeltas { delta_op, num_ops });
        }

        Ok(())
    }

    /// Returns an iterator over all assets that were changed by the provided operation.
    fn filter_by_op(&self, delta_op: AssetDeltaOperation) -> impl Iterator<Item = Asset> + '_ {
        self.delta
            .values()
            .filter(move |asset_delta| asset_delta.delta_op() == delta_op)
            .map(AssetDelta::asset)
    }

    /// Appends the assets changed by the provided operation, followed by the section's trailer.
    ///
    /// The trailer is omitted if the operation did not change any asset.
    fn append_asset_section(&self, delta_op: AssetDeltaOperation, elements: &mut Vec<Felt>) {
        let mut num_changed_assets = 0;
        for asset in self.filter_by_op(delta_op) {
            elements.extend_from_slice(&asset.as_elements());
            num_changed_assets += 1;
        }

        if num_changed_assets != 0 {
            let num_changed_assets = Felt::try_from(num_changed_assets as u64)
                .expect("number of changed assets should not exceed max representable felt");

            elements.extend_from_slice(&[
                Self::DOMAIN,
                Felt::from(delta_op.as_u8()),
                num_changed_assets,
                Felt::ZERO,
            ]);
            elements.extend_from_slice(Word::empty().as_elements());
        }
    }
}

impl Serializable for AccountVaultDelta {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.num_added_assets());
        target.write_many(self.added_assets());

        target.write(self.num_removed_assets());
        target.write_many(self.removed_assets());
    }

    fn get_size_hint(&self) -> usize {
        let added_size: usize = self.added_assets().map(|asset| asset.get_size_hint()).sum();
        let removed_size: usize = self.removed_assets().map(|asset| asset.get_size_hint()).sum();

        2 * 0u16.get_size_hint() + added_size + removed_size
    }
}

impl Deserializable for AccountVaultDelta {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_added_assets: u16 = source.read()?;
        if num_added_assets > Self::MAX_ASSETS_PER_DELTA_OP {
            return Err(DeserializationError::InvalidValue(
                AccountDeltaError::TooManyVaultAssetDeltas {
                    delta_op: AssetDeltaOperation::Add,
                    num_ops: usize::from(num_added_assets),
                }
                .to_string(),
            ));
        }

        // The capacity is not reserved upfront since the number of assets is not yet validated
        // against the remaining bytes at this point.
        let mut asset_deltas = Vec::new();
        for asset in source.read_many_iter::<Asset>(usize::from(num_added_assets))? {
            asset_deltas.push(AssetDelta::new(AssetDeltaOperation::Add, asset?));
        }

        let num_removed_assets: u16 = source.read()?;
        if num_removed_assets > Self::MAX_ASSETS_PER_DELTA_OP {
            return Err(DeserializationError::InvalidValue(
                AccountDeltaError::TooManyVaultAssetDeltas {
                    delta_op: AssetDeltaOperation::Remove,
                    num_ops: usize::from(num_removed_assets),
                }
                .to_string(),
            ));
        }
        for asset in source.read_many_iter::<Asset>(usize::from(num_removed_assets))? {
            asset_deltas.push(AssetDelta::new(AssetDeltaOperation::Remove, asset?));
        }

        Self::new(asset_deltas).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::{AccountVaultDelta, Deserializable, DeserializationError, Serializable};
    use crate::account::delta::AssetDeltaOperation;
    use crate::account::{AccountId, AssetDelta};
    use crate::asset::{Asset, FungibleAsset, NonFungibleAsset};
    use crate::errors::AccountDeltaError;
    use crate::utils::serde::ByteWriter;

    #[test]
    fn account_vault_delta_serde() -> anyhow::Result<()> {
        let empty_delta = AccountVaultDelta::default();
        assert!(empty_delta.is_empty());
        let serialized = empty_delta.to_bytes();
        assert_eq!(AccountVaultDelta::read_from_bytes(&serialized)?, empty_delta);
        assert_eq!(empty_delta.get_size_hint(), serialized.len());

        let delta = AccountVaultDelta::from_iters(
            [FungibleAsset::mock(100), NonFungibleAsset::mock(&[10, 21, 32, 43])],
            [NonFungibleAsset::mock(&[54, 65])],
        );
        assert!(!delta.is_empty());

        let serialized = delta.to_bytes();
        assert_eq!(AccountVaultDelta::read_from_bytes(&serialized)?, delta);
        assert_eq!(delta.get_size_hint(), serialized.len());

        Ok(())
    }

    fn generate_asset_deltas(delta_op: AssetDeltaOperation, num_deltas: usize) -> Vec<AssetDelta> {
        (0..num_deltas)
            .map(|_| {
                let asset =
                    FungibleAsset::new(AccountId::builder().build_with_seed(rand::random()), 42)
                        .unwrap();
                AssetDelta::new(delta_op, Asset::from(asset))
            })
            .collect::<Vec<_>>()
    }

    #[rstest]
    #[case::add(AssetDeltaOperation::Add)]
    #[case::remove(AssetDeltaOperation::Remove)]
    fn account_vault_delta_accepts_max_num_changed_assets(
        #[case] expected_delta_op: AssetDeltaOperation,
    ) -> anyhow::Result<()> {
        let asset_deltas = generate_asset_deltas(
            expected_delta_op,
            usize::from(AccountVaultDelta::MAX_ASSETS_PER_DELTA_OP),
        );

        AccountVaultDelta::new(asset_deltas)?;

        Ok(())
    }

    #[rstest]
    #[case::add(AssetDeltaOperation::Add)]
    #[case::remove(AssetDeltaOperation::Remove)]
    fn account_vault_delta_rejects_more_than_max_num_changed_assets(
        #[case] expected_delta_op: AssetDeltaOperation,
    ) -> anyhow::Result<()> {
        let expected_num_ops = usize::from(AccountVaultDelta::MAX_ASSETS_PER_DELTA_OP) + 1;
        let asset_deltas = generate_asset_deltas(expected_delta_op, expected_num_ops);

        let err = AccountVaultDelta::new(asset_deltas).unwrap_err();
        assert_matches!(err, AccountDeltaError::TooManyVaultAssetDeltas { delta_op, num_ops } => {
            assert_eq!(delta_op, expected_delta_op);
            assert_eq!(num_ops, expected_num_ops);
        });

        Ok(())
    }

    /// The same asset must not be changed by two deltas, since the delta could not represent both.
    #[test]
    fn account_vault_delta_rejects_duplicate_asset() -> anyhow::Result<()> {
        let asset = NonFungibleAsset::mock(&[10, 21, 32, 43]);
        let asset_deltas = [
            AssetDelta::new(AssetDeltaOperation::Add, asset),
            AssetDelta::new(AssetDeltaOperation::Remove, asset),
        ];

        let err = AccountVaultDelta::new(asset_deltas).unwrap_err();
        assert_matches!(err, AccountDeltaError::DuplicateAssetDelta(asset_id) => {
            assert_eq!(asset_id, asset.id());
        });

        Ok(())
    }

    /// A crafted byte stream that changes the same asset in both the added and the removed section
    /// must be rejected rather than silently collapsing into a single entry.
    #[test]
    fn account_vault_delta_deserialization_rejects_duplicate_asset() -> anyhow::Result<()> {
        let asset = NonFungibleAsset::mock(&[10, 21, 32, 43]);

        let mut bytes = Vec::new();
        bytes.write(1u16);
        bytes.write(asset);
        bytes.write(1u16);
        bytes.write(asset);

        let error = AccountVaultDelta::read_from_bytes(&bytes)
            .expect_err("delta with a duplicate asset should not deserialize");

        let expected = AccountDeltaError::DuplicateAssetDelta(asset.id()).to_string();
        assert_matches!(error, DeserializationError::InvalidValue(message) if message == expected);

        Ok(())
    }
}
