use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::string::ToString;
use alloc::vec::Vec;

use miden_core::Word;

use super::{
    AccountDeltaError,
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::Felt;
use crate::account::delta::AssetDeltaOperation;
use crate::asset::{Asset, AssetVaultKey, FungibleAsset, NonFungibleAsset};

// ACCOUNT VAULT DELTA
// ================================================================================================

/// [AccountVaultDelta] stores the difference between the initial and final account vault states.
///
/// The difference is represented as follows:
/// - fungible: a binary tree map of fungible asset balance changes in the account vault.
/// - non_fungible: a binary tree map of non-fungible assets that were added to or removed from the
///   account vault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountVaultDelta {
    fungible: FungibleAssetDelta,
    non_fungible: NonFungibleAssetDelta,
}

impl AccountVaultDelta {
    /// Domain separator for assets in the account delta commitment.
    pub(in crate::account) const DOMAIN: Felt = Felt::new_unchecked(3);

    /// Validates and creates an [AccountVaultDelta] with the given fungible and non-fungible asset
    /// deltas.
    ///
    /// # Errors
    /// Returns an error if the delta does not pass the validation.
    pub const fn new(fungible: FungibleAssetDelta, non_fungible: NonFungibleAssetDelta) -> Self {
        Self { fungible, non_fungible }
    }

    /// Returns a reference to the fungible asset delta.
    pub fn fungible(&self) -> &FungibleAssetDelta {
        &self.fungible
    }

    /// Returns a reference to the non-fungible asset delta.
    pub fn non_fungible(&self) -> &NonFungibleAssetDelta {
        &self.non_fungible
    }

    /// Returns true if this vault delta contains no updates.
    pub fn is_empty(&self) -> bool {
        self.fungible.is_empty() && self.non_fungible.is_empty()
    }

    /// Tracks asset addition.
    pub fn add_asset(&mut self, asset: Asset) -> Result<(), AccountDeltaError> {
        match asset {
            Asset::Fungible(asset) => self.fungible.add(asset),
            Asset::NonFungible(asset) => self.non_fungible.add(asset),
        }
    }

    /// Tracks asset removal.
    pub fn remove_asset(&mut self, asset: Asset) -> Result<(), AccountDeltaError> {
        match asset {
            Asset::Fungible(asset) => self.fungible.remove(asset),
            Asset::NonFungible(asset) => self.non_fungible.remove(asset),
        }
    }

    /// Returns an iterator over the added assets in this delta.
    pub fn added_assets(&self) -> impl Iterator<Item = crate::asset::Asset> + '_ {
        self.fungible
            .0
            .iter()
            .filter(|&(_, &value)| value >= 0)
            .map(|(vault_key, &diff)| {
                Asset::Fungible(
                    FungibleAsset::new(vault_key.faucet_id(), diff.unsigned_abs())
                        .unwrap()
                        .with_callbacks(vault_key.callback_flag()),
                )
            })
            .chain(
                self.non_fungible
                    .filter_by_action(NonFungibleDeltaAction::Add)
                    .map(Asset::NonFungible),
            )
    }

    /// Returns an iterator over the removed assets in this delta.
    pub fn removed_assets(&self) -> impl Iterator<Item = crate::asset::Asset> + '_ {
        self.fungible
            .0
            .iter()
            .filter(|&(_, &value)| value < 0)
            .map(|(vault_key, &diff)| {
                Asset::Fungible(
                    FungibleAsset::new(vault_key.faucet_id(), diff.unsigned_abs())
                        .unwrap()
                        .with_callbacks(vault_key.callback_flag()),
                )
            })
            .chain(
                self.non_fungible
                    .filter_by_action(NonFungibleDeltaAction::Remove)
                    .map(Asset::NonFungible),
            )
    }

    /// Appends the vault delta to the given `elements` from which the delta commitment will be
    /// computed.
    pub(super) fn append_delta_elements(&self, elements: &mut Vec<Felt>) {
        // Add added and removed assets to a map to sort by vault key.

        // TODO(unified_delta): Refactor the internal asset delta structure to match the tx kernel
        // internals and to make this extra allocation unnecessary.
        let added_assets = BTreeMap::from_iter(
            self.added_assets().map(|asset| (asset.vault_key(), asset.to_value_word())),
        );
        let removed_assets = BTreeMap::from_iter(
            self.removed_assets().map(|asset| (asset.vault_key(), asset.to_value_word())),
        );

        Self::add_asset_section(AssetDeltaOperation::Add, added_assets, elements);
        Self::add_asset_section(AssetDeltaOperation::Remove, removed_assets, elements);
    }

    fn add_asset_section(
        delta_op: AssetDeltaOperation,
        assets: BTreeMap<AssetVaultKey, Word>,
        elements: &mut Vec<Felt>,
    ) {
        let num_changed_assets = assets.len();
        for (asset_vault_key, asset_value) in assets {
            elements.extend_from_slice(asset_vault_key.to_word().as_elements());
            elements.extend_from_slice(asset_value.as_elements());
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

#[cfg(any(feature = "testing", test))]
impl AccountVaultDelta {
    /// Creates an [AccountVaultDelta] from the given iterators.
    pub fn from_iters(
        added_assets: impl IntoIterator<Item = crate::asset::Asset>,
        removed_assets: impl IntoIterator<Item = crate::asset::Asset>,
    ) -> Self {
        let mut fungible = FungibleAssetDelta::default();
        let mut non_fungible = NonFungibleAssetDelta::default();

        for asset in added_assets {
            match asset {
                Asset::Fungible(asset) => {
                    fungible.add(asset).unwrap();
                },
                Asset::NonFungible(asset) => {
                    non_fungible.add(asset).unwrap();
                },
            }
        }

        for asset in removed_assets {
            match asset {
                Asset::Fungible(asset) => {
                    fungible.remove(asset).unwrap();
                },
                Asset::NonFungible(asset) => {
                    non_fungible.remove(asset).unwrap();
                },
            }
        }

        Self { fungible, non_fungible }
    }
}

impl Serializable for AccountVaultDelta {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.fungible);
        target.write(&self.non_fungible);
    }

    fn get_size_hint(&self) -> usize {
        self.fungible.get_size_hint() + self.non_fungible.get_size_hint()
    }
}

impl Deserializable for AccountVaultDelta {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let fungible = source.read()?;
        let non_fungible = source.read()?;

        Ok(Self::new(fungible, non_fungible))
    }
}

// FUNGIBLE ASSET DELTA
// ================================================================================================

/// A binary tree map of fungible asset balance changes in the account vault.
///
/// The [`AssetVaultKey`] orders the assets in the same way as the in-kernel account delta which
/// uses a link map.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FungibleAssetDelta(BTreeMap<AssetVaultKey, i64>);

impl FungibleAssetDelta {
    /// Validates and creates a new fungible asset delta.
    ///
    /// # Errors
    /// Returns an error if the delta does not pass the validation.
    pub fn new(map: BTreeMap<AssetVaultKey, i64>) -> Result<Self, AccountDeltaError> {
        Self::validate(&map)?;

        Ok(Self(map))
    }

    /// Adds a new fungible asset to the delta.
    ///
    /// # Errors
    /// Returns an error if the delta would overflow.
    pub fn add(&mut self, asset: FungibleAsset) -> Result<(), AccountDeltaError> {
        let amount: i64 = asset.amount().as_i64();
        self.add_delta(asset.vault_key(), amount)
    }

    /// Removes a fungible asset from the delta.
    ///
    /// # Errors
    /// Returns an error if the delta would overflow.
    pub fn remove(&mut self, asset: FungibleAsset) -> Result<(), AccountDeltaError> {
        let amount: i64 = asset.amount().as_i64();
        self.add_delta(asset.vault_key(), -amount)
    }

    /// Returns the amount of the fungible asset with the given vault key.
    pub fn amount(&self, vault_key: &AssetVaultKey) -> Option<i64> {
        self.0.get(vault_key).copied()
    }

    /// Returns the number of fungible assets affected in the delta.
    pub fn num_assets(&self) -> usize {
        self.0.len()
    }

    /// Returns true if this vault delta contains no updates.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the (key, value) pairs of the map.
    pub fn iter(&self) -> impl Iterator<Item = (&AssetVaultKey, &i64)> {
        self.0.iter()
    }

    // HELPER FUNCTIONS
    // ---------------------------------------------------------------------------------------------

    /// Updates the provided map with the provided key and amount. If the final amount is 0,
    /// the entry is removed.
    ///
    /// # Errors
    /// Returns an error if the delta would overflow.
    fn add_delta(&mut self, vault_key: AssetVaultKey, delta: i64) -> Result<(), AccountDeltaError> {
        match self.0.entry(vault_key) {
            Entry::Vacant(entry) => {
                // Only track non-zero amounts.
                if delta != 0 {
                    entry.insert(delta);
                }
            },
            Entry::Occupied(mut entry) => {
                let old = *entry.get();
                let new = old.checked_add(delta).ok_or(
                    AccountDeltaError::FungibleAssetDeltaOverflow {
                        faucet_id: vault_key.faucet_id(),
                        current: old,
                        delta,
                    },
                )?;

                if new == 0 {
                    entry.remove();
                } else {
                    *entry.get_mut() = new;
                }
            },
        }

        Ok(())
    }

    /// Checks whether this vault delta is valid.
    ///
    /// # Errors
    /// Returns an error if one or more fungible assets' faucet IDs are invalid.
    fn validate(map: &BTreeMap<AssetVaultKey, i64>) -> Result<(), AccountDeltaError> {
        for vault_key in map.keys() {
            if !vault_key.composition().is_fungible() {
                return Err(AccountDeltaError::NotAFungibleFaucetId(vault_key.faucet_id()));
            }
        }

        Ok(())
    }
}

impl Serializable for FungibleAssetDelta {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.0.len());
        // TODO: We save `i64` as `u64` since winter utils only supports unsigned integers for now.
        //   We should update this code (and deserialization as well) once it supports signed
        //   integers.
        // TODO: If we keep this code, optimize by not serializing asset ID (which is always 0).
        target.write_many(self.0.iter().map(|(vault_key, &delta)| (*vault_key, delta as u64)));
    }

    fn get_size_hint(&self) -> usize {
        const ENTRY_SIZE: usize = AssetVaultKey::SERIALIZED_SIZE + core::mem::size_of::<u64>();
        self.0.len().get_size_hint() + self.0.len() * ENTRY_SIZE
    }
}

impl Deserializable for FungibleAssetDelta {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_fungible_assets = source.read_usize()?;
        // TODO: We save `i64` as `u64` since winter utils only supports unsigned integers for now.
        //   We should update this code (and serialization as well) once it supports signed
        //   integers.
        let map = source
            .read_many_iter::<(AssetVaultKey, u64)>(num_fungible_assets)?
            .map(|result| result.map(|(vault_key, delta_as_u64)| (vault_key, delta_as_u64 as i64)))
            .collect::<Result<_, _>>()?;

        Self::new(map).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// NON-FUNGIBLE ASSET DELTA
// ================================================================================================

/// A binary tree map of non-fungible asset changes (addition and removal) in the account vault.
///
/// The [`AssetVaultKey`] orders the assets in the same way as the in-kernel account delta which
/// uses a link map.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NonFungibleAssetDelta(
    BTreeMap<AssetVaultKey, (NonFungibleAsset, NonFungibleDeltaAction)>,
);

impl NonFungibleAssetDelta {
    /// Creates a new non-fungible asset delta.
    pub const fn new(
        map: BTreeMap<AssetVaultKey, (NonFungibleAsset, NonFungibleDeltaAction)>,
    ) -> Self {
        Self(map)
    }

    /// Adds a new non-fungible asset to the delta.
    ///
    /// # Errors
    /// Returns an error if the delta already contains the asset addition.
    pub fn add(&mut self, asset: NonFungibleAsset) -> Result<(), AccountDeltaError> {
        self.apply_action(asset, NonFungibleDeltaAction::Add)
    }

    /// Removes a non-fungible asset from the delta.
    ///
    /// # Errors
    /// Returns an error if the delta already contains the asset removal.
    pub fn remove(&mut self, asset: NonFungibleAsset) -> Result<(), AccountDeltaError> {
        self.apply_action(asset, NonFungibleDeltaAction::Remove)
    }

    /// Returns the number of non-fungible assets affected in the delta.
    pub fn num_assets(&self) -> usize {
        self.0.len()
    }

    /// Returns true if this vault delta contains no updates.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the (key, value) pairs of the map.
    pub fn iter(&self) -> impl Iterator<Item = (&NonFungibleAsset, &NonFungibleDeltaAction)> {
        self.0
            .iter()
            .map(|(_key, (non_fungible_asset, delta_action))| (non_fungible_asset, delta_action))
    }

    // HELPER FUNCTIONS
    // ---------------------------------------------------------------------------------------------

    /// Updates the provided map with the provided key and action.
    /// If the action is the opposite to the previous one, the entry is removed.
    ///
    /// # Errors
    /// Returns an error if the delta already contains the provided key and action.
    fn apply_action(
        &mut self,
        asset: NonFungibleAsset,
        action: NonFungibleDeltaAction,
    ) -> Result<(), AccountDeltaError> {
        match self.0.entry(asset.vault_key()) {
            Entry::Vacant(entry) => {
                entry.insert((asset, action));
            },
            Entry::Occupied(entry) => {
                let (_prev_asset, previous_action) = *entry.get();
                if previous_action == action {
                    // Asset cannot be added nor removed twice.
                    return Err(AccountDeltaError::DuplicateNonFungibleVaultUpdate(asset));
                }
                // Otherwise they cancel out.
                entry.remove();
            },
        }

        Ok(())
    }

    /// Returns an iterator over all keys that have the provided action.
    fn filter_by_action(
        &self,
        action: NonFungibleDeltaAction,
    ) -> impl Iterator<Item = NonFungibleAsset> + '_ {
        self.0
            .iter()
            .filter(move |&(_, (_asset, cur_action))| cur_action == &action)
            .map(|(_key, (asset, _action))| *asset)
    }
}

impl Serializable for NonFungibleAssetDelta {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let added: Vec<_> = self.filter_by_action(NonFungibleDeltaAction::Add).collect();
        let removed: Vec<_> = self.filter_by_action(NonFungibleDeltaAction::Remove).collect();

        target.write_usize(added.len());
        target.write_many(added.iter());

        target.write_usize(removed.len());
        target.write_many(removed.iter());
    }

    fn get_size_hint(&self) -> usize {
        let added = self.filter_by_action(NonFungibleDeltaAction::Add).count();
        let removed = self.filter_by_action(NonFungibleDeltaAction::Remove).count();

        added.get_size_hint()
            + removed.get_size_hint()
            + added * NonFungibleAsset::SERIALIZED_SIZE
            + removed * NonFungibleAsset::SERIALIZED_SIZE
    }
}

impl Deserializable for NonFungibleAssetDelta {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut map = BTreeMap::new();

        let num_added = source.read_usize()?;
        for _ in 0..num_added {
            let added_asset: NonFungibleAsset = source.read()?;
            map.insert(added_asset.vault_key(), (added_asset, NonFungibleDeltaAction::Add));
        }

        let num_removed = source.read_usize()?;
        for _ in 0..num_removed {
            let removed_asset: NonFungibleAsset = source.read()?;
            map.insert(removed_asset.vault_key(), (removed_asset, NonFungibleDeltaAction::Remove));
        }

        Ok(Self::new(map))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonFungibleDeltaAction {
    Add,
    Remove,
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{AccountVaultDelta, Deserializable, Serializable};
    use crate::account::AccountId;
    use crate::asset::{Asset, FungibleAsset, NonFungibleAsset};
    use crate::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    #[test]
    fn test_serde_account_vault() {
        let asset_0 = FungibleAsset::mock(100);
        let asset_1 = NonFungibleAsset::mock(&[10, 21, 32, 43]);
        let delta = AccountVaultDelta::from_iters([asset_0], [asset_1]);

        let serialized = delta.to_bytes();
        let deserialized = AccountVaultDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, delta);
    }

    #[test]
    fn test_is_empty_account_vault() {
        let faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
        let asset: Asset = FungibleAsset::new(faucet, 123).unwrap().into();

        assert!(AccountVaultDelta::default().is_empty());
        assert!(!AccountVaultDelta::from_iters([asset], []).is_empty());
        assert!(!AccountVaultDelta::from_iters([], [asset]).is_empty());
    }
}
