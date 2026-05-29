use alloc::collections::BTreeMap;

use miden_protocol::Word;
use miden_protocol::account::{AccountVaultDelta, AccountVaultPatch};
use miden_protocol::asset::{Asset, AssetVaultKey};

use crate::TransactionKernelError;
use crate::host::tx_event::{AddedAssetUpdate, RemovedAssetUpdate};

/// Keeps track of the updates to an account's vault during transaction execution.
///
/// On each add/remove event the tracker records:
/// - the relative change in [`AccountVaultDelta`],
/// - the initial value of the touched vault key, only the very first time it is observed,
/// - the latest absolute value of the touched vault key in [`AccountVaultPatch`].
///
/// At the end of the transaction, [`Self::into_patch`] normalizes the patch by dropping entries
/// whose final value equals the initial value, i.e. vault keys that were touched but ultimately
/// unchanged.
#[derive(Debug, Clone, Default)]
pub(crate) struct VaultUpdateTracker {
    delta: AccountVaultDelta,
    /// The absolute value of each touched vault key at the start of the transaction.
    init_values: BTreeMap<AssetVaultKey, Word>,
    /// The latest absolute value of each touched vault key.
    entries: BTreeMap<AssetVaultKey, Word>,
}

impl VaultUpdateTracker {
    /// Records an add-asset event in the vault delta and patch.
    pub fn add(&mut self, update: AddedAssetUpdate) -> Result<(), TransactionKernelError> {
        let added_asset = Asset::from_key_value(update.asset_key, update.added_asset_value)
            .map_err(|source| TransactionKernelError::MalformedAssetInEventHandler {
                handler: "AccountVaultAfterAddAsset",
                source,
            })?;

        self.delta
            .add_asset(added_asset)
            .map_err(TransactionKernelError::AccountDeltaAddAssetFailed)?;

        self.record_observation(
            update.asset_key,
            update.initial_vault_value,
            update.final_vault_value,
        );

        Ok(())
    }

    /// Records a remove-asset event in the vault delta and patch.
    pub fn remove(&mut self, update: RemovedAssetUpdate) -> Result<(), TransactionKernelError> {
        let removed_asset = Asset::from_key_value(update.asset_key, update.removed_asset_value)
            .map_err(|source| TransactionKernelError::MalformedAssetInEventHandler {
                handler: "AccountVaultAfterRemoveAsset",
                source,
            })?;

        self.delta
            .remove_asset(removed_asset)
            .map_err(TransactionKernelError::AccountDeltaRemoveAssetFailed)?;

        self.record_observation(
            update.asset_key,
            update.initial_vault_value,
            update.final_vault_value,
        );

        Ok(())
    }

    /// Returns a reference to the vault delta.
    pub fn delta(&self) -> &AccountVaultDelta {
        &self.delta
    }

    /// Consumes self and returns the vault delta.
    pub fn into_delta(self) -> AccountVaultDelta {
        self.delta
    }

    /// Consumes self and returns the normalized vault patch.
    ///
    /// Drops entries whose final value equals the initial value at the start of the transaction.
    pub fn into_patch(self) -> AccountVaultPatch {
        let Self { init_values, mut entries, .. } = self;

        entries.retain(|key, final_value| {
            let initial_value = init_values
                .get(key)
                .expect("initial value should be tracked for every touched vault key");
            final_value != initial_value
        });

        AccountVaultPatch::from_raw(entries)
    }

    /// Records the initial value of `asset_key` on first observation and updates its latest value.
    fn record_observation(
        &mut self,
        asset_key: AssetVaultKey,
        initial_value: Word,
        final_value: Word,
    ) {
        self.init_values.entry(asset_key).or_insert(initial_value);
        self.entries.insert(asset_key, final_value);
    }
}
