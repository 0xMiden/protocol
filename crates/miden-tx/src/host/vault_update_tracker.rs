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
    /// For each touched vault key, the `(initial, latest)` absolute values. The initial value is
    /// recorded only on the very first observation and never overwritten; the latest value is
    /// updated on every observation.
    entries: BTreeMap<AssetVaultKey, (Word, Word)>,
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
        let normalized = self
            .entries
            .into_iter()
            .filter_map(|(key, (initial_value, final_value))| {
                if final_value == initial_value {
                    None
                } else {
                    Some((key, final_value))
                }
            })
            .collect();

        AccountVaultPatch::from_raw(normalized)
    }

    /// Records the initial value of `asset_key` on first observation and updates its latest value.
    fn record_observation(
        &mut self,
        asset_key: AssetVaultKey,
        initial_value: Word,
        final_value: Word,
    ) {
        self.entries
            .entry(asset_key)
            .and_modify(|(_, latest)| *latest = final_value)
            .or_insert((initial_value, final_value));
    }
}
