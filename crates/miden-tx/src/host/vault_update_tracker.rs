use alloc::collections::BTreeMap;

use miden_protocol::Word;
use miden_protocol::account::delta::AssetDeltaOperation;
use miden_protocol::account::{
    AccountVaultDelta,
    AccountVaultPatch,
    FungibleAssetDelta,
    NonFungibleAssetDelta,
    NonFungibleDeltaAction,
};
use miden_protocol::asset::{Asset, AssetVaultKey};

use crate::TransactionKernelError;
use crate::host::tx_event::{AssetDelta, AssetPatch};

/// Keeps track of the updates to an account's vault during transaction execution.
///
/// On each add/remove event the tracker records:
/// - the initial value of the touched vault key, only the very first time it is observed,
/// - the final absolute value of the touched vault key in [`AccountVaultPatch`].
///
/// When the delta commitment is computed in the VM, the tracker records the relative change as the
/// per-asset [`AssetDelta`] reported by the kernel. Note that the delta could be computed multiple
/// times, so the tracker is reset before every computation to ensure the host delta matches the tx
/// kernel delta.
///
/// At the end of the transaction, [`Self::into_patch`] normalizes the patch by dropping entries
/// whose final value equals the initial value, i.e. vault keys that were touched but ultimately
/// unchanged.
#[derive(Debug, Clone, Default)]
pub(crate) struct VaultUpdateTracker {
    /// The latest absolute [`AssetDelta`] reported by the kernel for each touched vault key.
    delta: BTreeMap<AssetVaultKey, AssetDelta>,
    /// For each touched vault key, the `(initial, final)` absolute values. The initial value is
    /// recorded only on the very first observation and never overwritten; the final value is
    /// updated on every observation.
    entries: BTreeMap<AssetVaultKey, (Word, Word)>,
}

impl VaultUpdateTracker {
    /// Inserts an asset patch.
    pub fn update_patch(&mut self, patch: AssetPatch) -> Result<(), TransactionKernelError> {
        self.entries
            .entry(patch.asset_key)
            .and_modify(|(_, r#final)| *r#final = patch.final_vault_value)
            .or_insert((patch.initial_vault_value, patch.final_vault_value));

        Ok(())
    }

    /// Inserts an asset delta.
    pub fn update_delta(&mut self, delta: AssetDelta) {
        self.delta.insert(delta.asset.vault_key(), delta);
    }

    /// Clears the accumulating vault delta.
    pub fn reset_delta(&mut self) {
        self.delta.clear();
    }

    /// Consumes self and returns the vault delta.
    pub fn into_delta(self) -> AccountVaultDelta {
        self.build_delta()
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

    // HELPER FUNCTIONS
    // ---------------------------------------------------------------------------------------------

    /// Builds an [`AccountVaultDelta`] from the flat per-asset delta map.
    ///
    /// TODO(unified_delta): Will be simplified once `AccountVaultDelta` tracks only generic assets.
    fn build_delta(&self) -> AccountVaultDelta {
        let mut fungible: BTreeMap<AssetVaultKey, i64> = BTreeMap::new();
        let mut non_fungible: BTreeMap<AssetVaultKey, (_, NonFungibleDeltaAction)> =
            BTreeMap::new();

        for (&vault_key, asset_delta) in &self.delta {
            match asset_delta.asset {
                Asset::Fungible(fungible_asset) => {
                    let amount = fungible_asset.amount().as_i64();
                    let signed_amount = match asset_delta.delta_op {
                        AssetDeltaOperation::Add => amount,
                        AssetDeltaOperation::Remove => -amount,
                    };
                    fungible.insert(vault_key, signed_amount);
                },
                Asset::NonFungible(non_fungible_asset) => {
                    let action = match asset_delta.delta_op {
                        AssetDeltaOperation::Add => NonFungibleDeltaAction::Add,
                        AssetDeltaOperation::Remove => NonFungibleDeltaAction::Remove,
                    };
                    non_fungible.insert(vault_key, (non_fungible_asset, action));
                },
            }
        }

        let fungible = FungibleAssetDelta::new(fungible)
            .expect("tx kernel should only emit valid fungible asset deltas");
        let non_fungible = NonFungibleAssetDelta::new(non_fungible);

        AccountVaultDelta::new(fungible, non_fungible)
    }
}
