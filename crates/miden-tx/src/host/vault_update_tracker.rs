use alloc::collections::BTreeMap;

use miden_protocol::Word;
use miden_protocol::account::delta::AssetDeltaOp;
use miden_protocol::account::{AccountVaultDelta, AccountVaultPatch};
use miden_protocol::asset::AssetVaultKey;

use crate::TransactionKernelError;
use crate::host::tx_event::{AssetDelta, AssetPatch};

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
    /// For each touched vault key, the `(initial, final)` absolute values. The initial value is
    /// recorded only on the very first observation and never overwritten; the final value is
    /// updated on every observation.
    entries: BTreeMap<AssetVaultKey, (Word, Word)>,
}

impl VaultUpdateTracker {
    /// Records an asset patch.
    pub fn update_patch(&mut self, patch: AssetPatch) -> Result<(), TransactionKernelError> {
        self.entries
            .entry(patch.asset_key)
            .and_modify(|(_, r#final)| *r#final = patch.final_vault_value)
            .or_insert((patch.initial_vault_value, patch.final_vault_value));

        Ok(())
    }

    pub fn update_delta(&mut self, delta: AssetDelta) -> Result<(), TransactionKernelError> {
        // TODO(unified_delta): Temporary logic.
        match delta.delta_op {
            AssetDeltaOp::Add => {
                self.delta.add_asset(delta.asset).expect("TODO");
            },
            AssetDeltaOp::Remove => {
                self.delta.remove_asset(delta.asset).expect("TODO");
            },
        }

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
}
