use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::delta::AssetDeltaOperation;
use miden_protocol::account::{AccountVaultDelta, AccountVaultPatch, AssetDelta};
use miden_protocol::asset::{Asset, AssetId};

use crate::TransactionKernelError;
use crate::host::tx_event::AssetPatch;

/// Keeps track of the updates to an account's vault during transaction execution.
///
/// On each add/remove event the tracker records:
/// - the initial value of the touched asset ID, only the very first time it is observed,
/// - the final absolute value of the touched asset ID in [`AccountVaultPatch`].
///
/// When the delta commitment is computed in the VM, the tracker records the relative change as the
/// per-asset [`AssetDelta`] reported by the kernel. Note that the delta could be computed multiple
/// times, so the tracker is reset before every computation to ensure the host delta matches the tx
/// kernel delta.
///
/// At the end of the transaction, [`Self::into_patch`] normalizes the patch by dropping entries
/// whose final value equals the initial value, i.e. asset IDs that were touched but ultimately
/// unchanged.
#[derive(Debug, Clone, Default)]
pub(crate) struct VaultUpdateTracker {
    /// The [`AssetDelta`]s reported by the kernel, one per touched asset ID.
    asset_deltas: Vec<AssetDelta>,
    /// For each touched asset ID, the `(initial, final)` absolute values. The initial value is
    /// recorded only on the very first observation and never overwritten; the final value is
    /// updated on every observation.
    entries: BTreeMap<AssetId, (Word, Word)>,
}

impl VaultUpdateTracker {
    /// Inserts an asset patch.
    pub fn update_patch(&mut self, patch: AssetPatch) -> Result<(), TransactionKernelError> {
        self.entries
            .entry(patch.asset_id)
            .and_modify(|(_, r#final)| *r#final = patch.final_vault_value)
            .or_insert((patch.initial_vault_value, patch.final_vault_value));

        Ok(())
    }

    /// Records an asset delta reported by the kernel.
    pub fn add_delta(&mut self, delta: AssetDelta) {
        self.asset_deltas.push(delta);
    }

    /// Clears the accumulating vault delta.
    pub fn reset_delta(&mut self) {
        self.asset_deltas.clear();
    }

    /// Returns the number of 8-Felt body blocks in the vault-delta section.
    ///
    /// The host uses this before the kernel computes the delta commitment. At that point
    /// `asset_deltas` may still be empty because it is populated by the commitment pass itself, so
    /// the count is derived from the tracked initial/final vault values.
    pub fn delta_commitment_body_block_count(&self) -> Result<usize, TransactionKernelError> {
        let mut num_added_assets = 0usize;
        let mut num_removed_assets = 0usize;

        for (asset_id, (initial_value, final_value)) in self.entries.iter() {
            if initial_value == final_value {
                continue;
            }

            match compute_delta_op(*asset_id, *initial_value, *final_value)? {
                AssetDeltaOperation::Add => num_added_assets += 1,
                AssetDeltaOperation::Remove => num_removed_assets += 1,
            }
        }

        Ok(num_added_assets
            + usize::from(num_added_assets != 0)
            + num_removed_assets
            + usize::from(num_removed_assets != 0))
    }

    /// Consumes self and returns the vault delta.
    pub fn into_delta(self) -> AccountVaultDelta {
        // The kernel uses a map internally so it should never emit more than one delta per asset
        // ID. The kernel also enforces the maximum number of assets per delta operation.
        AccountVaultDelta::new(self.asset_deltas)
            .expect("tx kernel should emit a valid vault delta")
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

        AccountVaultPatch::new(normalized)
            .expect("vault update events should only be tracked for valid assets")
    }
}

fn compute_delta_op(
    asset_id: AssetId,
    initial_value: Word,
    final_value: Word,
) -> Result<AssetDeltaOperation, TransactionKernelError> {
    if asset_id.composition().is_none() {
        return if initial_value.is_empty() {
            Ok(AssetDeltaOperation::Add)
        } else {
            Ok(AssetDeltaOperation::Remove)
        };
    }

    if !asset_id.composition().is_fungible() {
        return Err(TransactionKernelError::other(
            "custom asset composition is not supported in account delta commitments",
        ));
    }

    let initial_amount = Asset::new(asset_id, initial_value)
        .map_err(|source| {
            TransactionKernelError::other_with_source(
                "failed to decode initial fungible asset value",
                source,
            )
        })?
        .unwrap_fungible()
        .amount();
    let final_amount = Asset::new(asset_id, final_value)
        .map_err(|source| {
            TransactionKernelError::other_with_source(
                "failed to decode final fungible asset value",
                source,
            )
        })?
        .unwrap_fungible()
        .amount();

    if final_amount > initial_amount {
        Ok(AssetDeltaOperation::Add)
    } else {
        Ok(AssetDeltaOperation::Remove)
    }
}
