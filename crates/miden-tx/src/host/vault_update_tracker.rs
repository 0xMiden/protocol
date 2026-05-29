use miden_protocol::account::{AccountVaultDelta, AccountVaultPatch};

use crate::TransactionKernelError;
use crate::host::tx_event::{AddedAssetUpdate, RemovedAssetUpdate};

/// Keeps track of the updates to an account's vault during transaction execution.
#[derive(Debug, Clone, Default)]
pub(crate) struct VaultUpdateTracker {
    delta: AccountVaultDelta,
    patch: AccountVaultPatch,
}

impl VaultUpdateTracker {
    /// Adds an asset to the vault delta and patch.
    pub fn add(&mut self, update: AddedAssetUpdate) -> Result<(), TransactionKernelError> {
        self.delta
            .add_asset(update.added_asset)
            .map_err(TransactionKernelError::AccountDeltaAddAssetFailed)?;

        self.patch.insert_asset(update.vault_asset);

        Ok(())
    }

    /// Removes an asset from the vault delta and patch.
    pub fn remove(&mut self, update: RemovedAssetUpdate) -> Result<(), TransactionKernelError> {
        self.delta
            .remove_asset(update.removed_asset)
            .map_err(TransactionKernelError::AccountDeltaRemoveAssetFailed)?;

        self.patch.insert_asset(update.vault_asset);

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

    /// Consumes self and returns the vault patch.
    pub fn into_patch(self) -> AccountVaultPatch {
        self.patch
    }
}
