use miden_protocol::Felt;
use miden_protocol::account::{
    AccountCode,
    AccountDelta,
    AccountId,
    AccountPatch,
    AccountVaultDelta,
    PartialAccount,
};

use crate::TransactionKernelError;
use crate::host::storage_patch_tracker::StoragePatchTracker;
use crate::host::tx_event::{AssetDelta, AssetPatch};
use crate::host::vault_update_tracker::VaultUpdateTracker;

// ACCOUNT DELTA TRACKER
// ================================================================================================

/// Keeps track of changes made to the account during transaction execution.
///
/// Currently, this tracks:
/// - Changes to the account storage, slots and maps.
/// - Changes to the account vault.
/// - Changes to the account nonce.
///
/// TODO: implement tracking of:
/// - account code changes.
#[derive(Debug, Clone)]
pub struct AccountUpdateTracker {
    account_id: AccountId,
    storage: StoragePatchTracker,
    vault: VaultUpdateTracker,
    code: Option<AccountCode>,
    initial_nonce: Felt,
    nonce_delta: Felt,
}

impl AccountUpdateTracker {
    /// Returns a new [`AccountUpdateTracker`] instantiated for the specified account.
    pub fn new(account: &PartialAccount) -> Self {
        let code = if account.is_new() {
            Some(account.code().clone())
        } else {
            None
        };

        Self {
            account_id: account.id(),
            storage: StoragePatchTracker::new(account),
            vault: VaultUpdateTracker::default(),
            code,
            nonce_delta: Felt::ZERO,
            initial_nonce: account.nonce(),
        }
    }

    /// Returns true if the nonce delta is non-zero.
    pub fn was_nonce_incremented(&self) -> bool {
        self.nonce_delta != Felt::ZERO
    }

    /// Increments the nonce delta by one.
    pub fn increment_nonce(&mut self) {
        self.nonce_delta += Felt::ONE;
    }

    /// Returns a reference to the vault delta.
    pub fn vault_delta(&self) -> &AccountVaultDelta {
        self.vault.delta()
    }

    /// Updates the vault patch.
    pub fn update_asset_patch(&mut self, patch: AssetPatch) -> Result<(), TransactionKernelError> {
        self.vault.update_patch(patch)
    }

    /// Updates the vault delta.
    pub fn update_asset_delta(&mut self, delta: AssetDelta) -> Result<(), TransactionKernelError> {
        self.vault.update_delta(delta)
    }

    /// Returns a mutable reference to the current storage patch tracker.
    pub fn storage(&mut self) -> &mut StoragePatchTracker {
        &mut self.storage
    }

    /// Consumes `self` and returns the resulting [AccountDelta].
    ///
    /// Normalizes the delta by removing entries for storage slots where the initial and new
    /// value are equal.
    pub fn into_delta(self) -> AccountDelta {
        let account_id = self.account_id;
        let nonce_delta = self.nonce_delta;

        let storage_patch = self.storage.into_patch();
        let vault_delta = self.vault.into_delta();

        AccountDelta::new(account_id, storage_patch, vault_delta, nonce_delta)
            .expect("account delta created in delta tracker should be valid")
            .with_code(self.code)
    }

    /// Consumes `self` and returns the resulting [`AccountPatch`].
    ///
    /// Normalizes the patch by removing entries for storage slots where the initial and new
    /// value are equal.
    #[allow(unused, reason = "TODO(patch): will be used in an upcoming PR")]
    pub fn into_patch(self) -> AccountPatch {
        let storage_patch = self.storage.into_patch();
        let vault_patch = self.vault.into_patch();

        let new_nonce = if self.nonce_delta == Felt::ZERO {
            None
        } else {
            debug_assert!(
                self.initial_nonce.as_canonical_u64() < (Felt::ORDER - 1),
                "tx kernel should abort if nonce would overflow"
            );
            Some(self.initial_nonce + self.nonce_delta)
        };

        AccountPatch::new(self.account_id, storage_patch, vault_patch, self.code, new_nonce)
            .expect("account patch created in delta tracker should be valid")
    }
}
