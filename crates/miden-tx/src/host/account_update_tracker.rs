use miden_protocol::account::{
    AccountCode,
    AccountCodePatch,
    AccountCodeUpgrade,
    AccountDelta,
    AccountId,
    AccountPatch,
    AssetDelta,
    PartialAccount,
};
use miden_protocol::{Felt, Word};

use crate::TransactionKernelError;
use crate::host::storage_patch_tracker::StoragePatchTracker;
use crate::host::tx_event::AssetPatch;
use crate::host::vault_update_tracker::VaultUpdateTracker;

// ACCOUNT DELTA TRACKER
// ================================================================================================

/// Keeps track of changes made to the account during transaction execution.
///
/// Currently, this tracks:
/// - Changes to the account storage, slots and maps.
/// - Changes to the account vault.
/// - Changes to the account nonce.
/// - Changes to the account code.
#[derive(Debug, Clone)]
pub struct AccountUpdateTracker {
    account_id: AccountId,
    storage: StoragePatchTracker,
    vault: VaultUpdateTracker,
    code: AccountCodeState,
    initial_nonce: Felt,
    nonce_delta: Felt,
}

impl AccountUpdateTracker {
    /// Returns a new [`AccountUpdateTracker`] instantiated for the specified account and the code
    /// upgrade the transaction may apply to it.
    ///
    /// # Errors
    ///
    /// Returns an error if the account is new and a code upgrade is provided.
    pub fn new(
        account: &PartialAccount,
        account_code_upgrade: Option<AccountCodeUpgrade>,
    ) -> Result<Self, TransactionKernelError> {
        let code = match (account.is_new(), account_code_upgrade) {
            (true, Some(_)) => {
                return Err(TransactionKernelError::AccountCodeUpgradeNotAllowedForNewAccount);
            },
            (true, None) => AccountCodeState::New(account.code().clone()),
            (false, Some(code_upgrade)) => AccountCodeState::UpgradeProvided(code_upgrade),
            (false, None) => AccountCodeState::None,
        };

        Ok(Self {
            account_id: account.id(),
            storage: StoragePatchTracker::new(account),
            vault: VaultUpdateTracker::default(),
            code,
            nonce_delta: Felt::ZERO,
            initial_nonce: account.nonce(),
        })
    }

    /// Returns true if the nonce delta is non-zero.
    pub fn was_nonce_incremented(&self) -> bool {
        self.nonce_delta != Felt::ZERO
    }

    /// Increments the nonce delta by one.
    pub fn increment_nonce(&mut self) {
        self.nonce_delta += Felt::ONE;
    }

    /// Records the code upgrade initialized by the kernel.
    ///
    /// An empty `new_code_commitment` means the upgrade was a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the executor did not provide the code upgrade.
    /// - the account is new.
    /// - the upgrade was already initialized.
    /// - the commitment of the provided code upgrade does not match `new_code_commitment`.
    pub fn record_code_upgrade(
        &mut self,
        new_code_commitment: Word,
    ) -> Result<(), TransactionKernelError> {
        if new_code_commitment.is_empty() {
            return Ok(());
        }

        let code_upgrade = match &self.code {
            AccountCodeState::None => {
                return Err(TransactionKernelError::AccountCodeUpgradeMissing(new_code_commitment));
            },
            AccountCodeState::New(_) => {
                return Err(TransactionKernelError::AccountCodeUpgradeNotAllowedForNewAccount);
            },
            AccountCodeState::UpgradeInitialized(_) => {
                return Err(TransactionKernelError::other(
                    "account code upgrade was already initialized",
                ));
            },
            AccountCodeState::UpgradeProvided(code_upgrade) => code_upgrade,
        };

        if code_upgrade.commitment() != new_code_commitment {
            return Err(TransactionKernelError::AccountCodeUpgradeCommitmentMismatch {
                expected: new_code_commitment,
                actual: code_upgrade.commitment(),
            });
        }

        self.code = AccountCodeState::UpgradeInitialized(code_upgrade.clone());

        Ok(())
    }

    /// Updates the vault patch.
    pub fn update_asset_patch(&mut self, patch: AssetPatch) -> Result<(), TransactionKernelError> {
        self.vault.update_patch(patch)
    }

    /// Records an asset delta reported by the kernel.
    pub fn add_asset_delta(&mut self, delta: AssetDelta) {
        self.vault.add_delta(delta);
    }

    /// Clears the accumulating vault delta so the next pass of the kernel's delta computation
    /// rebuilds it from scratch.
    pub fn reset_vault_delta(&mut self) {
        self.vault.reset_delta();
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

        AccountDelta::new(
            account_id,
            storage_patch,
            vault_delta,
            AccountCodePatch::new(self.code.into_option_code()),
            nonce_delta,
        )
        .expect("account delta created in delta tracker should be valid")
    }

    /// Consumes `self` and returns the resulting [`AccountPatch`].
    ///
    /// Normalizes the patch by removing entries for storage slots where the initial and new
    /// value are equal.
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

        AccountPatch::new(
            self.account_id,
            storage_patch,
            vault_patch,
            AccountCodePatch::new(self.code.into_option_code()),
            new_nonce,
        )
        .expect("account patch created in delta tracker should be valid")
    }
}

/// The account code that the resulting [`AccountCodePatch`] carries.
///
/// New accounts and code upgrades both put the full code into the patch, but they are kept
/// separate because only an existing account can upgrade its code.
#[derive(Debug, Clone)]
enum AccountCodeState {
    /// The transaction does not change the code of an existing account.
    None,
    /// The code of a new account, which the transaction creates.
    New(AccountCode),
    /// The code upgrade the executor provided for an existing account.
    ///
    /// The patch does not carry it, since the transaction may never apply it.
    UpgradeProvided(AccountCodeUpgrade),
    /// The code upgrade the transaction applies to an existing account.
    UpgradeInitialized(AccountCodeUpgrade),
}

impl AccountCodeState {
    /// Consumes `self` and returns the code for the [`AccountCodePatch`], if any.
    fn into_option_code(self) -> Option<AccountCode> {
        match self {
            AccountCodeState::None | AccountCodeState::UpgradeProvided(_) => None,
            AccountCodeState::New(account_code) => Some(account_code),
            AccountCodeState::UpgradeInitialized(code_upgrade) => Some(code_upgrade.into_code()),
        }
    }
}
