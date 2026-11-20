use crate::Word;
use crate::account::{AccountCode, AccountId, PartialAccount, PartialStorage, StorageMapWitness};
use crate::asset::{AssetWitness, PartialVault};
use crate::block::account_tree::AccountWitness;
use crate::crypto::merkle::smt::{SmtProof, SmtProofError};
use crate::errors::{AccountError, PartialAssetVaultError};

// ACCOUNT INPUTS
// ================================================================================================

/// Contains information about an account, with everything required to execute a transaction.
///
/// `AccountInputs` combines a partial account representation with the merkle proof that verifies
/// the account's inclusion in the account tree. The partial account should contain verifiable
/// access to the parts of the state of the account of which the transaction will make use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountInputs {
    /// Partial representation of the account's state.
    partial_account: PartialAccount,
    /// Proof of the account's inclusion in the account tree for this account's state commitment.
    witness: AccountWitness,
}

impl AccountInputs {
    /// Creates a new instance of `AccountInputs` with the specified partial account and witness.
    pub fn new(partial_account: PartialAccount, witness: AccountWitness) -> AccountInputs {
        AccountInputs { partial_account, witness }
    }

    /// Returns the account ID.
    pub fn id(&self) -> AccountId {
        self.partial_account.id()
    }

    /// Returns a reference to the partial account representation.
    pub fn account(&self) -> &PartialAccount {
        &self.partial_account
    }

    /// Returns a reference to the account code.
    pub fn code(&self) -> &AccountCode {
        self.partial_account.code()
    }

    /// Returns a reference to the partial representation of the account storage.
    pub fn storage(&self) -> &PartialStorage {
        self.partial_account.storage()
    }

    /// Returns a reference to the partial vault representation of the account.
    pub fn vault(&self) -> &PartialVault {
        self.partial_account.vault()
    }

    /// Returns a reference to the account's witness.
    pub fn witness(&self) -> &AccountWitness {
        &self.witness
    }

    /// Adds an asset witness to the partial account.
    ///
    /// # Errors
    ///
    /// Returns an error under the conditions of [`PartialAccount::add_asset_witness`].
    pub fn add_asset_witness(
        &mut self,
        witness: AssetWitness,
    ) -> Result<(), PartialAssetVaultError> {
        self.partial_account.add_asset_witness(witness)
    }

    /// Adds a storage map witness to the partial account.
    ///
    /// # Errors
    ///
    /// Returns an error under the conditions of [`PartialAccount::add_storage_map_witness`].
    pub fn add_storage_map_witness(
        &mut self,
        witness: StorageMapWitness,
    ) -> Result<(), AccountError> {
        self.partial_account.add_storage_map_witness(witness)
    }

    /// Decomposes the `AccountInputs` into its constituent parts.
    pub fn into_parts(self) -> (PartialAccount, AccountWitness) {
        (self.partial_account, self.witness)
    }

    /// Computes the account root based on the account witness.
    /// This root should be equal to the account root in the reference block header.
    pub fn compute_account_root(&self) -> Result<Word, SmtProofError> {
        let smt_merkle_path = self.witness.path().clone();
        let smt_leaf = self.witness.leaf();
        let root = SmtProof::new(smt_merkle_path, smt_leaf)?.compute_root();

        Ok(root)
    }
}
