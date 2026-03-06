use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_processor::{FutureMaybeSend, MastForestStore, Word};
use miden_protocol::account::{AccountId, PartialAccount, StorageMapKey, StorageMapWitness};
use miden_protocol::asset::{AssetVaultKey, AssetWitness};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::{AccountInputs, PartialBlockchain};

use crate::DataStoreError;

// DATA STORE TRAIT
// ================================================================================================

/// The [DataStore] trait defines the interface that transaction objects use to fetch data
/// required for transaction execution.
pub trait DataStore: MastForestStore {
    /// Returns all the data required to execute a transaction against the account with the
    /// specified ID and consuming input notes created in blocks in the input `ref_blocks` set.
    ///
    /// The highest block number in `ref_blocks` will be the transaction reference block. In
    /// general, it is recommended that the reference corresponds to the latest block available
    /// in the data store.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The account with the specified ID could not be found in the data store.
    /// - The block with the specified number could not be found in the data store.
    /// - The combination of specified inputs resulted in a transaction input error.
    /// - The data store encountered some internal error
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        ref_blocks: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<Result<(PartialAccount, BlockHeader, PartialBlockchain), DataStoreError>>;

    /// Returns a partial foreign account state together with a witness, proving its validity in the
    /// specified transaction reference block.
    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>>;

    /// Returns witnesses for the asset vault keys in the requested account's vault with the
    /// requested vault root.
    ///
    /// These are the witnesses that need to be added to the advice provider's merkle store and
    /// advice map to make access to the corresponding assets possible.
    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        vault_keys: BTreeSet<AssetVaultKey>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>>;

    /// Returns a witness for a storage map item identified by `map_key` in the requested account's
    /// storage with the requested storage `map_root`.
    ///
    /// Note that the `map_key` needs to be hashed in order to get the actual key into the storage
    /// map.
    ///
    /// This is the witness that needs to be added to the advice provider's merkle store and advice
    /// map to make access to the specified storage map item possible.
    fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>>;

    /// Returns a note script with the specified root, or `None` if not found.
    ///
    /// This method will try to find a note script with the specified root in the data store.
    /// If the script is not found, it returns `Ok(None)` rather than an error, as "not found"
    /// is a valid, expected outcome.
    ///
    /// **Note:** Data store implementers do not need to handle standard note scripts (e.g. P2ID).
    /// These are resolved directly by the transaction executor and will not trigger this method.
    ///
    /// # Errors
    /// Returns an error if the data store encountered an internal error while attempting to
    /// retrieve the script.
    fn get_note_script(
        &self,
        script_root: Word,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>>;
}
