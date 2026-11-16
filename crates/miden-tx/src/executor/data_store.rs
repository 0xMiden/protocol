use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::{FutureMaybeSend, MastForestStore, Word};
use miden_protocol::account::{AccountId, PartialAccount, StorageMapKey, StorageMapWitness};
use miden_protocol::assembly::mast::MastForest;
use miden_protocol::asset::{AssetId, AssetWitness};
use miden_protocol::block::code_tree::{CodeTreeRoot, CodeWitness};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::code::ProcedureRoot;
use miden_protocol::protocol_config::ProtocolConfig;
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
    /// The returned partial blockchain must track every block in `ref_blocks`.
    ///
    /// The highest block number in `ref_blocks` will be the transaction reference block. In
    /// general, it is recommended that the reference corresponds to the latest block available
    /// in the data store.
    ///
    /// The returned [`ProtocolConfig`] must be the one the returned block header commits to, since
    /// the header only carries its commitment.
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
    ) -> impl FutureMaybeSend<
        Result<(PartialAccount, BlockHeader, ProtocolConfig, PartialBlockchain), DataStoreError>,
    >;

    /// Returns a partial foreign account state together with a witness, proving its validity in the
    /// specified transaction reference block.
    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>>;

    /// Returns witnesses for the asset IDs in the requested account's vault with the
    /// requested vault root.
    ///
    /// These are the witnesses that need to be added to the advice provider's merkle store and
    /// advice map to make access to the corresponding assets possible.
    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        asset_ids: BTreeSet<AssetId>,
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

    /// Returns the code witnesses of the provided procedure roots in the code tree with the
    /// requested `code_tree_root`. The witnesses are needed to prove presence or absence of the
    /// procedures.
    fn get_code_witnesses(
        &self,
        code_tree_root: CodeTreeRoot,
        procedure_roots: Vec<ProcedureRoot>,
    ) -> impl FutureMaybeSend<Result<Vec<CodeWitness>, DataStoreError>>;

    /// Returns the code that the transaction may register for the provided procedure roots, which
    /// are absent from the code tree.
    ///
    /// The returned forests must contain all absent code that the procedure roots reach. A
    /// reference to code that the code tree already contains can stay an external node. The data
    /// store leaves out the code that it does not have.
    ///
    /// Unlike [`MastForestStore::get`], which provides code for execution, this method must only
    /// return code that is expected to be published, because the transaction adds it to the public
    /// code registry.
    fn get_code_to_register(
        &self,
        procedure_roots: BTreeSet<ProcedureRoot>,
    ) -> impl FutureMaybeSend<Result<Vec<Arc<MastForest>>, DataStoreError>>;
}
