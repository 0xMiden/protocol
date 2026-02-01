use alloc::borrow::ToOwned;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::fast::ExecutionOutput;
use miden_processor::{FutureMaybeSend, MastForest, MastForestStore, Word};
use miden_protocol::account::{
    Account,
    AccountId,
    PartialAccount,
    StorageMapWitness,
    StorageSlotContent,
};
use miden_protocol::assembly::debuginfo::{SourceLanguage, Uri};
use miden_protocol::assembly::{Assembler, SourceManager, SourceManagerSync};
use miden_protocol::asset::{Asset, AssetVaultKey, AssetWitness};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{Note, NoteScript};
use miden_protocol::transaction::{
    AccountInputs,
    ExecutedTransaction,
    InputNote,
    InputNotes,
    PartialBlockchain,
    TransactionArgs,
    TransactionInputs,
    TransactionKernel,
};
use miden_standards::code_builder::CodeBuilder;
use miden_tx::auth::{BasicAuthenticator, UnreachableAuth};
use miden_tx::{
    AccountProcedureIndexMap,
    DataStore,
    DataStoreError,
    ScriptMastForestStore,
    TransactionExecutor,
    TransactionExecutorError,
    TransactionExecutorHost,
    TransactionMastStore,
};

use crate::executor::CodeExecutor;
use crate::mock_host::MockHost;
use crate::tx_context::ExecError;

// TRANSACTION CONTEXT
// ================================================================================================

/// Represents all needed data for executing a transaction, or arbitrary code.
///
/// It implements [`DataStore`], so transactions may be executed with
/// [TransactionExecutor](miden_tx::TransactionExecutor)
pub struct TransactionContext {
    pub(super) account: Account,
    pub(super) expected_output_notes: Vec<Note>,
    pub(super) foreign_account_inputs: BTreeMap<AccountId, (Account, AccountWitness)>,
    pub(super) tx_inputs: TransactionInputs,
    pub(super) mast_store: TransactionMastStore,
    pub(super) authenticator: Option<BasicAuthenticator>,
    pub(super) source_manager: Arc<dyn SourceManagerSync>,
    pub(super) note_scripts: BTreeMap<Word, NoteScript>,
    pub(super) is_lazy_loading_enabled: bool,
    pub(super) is_debug_mode_enabled: bool,
}

impl TransactionContext {
    /// Executes arbitrary code within the context of a mocked transaction environment and returns
    /// the resulting [`ExecutionOutput`].
    ///
    /// The code is compiled with the assembler built by [`CodeBuilder::with_mock_libraries`]
    /// and executed with advice inputs constructed from the data stored in the context. The program
    /// is run on a modified [`TransactionExecutorHost`] which is loaded with the procedures exposed
    /// by the transaction kernel, and also individual kernel functions (not normally exposed).
    ///
    /// # Errors
    ///
    /// Returns an error if the assembly or execution of the provided code fails.
    ///
    /// # Panics
    ///
    /// - If the provided `code` is not a valid program.
    pub async fn execute_code(&self, code: &str) -> Result<ExecutionOutput, ExecError> {
        // Fetch all witnesses for note assets and the fee asset.
        let mut asset_vault_keys = self
            .tx_inputs
            .input_notes()
            .iter()
            .flat_map(|note| note.note().assets().iter().map(Asset::vault_key))
            .collect::<BTreeSet<_>>();
        let fee_asset_vault_key = AssetVaultKey::from_account_id(
            self.tx_inputs().block_header().fee_parameters().native_asset_id(),
        )
        .expect("fee asset should be a fungible asset");
        asset_vault_keys.extend([fee_asset_vault_key]);

        let (account, block_header, _blockchain) = self
            .get_transaction_inputs(
                self.tx_inputs.account().id(),
                BTreeSet::from_iter([self.tx_inputs.block_header().block_num()]),
            )
            .await
            .expect("failed to fetch transaction inputs");

        // Add the vault key for the fee asset to the list of asset vault keys which may need to be
        // accessed at the end of the transaction.
        let fee_asset_vault_key =
            AssetVaultKey::from_account_id(block_header.fee_parameters().native_asset_id())
                .expect("fee asset should be a fungible asset");
        asset_vault_keys.insert(fee_asset_vault_key);

        // Fetch the witnesses for all asset vault keys.
        let asset_witnesses = self
            .get_vault_asset_witnesses(account.id(), account.vault().root(), asset_vault_keys)
            .await
            .expect("failed to fetch asset witnesses");

        let tx_inputs = self.tx_inputs.clone().with_asset_witnesses(asset_witnesses);
        let (stack_inputs, advice_inputs) = TransactionKernel::prepare_inputs(&tx_inputs);

        // Virtual file name should be unique.
        let virtual_source_file = self.source_manager.load(
            SourceLanguage::Masm,
            Uri::new("_tx_context_code"),
            code.to_owned(),
        );

        let assembler: Assembler =
            CodeBuilder::with_mock_libraries_with_source_manager(self.source_manager.clone())
                .into();

        let program = assembler
            .assemble_program(virtual_source_file)
            .expect("code was not well formed");

        // Load transaction kernel and the program into the mast forest in self.
        // Note that native and foreign account's code are already loaded by the
        // TransactionContextBuilder.
        self.mast_store.insert(TransactionKernel::library().mast_forest().clone());
        self.mast_store.insert(program.mast_forest().clone());

        let account_procedure_idx_map = AccountProcedureIndexMap::new(
            [tx_inputs.account().code()]
                .into_iter()
                .chain(self.foreign_account_inputs.values().map(|(account, _)| account.code())),
        );

        // The ref block is unimportant when using execute_code so we can set it to any value.
        let ref_block = tx_inputs.block_header().block_num();

        let exec_host = TransactionExecutorHost::<'_, '_, _, UnreachableAuth>::new(
            &PartialAccount::from(self.account()),
            tx_inputs.input_notes().clone(),
            self,
            ScriptMastForestStore::default(),
            account_procedure_idx_map,
            None,
            ref_block,
            // We don't need to set the initial balance in this context under the assumption that
            // fees are zero.
            0u64,
            self.source_manager(),
        );

        let advice_inputs = advice_inputs.into_advice_inputs();

        let mut mock_host = MockHost::new(exec_host);
        if self.is_lazy_loading_enabled {
            mock_host.enable_lazy_loading()
        }

        CodeExecutor::new(mock_host)
            .stack_inputs(stack_inputs)
            .extend_advice_inputs(advice_inputs)
            .execute_program(program)
            .await
    }

    /// Executes the transaction through a [TransactionExecutor]
    pub async fn execute(self) -> Result<ExecutedTransaction, TransactionExecutorError> {
        let account_id = self.account().id();
        let block_num = self.tx_inputs().block_header().block_num();
        let notes = self.tx_inputs().input_notes().clone();
        let tx_args = self.tx_args().clone();

        let mut tx_executor =
            TransactionExecutor::new(&self).with_source_manager(self.source_manager.clone());

        if self.is_debug_mode_enabled {
            tx_executor = tx_executor.with_debug_mode();
        }

        if let Some(authenticator) = self.authenticator() {
            tx_executor = tx_executor.with_authenticator(authenticator);
        }

        tx_executor.execute_transaction(account_id, block_num, notes, tx_args).await
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    pub fn expected_output_notes(&self) -> &[Note] {
        &self.expected_output_notes
    }

    pub fn tx_args(&self) -> &TransactionArgs {
        self.tx_inputs.tx_args()
    }

    pub fn input_notes(&self) -> &InputNotes<InputNote> {
        self.tx_inputs.input_notes()
    }

    pub fn set_tx_args(&mut self, tx_args: TransactionArgs) {
        self.tx_inputs.set_tx_args(tx_args);
    }

    pub fn tx_inputs(&self) -> &TransactionInputs {
        &self.tx_inputs
    }

    pub fn authenticator(&self) -> Option<&BasicAuthenticator> {
        self.authenticator.as_ref()
    }

    /// Returns the source manager used in the assembler of the transaction context builder.
    pub fn source_manager(&self) -> Arc<dyn SourceManagerSync> {
        Arc::clone(&self.source_manager)
    }
}

impl DataStore for TransactionContext {
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        ref_blocks: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<Result<(PartialAccount, BlockHeader, PartialBlockchain), DataStoreError>>
    {
        // Sanity checks
        assert_eq!(account_id, self.account().id());
        assert_eq!(account_id, self.tx_inputs.account().id());
        assert_eq!(
            ref_blocks
                .last()
                .copied()
                .expect("at least the tx ref block should be provided"),
            self.tx_inputs().blockchain().chain_length(),
            "tx reference block should match partial blockchain length"
        );

        let account = self.tx_inputs.account().clone();
        let block_header = self.tx_inputs.block_header().clone();
        let blockchain = self.tx_inputs.blockchain().clone();

        async move { Ok((account, block_header, blockchain)) }
    }

    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        _ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        // Note that we cannot validate that the foreign account inputs are valid for the
        // transaction's reference block.
        async move {
            let (foreign_account, account_witness) =
                self.foreign_account_inputs.get(&foreign_account_id).ok_or_else(|| {
                    DataStoreError::other(format!(
                        "failed to find foreign account {foreign_account_id}"
                    ))
                })?;

            Ok(AccountInputs::new(
                PartialAccount::from(foreign_account),
                account_witness.clone(),
            ))
        }
    }

    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        vault_keys: BTreeSet<AssetVaultKey>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        async move {
            let asset_vault = if account_id == self.account().id() {
                if self.account().vault().root() != vault_root {
                    return Err(DataStoreError::other(format!(
                        "native account {account_id} has vault root {} but {vault_root} was requested",
                        self.account().vault().root()
                    )));
                }
                self.account().vault()
            } else {
                let (foreign_account, _witness) = self
                    .foreign_account_inputs
                    .iter()
                    .find_map(
                        |(id, account_inputs)| {
                            if account_id == *id { Some(account_inputs) } else { None }
                        },
                    )
                    .ok_or_else(|| {
                        DataStoreError::other(format!(
                            "failed to find foreign account {account_id} in foreign account inputs"
                        ))
                    })?;

                if foreign_account.vault().root() != vault_root {
                    return Err(DataStoreError::other(format!(
                        "foreign account {account_id} has vault root {} but {vault_root} was requested",
                        foreign_account.vault().root()
                    )));
                }
                foreign_account.vault()
            };

            Ok(vault_keys.into_iter().map(|vault_key| asset_vault.open(vault_key)).collect())
        }
    }

    fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: Word,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async move {
            if account_id == self.account().id() {
                // Iterate the account storage to find the map with the requested root.
                let storage_map = self
                    .account()
                    .storage()
                    .slots()
                    .iter()
                    .find_map(|slot| match slot.content() {
                        StorageSlotContent::Map(storage_map) if storage_map.root() == map_root => {
                            Some(storage_map)
                        },
                        _ => None,
                    })
                    .ok_or_else(|| {
                        DataStoreError::other(format!(
                            "failed to find storage map with root {map_root} in account storage"
                        ))
                    })?;

                Ok(storage_map.open(&map_key))
            } else {
                let (foreign_account, _witness) = self
                    .foreign_account_inputs
                    .iter()
                    .find_map(
                        |(id, account_inputs)| {
                            if account_id == *id { Some(account_inputs) } else { None }
                        },
                    )
                    .ok_or_else(|| {
                        DataStoreError::other(format!(
                            "failed to find foreign account {account_id} in foreign account inputs"
                        ))
                    })?;

                let map = foreign_account
                    .storage()
                    .slots()
                    .iter()
                    .find_map(|slot| match slot.content() {
                        StorageSlotContent::Map(storage_map) if storage_map.root() == map_root => {Some(storage_map)},
                        _ => None,
                    })
                    .ok_or_else(|| {
                        DataStoreError::other(format!(
                            "failed to find storage map with root {map_root} in foreign account {account_id}"
                        ))
                    })?;

                Ok(map.open(&map_key))
            }
        }
    }

    fn get_note_script(
        &self,
        script_root: Word,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        async move { Ok(self.note_scripts.get(&script_root).cloned()) }
    }
}

impl MastForestStore for TransactionContext {
    fn get(&self, procedure_hash: &Word) -> Option<Arc<MastForest>> {
        self.mast_store.get(procedure_hash)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Felt;
    use miden_protocol::assembly::Assembler;
    use miden_protocol::note::NoteScript;

    use super::*;
    use crate::TransactionContextBuilder;

    #[tokio::test]
    async fn test_get_note_scripts() {
        // Create two note scripts
        let assembler1 = Assembler::default();
        let script1_code = "begin push.1 end";
        let program1 = assembler1
            .assemble_program(script1_code)
            .expect("failed to assemble note script 1");
        let note_script1 = NoteScript::new(program1);
        let script_root1 = note_script1.root();

        let assembler2 = Assembler::default();
        let script2_code = "begin push.2 push.3 add end";
        let program2 = assembler2
            .assemble_program(script2_code)
            .expect("failed to assemble note script 2");
        let note_script2 = NoteScript::new(program2);
        let script_root2 = note_script2.root();

        // Build a transaction context with both note scripts
        let tx_context = TransactionContextBuilder::with_existing_mock_account()
            .add_note_script(note_script1.clone())
            .add_note_script(note_script2.clone())
            .build()
            .expect("failed to build transaction context");

        // Assert that fetching both note scripts works
        let retrieved_script1 = tx_context
            .get_note_script(script_root1)
            .await
            .expect("failed to get note script 1")
            .expect("note script 1 should exist");
        assert_eq!(retrieved_script1, note_script1);

        let retrieved_script2 = tx_context
            .get_note_script(script_root2)
            .await
            .expect("failed to get note script 2")
            .expect("note script 2 should exist");
        assert_eq!(retrieved_script2, note_script2);

        // Fetching a non-existent one returns None
        let non_existent_root =
            Word::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
        let result = tx_context.get_note_script(non_existent_root).await;
        assert!(matches!(result, Ok(None)));
    }
}
