use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{AccountDelta, PartialAccount};
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    OutputNote,
    ProvenTransaction,
    ProvenTransactionBuilder,
    TransactionInputs,
    TransactionKernel,
    TransactionOutputs,
};
pub use miden_prover::ProvingOptions;
use miden_prover::{ExecutionProof, Word, prove};

use super::TransactionProverError;
use crate::host::{AccountProcedureIndexMap, ScriptMastForestStore};

mod prover_host;
pub use prover_host::TransactionProverHost;

mod mast_store;
pub use mast_store::TransactionMastStore;

// LOCAL TRANSACTION PROVER
// ------------------------------------------------------------------------------------------------

/// Local Transaction prover is a stateless component which is responsible for proving transactions.
pub struct LocalTransactionProver {
    mast_store: Arc<TransactionMastStore>,
    proof_options: ProvingOptions,
}

impl LocalTransactionProver {
    /// Creates a new [LocalTransactionProver] instance.
    pub fn new(proof_options: ProvingOptions) -> Self {
        Self {
            mast_store: Arc::new(TransactionMastStore::new()),
            proof_options,
        }
    }

    fn build_proven_transaction(
        &self,
        input_notes: &InputNotes<InputNote>,
        tx_outputs: TransactionOutputs,
        pre_fee_account_delta: AccountDelta,
        account: PartialAccount,
        ref_block_num: BlockNumber,
        ref_block_commitment: Word,
        proof: ExecutionProof,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        // erase private note information (convert private full notes to just headers)
        let output_notes: Vec<_> = tx_outputs.output_notes.iter().map(OutputNote::shrink).collect();

        // Compute the commitment of the pre-fee delta, which goes into the proven transaction,
        // since it is the output of the transaction and so is needed for proof verification.
        let pre_fee_delta_commitment: Word = pre_fee_account_delta.to_commitment();

        let builder = ProvenTransactionBuilder::new(
            account.id(),
            account.initial_commitment(),
            tx_outputs.account.commitment(),
            pre_fee_delta_commitment,
            ref_block_num,
            ref_block_commitment,
            tx_outputs.fee,
            tx_outputs.expiration_block_num,
            proof,
        )
        .add_input_notes(input_notes)
        .add_output_notes(output_notes);

        // The full transaction delta is the pre fee delta with the fee asset removed.
        let mut post_fee_account_delta = pre_fee_account_delta;
        post_fee_account_delta
            .vault_mut()
            .remove_asset(Asset::from(tx_outputs.fee))
            .map_err(TransactionProverError::RemoveFeeAssetFromDelta)?;

        let builder = match account.has_public_state() {
            true => {
                let account_update_details = AccountUpdateDetails::Delta(post_fee_account_delta);
                builder.account_update_details(account_update_details)
            },
            false => builder,
        };

        builder.build().map_err(TransactionProverError::ProvenTransactionBuildFailed)
    }

    pub fn prove(
        &self,
        tx_inputs: impl Into<TransactionInputs>,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        let tx_inputs = tx_inputs.into();
        let (stack_inputs, advice_inputs) = TransactionKernel::prepare_inputs(&tx_inputs);

        self.mast_store.load_account_code(tx_inputs.account().code());
        for account_code in tx_inputs.foreign_account_code() {
            self.mast_store.load_account_code(account_code);
        }

        let script_mast_store = ScriptMastForestStore::new(
            tx_inputs.tx_script(),
            tx_inputs.input_notes().iter().map(|n| n.note().script()),
        );

        let account_procedure_index_map = AccountProcedureIndexMap::new(
            tx_inputs.foreign_account_code().iter().chain([tx_inputs.account().code()]),
        );

        let (partial_account, ref_block, _, input_notes, _) = tx_inputs.into_parts();
        let mut host = TransactionProverHost::new(
            &partial_account,
            input_notes,
            self.mast_store.as_ref(),
            script_mast_store,
            account_procedure_index_map,
        );

        let advice_inputs = advice_inputs.into_advice_inputs();

        let (stack_outputs, proof) = prove(
            &TransactionKernel::main(),
            stack_inputs,
            advice_inputs.clone(),
            &mut host,
            self.proof_options.clone(),
        )
        .map_err(TransactionProverError::TransactionProgramExecutionFailed)?;

        // Extract transaction outputs and process transaction data.
        // Note that the account delta does not contain the removed transaction fee, so it is the
        // "pre-fee" delta of the transaction.
        let (pre_fee_account_delta, input_notes, output_notes) = host.into_parts();
        let tx_outputs =
            TransactionKernel::from_transaction_parts(&stack_outputs, &advice_inputs, output_notes)
                .map_err(TransactionProverError::TransactionOutputConstructionFailed)?;

        self.build_proven_transaction(
            &input_notes,
            tx_outputs,
            pre_fee_account_delta,
            partial_account,
            ref_block.block_num(),
            ref_block.commitment(),
            proof,
        )
    }
}

impl Default for LocalTransactionProver {
    fn default() -> Self {
        Self {
            mast_store: Arc::new(TransactionMastStore::new()),
            proof_options: Default::default(),
        }
    }
}

#[cfg(any(feature = "testing", test))]
impl LocalTransactionProver {
    pub fn prove_dummy(
        &self,
        executed_transaction: miden_protocol::transaction::ExecutedTransaction,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        let (tx_inputs, tx_outputs, account_delta, _) = executed_transaction.into_parts();

        let (partial_account, ref_block, _, input_notes, _) = tx_inputs.into_parts();

        self.build_proven_transaction(
            &input_notes,
            tx_outputs,
            account_delta,
            partial_account,
            ref_block.block_num(),
            ref_block.commitment(),
            ExecutionProof::new_dummy(),
        )
    }
}
