use alloc::vec::Vec;

use miden_processor::{ExecutionError, ExecutionOptions, FastProcessor};
use miden_protocol::account::{AccountPatch, AccountUpdateDetails, PartialAccount};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    ProvenTransaction,
    TransactionInputs,
    TransactionKernel,
    TransactionOutputs,
    TxAccountUpdate,
};
use miden_prover::HashFunction::Poseidon2;
pub use miden_prover::Prover;
use miden_prover::{ExecutionProof, Word};

use super::TransactionProverError;
use crate::host::{AccountProcedureIndexMap, ScriptMastForestStore};

mod prover_host;
pub use prover_host::TransactionProverHost;

mod mast_store;
pub use mast_store::TransactionMastStore;

// LOCAL TRANSACTION PROVER
// ------------------------------------------------------------------------------------------------

/// Local Transaction prover is a stateless component which is responsible for proving transactions.
///
/// The produced proof covers the VM execution only. Precompile claims are left deferred, because a
/// batch settles the claims of all its transactions with a single precompile proof.
///
/// Each `prove()` call creates a fresh [`TransactionMastStore`] loaded with only the current
/// transaction's account code, ensuring no state accumulates across calls. This is important
/// in WASM environments where accumulated MAST forests fragment the linear memory.
#[derive(Debug, Clone)]
pub struct LocalTransactionProver {
    prover: Prover,
    execution_options: ExecutionOptions,
}

impl Default for LocalTransactionProver {
    fn default() -> Self {
        Self::new(Prover::new().with_hash_fn(Poseidon2))
    }
}

impl LocalTransactionProver {
    /// Creates a new [LocalTransactionProver] instance with the default [`ExecutionOptions`].
    pub fn new(prover: Prover) -> Self {
        Self {
            prover,
            execution_options: ExecutionOptions::default(),
        }
    }

    /// Sets the [`ExecutionOptions`] used while proving and returns the resulting prover.
    ///
    /// This lets a caller tune the VM limits enforced during proving, so that proving can use the
    /// same options as execution.
    ///
    /// This will overwrite any previously set options.
    #[must_use]
    pub fn with_execution_options(mut self, execution_options: ExecutionOptions) -> Self {
        self.execution_options = execution_options;
        self
    }

    /// Returns the [`ExecutionOptions`] this prover uses.
    pub fn execution_options(&self) -> ExecutionOptions {
        self.execution_options
    }

    fn build_proven_transaction(
        &self,
        input_notes: &InputNotes<InputNote>,
        tx_outputs: TransactionOutputs,
        account_patch: AccountPatch,
        account: PartialAccount,
        ref_block_num: BlockNumber,
        ref_block_commitment: Word,
        proof: ExecutionProof,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        let expiration_block_num = tx_outputs.expiration_block_num();
        let (account_header, output_notes) = tx_outputs.into_parts();

        // erase private note information (convert private full notes to just headers)
        let output_notes: Vec<_> = output_notes
            .into_iter()
            .map(|note| note.into_output_note())
            .collect::<Result<Vec<_>, _>>()
            .map_err(TransactionProverError::OutputNoteShrinkFailed)?;

        // Compute the commitment of the patch, which goes into the proven transaction since it is
        // the output of the transaction and so is needed for proof verification.
        let patch_commitment: Word = account_patch.to_commitment();

        let account_update_details = if account.id().is_public() {
            AccountUpdateDetails::Public(account_patch)
        } else {
            AccountUpdateDetails::Private
        };

        let account_update = TxAccountUpdate::new(
            account.id(),
            account.initial_commitment(),
            account_header.to_commitment(),
            patch_commitment,
            account_update_details,
        )
        .map_err(TransactionProverError::ProvenTransactionBuildFailed)?;

        ProvenTransaction::new(
            account_update,
            input_notes.iter(),
            output_notes,
            ref_block_num,
            ref_block_commitment,
            expiration_block_num,
            proof,
        )
        .map_err(TransactionProverError::ProvenTransactionBuildFailed)
    }

    pub fn prove(
        &self,
        tx_inputs: impl Into<TransactionInputs>,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        let tx_inputs = tx_inputs.into();
        let (stack_inputs, advice_inputs) = TransactionKernel::prepare_inputs(&tx_inputs);

        // Create a per-call MAST store to avoid accumulating forests across prove
        // calls. Using the shared self.mast_store would grow monotonically (each
        // call adds account code that is never removed), fragmenting WASM linear
        // memory and eventually causing capacity_overflow panics. A per-call store
        // also avoids races: prove() takes &self, so concurrent calls would
        // conflict on a shared mutable store.
        let mast_store = TransactionMastStore::new();
        mast_store.load_account_code(tx_inputs.account().code());
        for account_code in tx_inputs.foreign_account_code() {
            mast_store.load_account_code(account_code);
        }

        let script_mast_store = ScriptMastForestStore::new(
            tx_inputs.tx_script(),
            tx_inputs.input_notes().iter().map(|n| n.note().script()),
        );

        let account_procedure_index_map = AccountProcedureIndexMap::new(
            tx_inputs.foreign_account_code().iter().chain([tx_inputs.account().code()]),
        );

        let block_commitments = tx_inputs.collect_block_commitments();

        let (partial_account, ref_block, _, input_notes, tx_args) = tx_inputs.into_parts();
        let mut host = TransactionProverHost::new(
            &partial_account,
            input_notes,
            block_commitments,
            &mast_store,
            script_mast_store,
            account_procedure_index_map,
            tx_args.account_code_upgrade().cloned(),
        )
        .map_err(TransactionProverError::TransactionHostConstructionFailed)?;

        let advice_inputs = advice_inputs.into_advice_inputs();

        let processor = FastProcessor::new_with_options(
            stack_inputs,
            advice_inputs.clone(),
            self.execution_options,
        )
        .map_err(ExecutionError::advice_error_no_context)
        .map_err(TransactionProverError::TransactionProgramExecutionFailed)?;

        let witness = processor
            .execute_for_proving_sync(&TransactionKernel::main(), &mut host)
            .map_err(TransactionProverError::TransactionProgramExecutionFailed)?;
        let stack_outputs = *witness.claim().stack_outputs();

        let proof = self
            .prover
            .prove(witness)
            .map_err(TransactionProverError::TransactionProofGenerationFailed)?;

        // Extract transaction outputs and process transaction data.
        let (account_patch, input_notes, output_notes) = host.into_parts();
        let tx_outputs =
            TransactionKernel::from_transaction_parts(&stack_outputs, &advice_inputs, output_notes)
                .map_err(TransactionProverError::TransactionOutputConstructionFailed)?;

        self.build_proven_transaction(
            &input_notes,
            tx_outputs,
            account_patch,
            partial_account,
            ref_block.block_num(),
            ref_block.commitment(),
            proof,
        )
    }
}

#[cfg(any(feature = "testing", test))]
impl LocalTransactionProver {
    pub fn prove_dummy(
        &self,
        executed_transaction: miden_protocol::transaction::ExecutedTransaction,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        self.prove_with_dummy(
            executed_transaction,
            miden_protocol::testing::dummy_execution_proof(),
        )
    }

    /// Returns a proven transaction carrying a structurally incomplete proof for verifier tests.
    pub fn prove_dummy_deferred(
        &self,
        executed_transaction: miden_protocol::transaction::ExecutedTransaction,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        self.prove_with_dummy(
            executed_transaction,
            miden_protocol::testing::dummy_deferred_execution_proof(),
        )
    }

    /// Returns a proven transaction carrying a complete proof with precompile work for verifier
    /// tests.
    pub fn prove_dummy_precompile(
        &self,
        executed_transaction: miden_protocol::transaction::ExecutedTransaction,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        self.prove_with_dummy(
            executed_transaction,
            miden_protocol::testing::dummy_precompile_execution_proof(),
        )
    }

    fn prove_with_dummy(
        &self,
        executed_transaction: miden_protocol::transaction::ExecutedTransaction,
        proof: ExecutionProof,
    ) -> Result<ProvenTransaction, TransactionProverError> {
        let (tx_inputs, tx_outputs, account_patch, _) = executed_transaction.into_parts();

        let (partial_account, ref_block, _, input_notes, _) = tx_inputs.into_parts();

        self.build_proven_transaction(
            &input_notes,
            tx_outputs,
            account_patch,
            partial_account,
            ref_block.block_num(),
            ref_block.commitment(),
            proof,
        )
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_execution_options_are_used_unless_replaced() {
        let prover = LocalTransactionProver::default();
        assert_eq!(prover.execution_options(), ExecutionOptions::default());

        let custom_options = ExecutionOptions::default().with_max_advice_size_bytes(1);
        let prover = prover.with_execution_options(custom_options);
        assert_eq!(prover.execution_options(), custom_options);
    }
}
