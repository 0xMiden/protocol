//! Capture per-component trace lengths alongside cycle measurements.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use miden_processor::FastProcessor;
use miden_processor::trace::{TraceLenSummary, build_trace};
use miden_protocol::transaction::{
    AccountInputs,
    TransactionInputs,
    TransactionKernel,
    TransactionMeasurements,
};
use miden_testing::MockTransaction;
use miden_tx::{
    AccountProcedureIndexMap,
    ExecutionOptions,
    ScriptMastForestStore,
    TransactionMastStore,
    TransactionProverHost,
};

use crate::note_labels::NoteLabels;

/// Executes the transaction, then replays its inputs through the trace-build path to capture a
/// `TraceLenSummary`. Also resolves the stable labels of the transaction's input notes, which the
/// measurements are reported under.
///
/// Two passes: `TransactionExecutor` first so the authenticator resolves any required signatures
/// into the `ExecutedTransaction`'s inputs, then `LocalTransactionProver::prove`'s trace-build
/// setup against those inputs (minus the prove step). The duplicate run is per-bench, not
/// per-iteration.
pub async fn capture_measurements_and_trace_summary(
    mock_tx: MockTransaction,
) -> Result<(TransactionMeasurements, TraceLenSummary, NoteLabels)> {
    let executed = mock_tx
        .execute()
        .await
        .context("pre-execution (to resolve signatures) failed")?;
    let (tx_inputs, _tx_outputs, _account_patch, measurements) = executed.into_parts();

    // resolved before `tx_inputs` is consumed by the trace-build pass
    let note_labels = NoteLabels::from_inputs(&tx_inputs);
    let trace_summary = build_trace_summary(tx_inputs).await?;

    Ok((measurements, trace_summary, note_labels))
}

// TODO(#2841): integrate `TraceLenSummary` into `TransactionMeasurements` so we can drop this
// duplicate-execute path. See https://github.com/0xMiden/protocol/issues/2841.
async fn build_trace_summary(tx_inputs: TransactionInputs) -> Result<TraceLenSummary> {
    let (stack_inputs, tx_advice_inputs) = TransactionKernel::prepare_inputs(&tx_inputs);

    let mast_store = Arc::new(TransactionMastStore::new());
    mast_store.load_account_code(tx_inputs.account().code());
    for foreign_account in tx_inputs.foreign_accounts().values() {
        mast_store.load_account_code(foreign_account.code());
    }

    let script_mast_store = ScriptMastForestStore::new(
        tx_inputs.tx_script(),
        tx_inputs.input_notes().iter().map(|n| n.note().script()),
    );
    let account_procedure_index_map = AccountProcedureIndexMap::new(
        tx_inputs
            .foreign_accounts()
            .values()
            .map(AccountInputs::code)
            .chain([tx_inputs.account().code()]),
    );

    let block_commitments = tx_inputs.collect_block_commitments();

    let (partial_account, _ref_block, _blockchain, input_notes, _tx_args) = tx_inputs.into_parts();
    let mut host = TransactionProverHost::new(
        &partial_account,
        input_notes,
        block_commitments,
        mast_store.as_ref(),
        script_mast_store,
        account_procedure_index_map,
    )
    .context("failed to construct transaction prover host")?;

    let advice_inputs = tx_advice_inputs.into_advice_inputs();
    let program = TransactionKernel::main();

    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .context("failed to construct FastProcessor for trace capture")?;
    let execution_witness = processor
        .execute_for_proving(&program, &mut host)
        .await
        .context("failed to execute transaction kernel for trace")?;
    let (vm_witness, _precompile_witness) = execution_witness.into_parts();
    let trace = build_trace(vm_witness).context("failed to build trace from execution output")?;

    Ok(*trace.trace_len_summary())
}
