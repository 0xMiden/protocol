//! Capture per-component trace lengths alongside cycle measurements.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use miden_core::program::ProgramInfo;
use miden_processor::FastProcessor;
use miden_processor::trace::{TraceLenSummary, build_trace};
use miden_protocol::transaction::{TransactionInputs, TransactionKernel, TransactionMeasurements};
use miden_testing::TransactionContext;
use miden_tx::{
    AccountProcedureIndexMap,
    ExecutionOptions,
    ScriptMastForestStore,
    TransactionMastStore,
    TransactionProverHost,
};

/// Executes the transaction, then replays its inputs through the trace-build path to capture a
/// `TraceLenSummary`.
///
/// Two passes: `TransactionExecutor` first so the authenticator resolves any required signatures
/// into the `ExecutedTransaction`'s inputs, then `LocalTransactionProver::prove`'s trace-build
/// setup against those inputs (minus the prove step). The duplicate run is per-bench, not
/// per-iteration.
pub async fn capture_measurements_and_trace_summary(
    context: TransactionContext,
) -> Result<(TransactionMeasurements, TraceLenSummary)> {
    let executed = context
        .execute()
        .await
        .context("pre-execution (to resolve signatures) failed")?;
    let (tx_inputs, _tx_outputs, _account_delta, measurements) = executed.into_parts();

    let trace_summary = build_trace_summary(tx_inputs).await?;

    Ok((measurements, trace_summary))
}

async fn build_trace_summary(tx_inputs: TransactionInputs) -> Result<TraceLenSummary> {
    let (stack_inputs, tx_advice_inputs) = TransactionKernel::prepare_inputs(&tx_inputs);

    let mast_store = Arc::new(TransactionMastStore::new());
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

    let (partial_account, _ref_block, _blockchain, input_notes, _tx_args) = tx_inputs.into_parts();
    let mut host = TransactionProverHost::new(
        &partial_account,
        input_notes,
        mast_store.as_ref(),
        script_mast_store,
        account_procedure_index_map,
    );

    let advice_inputs = tx_advice_inputs.into_advice_inputs();
    let program = TransactionKernel::main();

    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default());
    let (execution_output, trace_generation_context) = processor
        .execute_for_trace(&program, &mut host)
        .await
        .context("failed to execute transaction kernel for trace")?;
    let program_info = ProgramInfo::from(program.clone());
    let trace = build_trace(execution_output, trace_generation_context, program_info)
        .context("failed to build trace from execution output")?;

    Ok(*trace.trace_len_summary())
}
