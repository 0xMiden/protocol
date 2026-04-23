//! Produce trace snapshots for `miden-vm`'s synthetic benchmark.
//!
//! Runs representative transaction contexts to build a real execution trace, extracts the hard
//! total lengths and an advisory chiplet breakdown, and writes one JSON snapshot per scenario under
//! `bin/bench-transaction/snapshots/`.
//!
//! The JSON schema is hand-maintained to match
//! `miden-vm/benches/synthetic-tx-kernel/src/snapshot.rs`. The trace-build path mirrors
//! `LocalTransactionProver::prove`'s setup up to (but not including) the prove step.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use bench_transaction::context_setups::{tx_consume_single_p2id_note, tx_consume_two_p2id_notes};
use miden_core::program::ProgramInfo;
use miden_processor::FastProcessor;
use miden_processor::trace::build_trace;
use miden_protocol::transaction::{TransactionInputs, TransactionKernel};
use miden_testing::TransactionContext;
use miden_tx::{
    AccountProcedureIndexMap,
    ExecutionOptions,
    ScriptMastForestStore,
    TransactionMastStore,
    TransactionProverHost,
};
use serde::Serialize;

#[derive(Serialize)]
struct TraceSnapshot {
    schema_version: &'static str,
    source: String,
    timestamp: String,
    miden_vm_version: &'static str,
    trace: TraceTotals,
    shape: TraceBreakdown,
}

#[derive(Serialize)]
struct TraceTotals {
    core_rows: u64,
    chiplets_rows: u64,
    range_rows: u64,
}

#[derive(Serialize)]
struct TraceBreakdown {
    hasher_rows: u64,
    bitwise_rows: u64,
    memory_rows: u64,
    kernel_rom_rows: u64,
    ace_rows: u64,
}

const MIDEN_VM_VERSION: &str = "0.22";
const SCHEMA_VERSION: &str = "0";

type TxBuilder = fn() -> Result<TransactionContext>;

struct CapturedShape {
    trace: TraceTotals,
    shape: TraceBreakdown,
}

async fn capture_trace_shape(context: TransactionContext) -> Result<CapturedShape> {
    // Execute first so the authenticator resolves any signatures; the resulting
    // `ExecutedTransaction` carries them into the prover-host setup below. The trace-build steps
    // that follow mirror `LocalTransactionProver::prove` (see `crates/miden-tx/src/prover/mod.rs`).
    let executed = context
        .execute()
        .await
        .context("pre-execution (to resolve signatures) failed")?;
    let tx_inputs: TransactionInputs = executed.into();
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

    let summary = trace.trace_len_summary();
    let chiplets = summary.chiplets_trace_len();
    let shape = TraceBreakdown {
        hasher_rows: chiplets.hash_chiplet_len() as u64,
        bitwise_rows: chiplets.bitwise_chiplet_len() as u64,
        memory_rows: chiplets.memory_chiplet_len() as u64,
        kernel_rom_rows: chiplets.kernel_rom_len() as u64,
        // TODO: replace this with `chiplets.ace_chiplet_len()` once the protocol-side
        // `miden-processor` dependency exposes that accessor.
        ace_rows: 0,
    };
    let trace_totals = TraceTotals {
        core_rows: summary.main_trace_len() as u64,
        chiplets_rows: chiplets.trace_len() as u64,
        range_rows: summary.range_trace_len() as u64,
    };
    Ok(CapturedShape { trace: trace_totals, shape })
}

fn timestamp_string() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => format!("unix-{}", d.as_secs()),
        Err(_) => "unix-unknown".to_string(),
    }
}

// Matches `TraceBreakdown::chiplets_sum` in the consumer.
fn chiplets_sum(b: &TraceBreakdown) -> u64 {
    b.hasher_rows + b.bitwise_rows + b.memory_rows + b.kernel_rom_rows + b.ace_rows + 1
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let out_dir = PathBuf::from("bin/bench-transaction/snapshots");
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;

    let txs: &[(&str, TxBuilder)] = &[
        ("consume-single-p2id", tx_consume_single_p2id_note),
        ("consume-two-p2id", tx_consume_two_p2id_notes),
    ];

    for (name, build_ctx) in txs {
        let context =
            build_ctx().with_context(|| format!("failed to build tx context for {name}"))?;
        let captured = capture_trace_shape(context)
            .await
            .with_context(|| format!("failed to capture trace shape for {name}"))?;

        // Mirror the consumer-side consistency check so we don't write an inconsistent snapshot
        // to disk.
        let expected_chiplets = chiplets_sum(&captured.shape);
        if captured.trace.chiplets_rows != expected_chiplets {
            anyhow::bail!(
                "inconsistent trace shape for {name}: trace.chiplets_rows = {}, shape sum = {}",
                captured.trace.chiplets_rows,
                expected_chiplets,
            );
        }

        let snapshot = TraceSnapshot {
            schema_version: SCHEMA_VERSION,
            source: format!("protocol/bench-transaction:{name}"),
            timestamp: timestamp_string(),
            miden_vm_version: MIDEN_VM_VERSION,
            trace: captured.trace,
            shape: captured.shape,
        };

        let path = out_dir.join(format!("{name}.json"));
        let json =
            serde_json::to_string_pretty(&snapshot).context("failed to serialize snapshot")?;
        std::fs::write(&path, json)
            .with_context(|| format!("failed to write {}", path.display()))?;

        println!(
            "{}: core={} chiplets={} hasher={} bitwise={} memory={} kernel_rom={}",
            path.display(),
            snapshot.trace.core_rows,
            snapshot.trace.chiplets_rows,
            snapshot.shape.hasher_rows,
            snapshot.shape.bitwise_rows,
            snapshot.shape.memory_rows,
            snapshot.shape.kernel_rom_rows,
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    const MIN_TRACE_LEN: u64 = 64;

    #[derive(Deserialize)]
    struct SnapshotForTest {
        schema_version: String,
        source: String,
        timestamp: String,
        miden_vm_version: String,
        trace: TraceTotalsForTest,
        shape: TraceBreakdownForTest,
    }

    #[derive(Deserialize)]
    struct TraceTotalsForTest {
        core_rows: u64,
        chiplets_rows: u64,
        range_rows: u64,
    }

    #[derive(Deserialize)]
    struct TraceBreakdownForTest {
        hasher_rows: u64,
        bitwise_rows: u64,
        memory_rows: u64,
        kernel_rom_rows: u64,
        ace_rows: u64,
    }

    impl TraceTotalsForTest {
        fn padded_core_side(&self) -> u64 {
            self.core_rows.max(self.range_rows).next_power_of_two().max(MIN_TRACE_LEN)
        }

        fn padded_chiplets(&self) -> u64 {
            self.chiplets_rows.next_power_of_two().max(MIN_TRACE_LEN)
        }

        fn padded_total(&self) -> u64 {
            self.core_rows
                .max(self.range_rows)
                .max(self.chiplets_rows)
                .next_power_of_two()
                .max(MIN_TRACE_LEN)
        }

        fn range_dominates(&self) -> bool {
            self.range_rows > self.core_rows && self.range_rows > self.chiplets_rows
        }
    }

    struct ExpectedBrackets {
        padded_core_side: u64,
        padded_chiplets: u64,
        padded_total: u64,
        range_dominates: bool,
    }

    fn assert_snapshot_contract(name: &str, json: &str, expected: ExpectedBrackets) {
        let snapshot: SnapshotForTest =
            serde_json::from_str(json).expect("snapshot should match the schema");

        assert_eq!(snapshot.schema_version, SCHEMA_VERSION);
        assert_eq!(snapshot.source, format!("protocol/bench-transaction:{name}"));
        assert_eq!(snapshot.miden_vm_version, MIDEN_VM_VERSION);
        assert!(snapshot.timestamp.starts_with("unix-"));
        assert!(snapshot.trace.core_rows > 0);
        assert!(snapshot.trace.chiplets_rows > 0);
        assert!(snapshot.trace.range_rows > 0);
        assert_eq!(
            snapshot.trace.chiplets_rows,
            snapshot.shape.hasher_rows
                + snapshot.shape.bitwise_rows
                + snapshot.shape.memory_rows
                + snapshot.shape.kernel_rom_rows
                + snapshot.shape.ace_rows
                + 1,
        );

        let formula_padded_core_side = snapshot
            .trace
            .core_rows
            .max(snapshot.trace.range_rows)
            .next_power_of_two()
            .max(MIN_TRACE_LEN);
        let formula_padded_chiplets =
            snapshot.trace.chiplets_rows.next_power_of_two().max(MIN_TRACE_LEN);
        let formula_padded_total = snapshot
            .trace
            .core_rows
            .max(snapshot.trace.range_rows)
            .max(snapshot.trace.chiplets_rows)
            .next_power_of_two()
            .max(MIN_TRACE_LEN);
        let formula_range_dominates = snapshot.trace.range_rows > snapshot.trace.core_rows
            && snapshot.trace.range_rows > snapshot.trace.chiplets_rows;

        assert_eq!(snapshot.trace.padded_core_side(), formula_padded_core_side);
        assert_eq!(snapshot.trace.padded_chiplets(), formula_padded_chiplets);
        assert_eq!(snapshot.trace.padded_total(), formula_padded_total);
        assert_eq!(snapshot.trace.range_dominates(), formula_range_dominates);

        assert_eq!(snapshot.trace.padded_core_side(), expected.padded_core_side);
        assert_eq!(snapshot.trace.padded_chiplets(), expected.padded_chiplets);
        assert_eq!(snapshot.trace.padded_total(), expected.padded_total);
        assert_eq!(snapshot.trace.range_dominates(), expected.range_dominates);

        assert!(snapshot.trace.padded_core_side() > 0);
        assert!(snapshot.trace.padded_core_side().is_power_of_two());
        assert!(snapshot.trace.padded_chiplets() > 0);
        assert!(snapshot.trace.padded_chiplets().is_power_of_two());
        assert!(snapshot.trace.padded_total() > 0);
        assert!(snapshot.trace.padded_total().is_power_of_two());
    }

    #[test]
    fn committed_snapshots_match_schema() {
        assert_snapshot_contract(
            "consume-single-p2id",
            include_str!("../../snapshots/consume-single-p2id.json"),
            ExpectedBrackets {
                padded_core_side: 131_072,
                padded_chiplets: 131_072,
                padded_total: 131_072,
                range_dominates: false,
            },
        );
        assert_snapshot_contract(
            "consume-two-p2id",
            include_str!("../../snapshots/consume-two-p2id.json"),
            ExpectedBrackets {
                padded_core_side: 131_072,
                padded_chiplets: 262_144,
                padded_total: 262_144,
                range_dominates: false,
            },
        );
    }
}
