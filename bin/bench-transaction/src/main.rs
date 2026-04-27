use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

mod context_setups;
use context_setups::{
    tx_consume_single_p2id_note,
    tx_consume_two_p2id_notes,
    tx_create_single_p2id_note,
};

mod cycle_counting_benchmarks;
use cycle_counting_benchmarks::ExecutionBenchmark;
use cycle_counting_benchmarks::trace_capture::capture_measurements_and_trace_summary;
use cycle_counting_benchmarks::utils::{MeasurementsPrinter, write_bench_results_to_json};
use miden_testing::TransactionContext;

type ContextBuilder = fn() -> Result<TransactionContext>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // create a template file for benchmark results
    let path = Path::new("bin/bench-transaction/bench-tx.json");
    let mut file = File::create(path).context("failed to create file")?;
    file.write_all(b"{}").context("failed to write to file")?;

    let scenarios: &[(ExecutionBenchmark, ContextBuilder)] = &[
        (ExecutionBenchmark::ConsumeSingleP2ID, tx_consume_single_p2id_note),
        (ExecutionBenchmark::ConsumeTwoP2ID, tx_consume_two_p2id_notes),
        (ExecutionBenchmark::CreateSingleP2ID, tx_create_single_p2id_note),
    ];

    let mut benchmark_results = Vec::with_capacity(scenarios.len());
    for &(bench, build_ctx) in scenarios {
        let context =
            build_ctx().with_context(|| format!("failed to build tx context for `{bench}`"))?;
        let (measurements, trace) = capture_measurements_and_trace_summary(context)
            .await
            .with_context(|| format!("failed to capture measurements for `{bench}`"))?;
        benchmark_results.push((bench, MeasurementsPrinter::from_parts(measurements, trace)));
    }

    // store benchmark results in the JSON file
    write_bench_results_to_json(path, benchmark_results)?;

    Ok(())
}
