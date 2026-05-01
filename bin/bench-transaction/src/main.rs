use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

mod context_setups;
use context_setups::{
    ClaimDataSource,
    tx_consume_b2agg_note,
    tx_consume_claim_note,
    tx_consume_single_p2id_note,
    tx_consume_two_p2id_notes,
    tx_create_single_p2id_note,
};

mod cycle_counting_benchmarks;
use cycle_counting_benchmarks::ExecutionBenchmark;
use cycle_counting_benchmarks::trace_capture::capture_measurements_and_trace_summary;
use cycle_counting_benchmarks::utils::{MeasurementsPrinter, write_bench_results_to_json};
use miden_testing::TransactionContext;

async fn run_scenario(
    bench: ExecutionBenchmark,
    context: TransactionContext,
) -> Result<(ExecutionBenchmark, MeasurementsPrinter)> {
    let (measurements, trace) = capture_measurements_and_trace_summary(context)
        .await
        .with_context(|| format!("failed to capture measurements for `{bench}`"))?;
    Ok((bench, MeasurementsPrinter::from_parts(measurements, trace)))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // create a template file for benchmark results
    let path = Path::new("bin/bench-transaction/bench-tx.json");
    let mut file = File::create(path).context("failed to create file")?;
    file.write_all(b"{}").context("failed to write to file")?;

    let benchmark_results = vec![
        run_scenario(ExecutionBenchmark::ConsumeSingleP2ID, tx_consume_single_p2id_note()?).await?,
        run_scenario(ExecutionBenchmark::ConsumeTwoP2ID, tx_consume_two_p2id_notes()?).await?,
        run_scenario(ExecutionBenchmark::CreateSingleP2ID, tx_create_single_p2id_note()?).await?,
        run_scenario(
            ExecutionBenchmark::ConsumeClaimNoteL1ToMiden,
            tx_consume_claim_note(ClaimDataSource::L1ToMiden).await?,
        )
        .await?,
        run_scenario(
            ExecutionBenchmark::ConsumeClaimNoteL2ToMiden,
            tx_consume_claim_note(ClaimDataSource::L2ToMiden).await?,
        )
        .await?,
        run_scenario(ExecutionBenchmark::ConsumeB2AggNote, tx_consume_b2agg_note().await?).await?,
    ];

    // store benchmark results in the JSON file
    write_bench_results_to_json(path, benchmark_results)?;

    Ok(())
}
