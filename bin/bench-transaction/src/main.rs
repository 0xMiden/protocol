use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use bench_transaction::context_setups::build_benchmark_context;
use bench_transaction::cycle_counting_benchmarks::ExecutionBenchmark;
use bench_transaction::cycle_counting_benchmarks::trace_capture::capture_measurements_and_trace_summary;
use bench_transaction::cycle_counting_benchmarks::utils::{
    MeasurementsPrinter,
    write_bench_results_to_json,
};

async fn run_scenario(
    bench: ExecutionBenchmark,
) -> Result<(ExecutionBenchmark, MeasurementsPrinter, u32)> {
    let mock_tx = build_benchmark_context(bench)
        .await
        .with_context(|| format!("failed to build mock transaction for `{bench}`"))?;
    let (measurements, trace, note_labels) = capture_measurements_and_trace_summary(mock_tx)
        .await
        .with_context(|| format!("failed to capture measurements for `{bench}`"))?;
    let total_cycles = u32::try_from(measurements.total_cycles())
        .context("total cycle count does not fit into u32")?;
    let printer = MeasurementsPrinter::from_parts(measurements, trace, &note_labels)
        .with_context(|| format!("failed to render measurements for `{bench}`"))?;
    Ok((bench, printer, total_cycles))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let update_costs = match std::env::args().nth(1).as_deref() {
        None => false,
        Some("update-note-costs") => true,
        Some(other) => anyhow::bail!("unknown argument `{other}`; expected `update-note-costs`"),
    };

    // create a template file for benchmark results
    let path = Path::new("bin/bench-transaction/bench-tx.json");
    let mut file = File::create(path).context("failed to create file")?;
    file.write_all(b"{}").context("failed to write to file")?;

    let mut benchmark_results = Vec::new();
    let mut measured_cycles = BTreeMap::new();
    for &bench in ExecutionBenchmark::all() {
        let (bench, printer, total_cycles) = run_scenario(bench).await?;
        measured_cycles.insert(bench, total_cycles);
        benchmark_results.push((bench, printer));
    }

    // store benchmark results in the JSON file
    write_bench_results_to_json(path, benchmark_results)?;

    if update_costs {
        bench_transaction::note_costs::update_cost_tables(&measured_cycles)?;
    }

    Ok(())
}
