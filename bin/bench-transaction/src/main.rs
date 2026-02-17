use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use miden_protocol::transaction::TransactionMeasurements;

mod context_setups;
use context_setups::{
    tx_consume_single_p2id_note,
    tx_consume_two_p2id_notes,
    tx_create_single_p2id_note,
};

mod cycle_counting_benchmarks;
use cycle_counting_benchmarks::ExecutionBenchmark;
use cycle_counting_benchmarks::utils::write_bench_results_to_json;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // create a template file for benchmark results
    let path = Path::new("bin/bench-transaction/bench-tx.json");
    let mut file = File::create(path).context("failed to create file")?;
    file.write_all(b"{}").context("failed to write to file")?;

    // run all available benchmarks
    let benchmark_results = vec![
        (
            ExecutionBenchmark::ConsumeSingleP2ID,
            tx_consume_single_p2id_note()?
                .execute()
                .await
                .map(TransactionMeasurements::from)?
                .into(),
        ),
        (
            ExecutionBenchmark::ConsumeTwoP2ID,
            tx_consume_two_p2id_notes()?
                .execute()
                .await
                .map(TransactionMeasurements::from)?
                .into(),
        ),
        (
            ExecutionBenchmark::CreateSingleP2ID,
            tx_create_single_p2id_note()?
                .execute()
                .await
                .map(TransactionMeasurements::from)?
                .into(),
        ),
    ];

    // store benchmark results in the JSON file
    write_bench_results_to_json(path, benchmark_results)?;

    Ok(())
}
