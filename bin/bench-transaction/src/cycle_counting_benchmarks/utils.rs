extern crate alloc;
pub use alloc::collections::BTreeMap;
pub use alloc::string::String;
use std::fs::{read_to_string, write};
use std::path::Path;

use anyhow::Context;
use miden_protocol::transaction::TransactionMeasurements;
use serde::Serialize;
use serde_json::{Value, from_str, to_string_pretty};

use super::ExecutionBenchmark;

// MEASUREMENTS PRINTER
// ================================================================================================

/// Helper structure holding the cycle count of each transaction stage which could be easily
/// converted to the JSON file.
#[derive(Debug, Clone, Serialize)]
pub struct MeasurementsPrinter {
    prologue: usize,
    notes_processing: usize,
    note_execution: BTreeMap<String, usize>,
    tx_script_processing: usize,
    epilogue: EpilogueMeasurements,
}

impl From<TransactionMeasurements> for MeasurementsPrinter {
    fn from(tx_measurements: TransactionMeasurements) -> Self {
        let note_execution_map = tx_measurements
            .note_execution
            .iter()
            .map(|(id, len)| (id.to_hex(), *len))
            .collect();

        MeasurementsPrinter {
            prologue: tx_measurements.prologue,
            notes_processing: tx_measurements.notes_processing,
            note_execution: note_execution_map,
            tx_script_processing: tx_measurements.tx_script_processing,
            epilogue: EpilogueMeasurements::from_parts(
                tx_measurements.epilogue,
                tx_measurements.auth_procedure,
                tx_measurements.after_tx_cycles_obtained,
            ),
        }
    }
}

/// Helper structure holding the cycle count for different intervals in the epilogue, namely:
/// - `total` interval holds the total number of cycles required to execute the epilogue
/// - `auth_procedure` interval holds the number of cycles required to execute the authentication
///   procedure
/// - `after_tx_cycles_obtained` holds the number of cycles which was executed from the moment of
///   the cycle count obtainment in the `epilogue::compute_fee` procedure to the end of the
///   epilogue.
#[derive(Debug, Clone, Serialize)]
struct EpilogueMeasurements {
    total: usize,
    auth_procedure: usize,
    after_tx_cycles_obtained: usize,
}

impl EpilogueMeasurements {
    pub fn from_parts(
        total: usize,
        auth_procedure: usize,
        after_tx_cycles_obtained: usize,
    ) -> Self {
        Self {
            total,
            auth_procedure,
            after_tx_cycles_obtained,
        }
    }
}

/// Writes the provided benchmark results to the JSON file at the provided path.
pub fn write_bench_results_to_json(
    path: &Path,
    tx_benchmarks: Vec<(ExecutionBenchmark, MeasurementsPrinter)>,
) -> anyhow::Result<()> {
    // convert benchmark file internals to the JSON Value
    let benchmark_file = read_to_string(path).context("failed to read benchmark file")?;
    let mut benchmark_json: Value =
        from_str(&benchmark_file).context("failed to convert benchmark contents to json")?;

    // fill benchmarks JSON with results of each benchmark
    for (bench_type, tx_progress) in tx_benchmarks {
        let tx_benchmark_json = serde_json::to_value(tx_progress)
            .context("failed to convert tx measurements to json")?;

        benchmark_json[bench_type.to_string()] = tx_benchmark_json;
    }

    // write the benchmarks JSON to the results file
    write(
        path,
        to_string_pretty(&benchmark_json).expect("failed to convert json to String"),
    )
    .context("failed to write benchmark results to file")?;

    Ok(())
}
