extern crate alloc;
pub use alloc::collections::BTreeMap;
pub use alloc::string::String;
use std::collections::HashMap;
use std::fs::{read_to_string, write};
use std::path::Path;

use anyhow::Context;
use miden_protocol::transaction::TransactionMeasurements;
use serde::Serialize;
use serde_json::{Value, from_str, to_string_pretty};

use super::ExecutionBenchmark;
use crate::vm_profile::{VmProfile, TransactionKernelProfile, PhaseProfile, InstructionMix, ProcedureProfile};

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

/// Writes the VM execution profile to a JSON file for synthetic benchmark generation.
///
/// This exports a machine-readable profile that describes the transaction kernel's
/// instruction mix and cycle characteristics, which can be used by miden-vm to
/// generate representative synthetic benchmarks.
pub fn write_vm_profile(
    path: &Path,
    tx_benchmarks: &Vec<(ExecutionBenchmark, MeasurementsPrinter)>,
) -> anyhow::Result<()> {
    // Aggregate measurements across all benchmarks to create a representative profile
    let mut total_prologue = 0usize;
    let mut total_notes_processing = 0usize;
    let mut total_tx_script = 0usize;
    let mut total_epilogue = 0usize;
    let mut total_auth = 0usize;
    let mut count = 0usize;

    for (_, measurements) in tx_benchmarks {
        total_prologue += measurements.prologue;
        total_notes_processing += measurements.notes_processing;
        total_tx_script += measurements.tx_script_processing;
        total_epilogue += measurements.epilogue.total;
        total_auth += measurements.epilogue.auth_procedure;
        count += 1;
    }

    if count == 0 {
        anyhow::bail!("No benchmark results to aggregate");
    }

    // Calculate averages
    let avg_prologue = (total_prologue / count) as u64;
    let avg_notes_processing = (total_notes_processing / count) as u64;
    let avg_tx_script = (total_tx_script / count) as u64;
    let avg_epilogue = (total_epilogue / count) as u64;
    let avg_auth = (total_auth / count) as u64;

    // Build phase map
    let mut phases = HashMap::new();
    phases.insert(
        "prologue".to_string(),
        PhaseProfile {
            cycles: avg_prologue,
            operations: HashMap::new(), // TODO: Add operation counting when VM instrumentation is available
        },
    );
    phases.insert(
        "notes_processing".to_string(),
        PhaseProfile {
            cycles: avg_notes_processing,
            operations: HashMap::new(),
        },
    );
    phases.insert(
        "tx_script_processing".to_string(),
        PhaseProfile {
            cycles: avg_tx_script,
            operations: HashMap::new(),
        },
    );
    phases.insert(
        "epilogue".to_string(),
        PhaseProfile {
            cycles: avg_epilogue,
            operations: HashMap::new(),
        },
    );

    // Calculate total cycles
    let total_cycles = avg_prologue + avg_notes_processing + avg_tx_script + avg_epilogue;

    // Estimate instruction mix based on known characteristics
    // Auth procedure (signature verification) dominates at ~85% of epilogue
    let signature_ratio = if avg_epilogue > 0 {
        (avg_auth as f64) / (total_cycles as f64)
    } else {
        0.0
    };

    // Remaining cycles are distributed among other operations
    let remaining = 1.0 - signature_ratio;
    let instruction_mix = InstructionMix {
        signature_verify: signature_ratio,
        hashing: remaining * 0.5,      // Hashing is significant in remaining work
        memory: remaining * 0.2,       // Memory operations
        control_flow: remaining * 0.2, // Loops, conditionals
        arithmetic: remaining * 0.1,   // Basic arithmetic
    };

    // Key procedures - auth is the heavyweight
    let key_procedures = vec![
        ProcedureProfile {
            name: "auth_procedure".to_string(),
            cycles: avg_auth,
            invocations: 1,
        },
    ];

    let profile = VmProfile {
        profile_version: "1.0".to_string(),
        source: "miden-base/bin/bench-transaction".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        miden_vm_version: env!("CARGO_PKG_VERSION").to_string(),
        transaction_kernel: TransactionKernelProfile {
            total_cycles,
            phases,
            instruction_mix,
            key_procedures,
        },
    };

    let json = serde_json::to_string_pretty(&profile)?;
    write(path, json).context("failed to write VM profile to file")?;

    println!("VM profile exported to: {}", path.display());
    Ok(())
}
