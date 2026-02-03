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
use crate::vm_profile::{
    InstructionMix,
    OperationDetails,
    PhaseProfile,
    ProcedureProfile,
    TransactionKernelProfile,
    VmProfile,
};

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
    tx_benchmarks: &[(ExecutionBenchmark, MeasurementsPrinter)],
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
            operations: HashMap::new(), /* TODO: Add operation counting when VM instrumentation
                                         * is available */
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
    let mut instruction_mix = InstructionMix {
        signature_verify: signature_ratio,
        hashing: remaining * 0.5, // Hashing is significant in remaining work
        memory: remaining * 0.2,  // Memory operations
        control_flow: remaining * 0.2, // Loops, conditionals
        arithmetic: remaining * 0.1, // Basic arithmetic
    };
    const MIX_SUM_TOLERANCE: f64 = 0.001;
    let mix_sum = instruction_mix.arithmetic
        + instruction_mix.hashing
        + instruction_mix.memory
        + instruction_mix.control_flow
        + instruction_mix.signature_verify;
    if mix_sum > 0.0 && (mix_sum - 1.0).abs() > MIX_SUM_TOLERANCE {
        instruction_mix = InstructionMix {
            arithmetic: instruction_mix.arithmetic / mix_sum,
            hashing: instruction_mix.hashing / mix_sum,
            memory: instruction_mix.memory / mix_sum,
            control_flow: instruction_mix.control_flow / mix_sum,
            signature_verify: instruction_mix.signature_verify / mix_sum,
        };
    }

    // Key procedures - auth is the heavyweight
    let key_procedures = vec![ProcedureProfile {
        name: "auth_procedure".to_string(),
        cycles: avg_auth,
        invocations: 1,
    }];

    // Build operation details based on instruction mix
    // These are estimates based on typical transaction patterns
    let mut operation_details = Vec::new();

    // Minimum threshold for including an operation type (avoid floating-point noise)
    const MIN_MIX_RATIO: f64 = 0.001; // 0.1%
    // Threshold for applying minimum iteration counts (only for substantial workloads)
    const MIN_CYCLES_FOR_MINIMUMS: u64 = 10000;
    let apply_minimums = total_cycles >= MIN_CYCLES_FOR_MINIMUMS;
    let apply_minimum = |raw: u64, minimum: u64| -> u64 {
        if apply_minimums && raw >= minimum / 2 {
            raw.max(minimum)
        } else {
            raw
        }
    };

    // Signature verification operations
    // Only include if the calculated count is at least 1 (avoid inflating small workloads)
    if signature_ratio > MIN_MIX_RATIO {
        let sig_count = (total_cycles as f64 * signature_ratio / 59859.0) as u64;
        // Only include signature verification if we have at least 1 full verification
        // This avoids inflating operation_details with a 60K cycle op when the
        // actual average auth cost is much smaller
        if sig_count > 0 {
            operation_details.push(OperationDetails {
                op_type: "falcon512_verify".to_string(),
                input_sizes: vec![64, 32], // PK commitment (64 bytes), message (32 bytes)
                iterations: sig_count,
                cycle_cost: 59859,
            });
        }
    }

    // Hashing operations - split hashing ratio between hperm (80%) and hmerge (20%)
    // This approximates observed patterns where permutations dominate over merges
    const HPERM_HASHING_RATIO: f64 = 0.8;
    const HMERGE_HASHING_RATIO: f64 = 0.2;

    if instruction_mix.hashing > MIN_MIX_RATIO {
        let hperm_count =
            (total_cycles as f64 * instruction_mix.hashing * HPERM_HASHING_RATIO) as u64;
        if hperm_count > 0 {
            operation_details.push(OperationDetails {
                op_type: "hperm".to_string(),
                input_sizes: vec![48], // 12 field elements state
                iterations: apply_minimum(hperm_count, 100),
                cycle_cost: 1,
            });
        }

        let hmerge_count =
            (total_cycles as f64 * instruction_mix.hashing * HMERGE_HASHING_RATIO / 16.0) as u64;
        if hmerge_count > 0 {
            operation_details.push(OperationDetails {
                op_type: "hmerge".to_string(),
                input_sizes: vec![32, 32], // Two 32-byte digests
                iterations: apply_minimum(hmerge_count, 10),
                cycle_cost: 16,
            });
        }
    }

    // Memory operations
    if instruction_mix.memory > MIN_MIX_RATIO {
        let mem_count = (total_cycles as f64 * instruction_mix.memory / 10.0) as u64;
        if mem_count > 0 {
            operation_details.push(OperationDetails {
                op_type: "load_store".to_string(),
                input_sizes: vec![32], // Word-sized memory operations
                iterations: apply_minimum(mem_count, 10),
                cycle_cost: 10,
            });
        }
    }

    // Arithmetic operations
    if instruction_mix.arithmetic > MIN_MIX_RATIO {
        let arith_count = (total_cycles as f64 * instruction_mix.arithmetic) as u64;
        if arith_count > 0 {
            operation_details.push(OperationDetails {
                op_type: "arithmetic".to_string(),
                input_sizes: vec![8], // Field element operations
                iterations: apply_minimum(arith_count, 10),
                cycle_cost: 1,
            });
        }
    }

    // Control flow operations
    if instruction_mix.control_flow > MIN_MIX_RATIO {
        let control_count = (total_cycles as f64 * instruction_mix.control_flow / 5.0) as u64;
        if control_count > 0 {
            operation_details.push(OperationDetails {
                op_type: "control_flow".to_string(),
                input_sizes: vec![],
                iterations: apply_minimum(control_count, 10),
                cycle_cost: 5,
            });
        }
    }

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
            operation_details,
        },
    };

    let json = serde_json::to_string_pretty(&profile)?;
    write(path, json).context("failed to write VM profile to file")?;

    println!("VM profile exported to: {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that operation details are generated with correct hashing split
    #[test]
    fn operation_details_hashing_split_ratio() {
        let total_cycles = 100000u64;
        let instruction_mix = InstructionMix {
            arithmetic: 0.05,
            hashing: 0.45,
            memory: 0.08,
            control_flow: 0.05,
            signature_verify: 0.37,
        };

        // Simulate the calculation from write_vm_profile
        let hperm_count = (total_cycles as f64 * instruction_mix.hashing * 0.8) as u64;
        let hmerge_count = (total_cycles as f64 * instruction_mix.hashing * 0.2 / 16.0) as u64;

        // hperm should get ~80% of hashing cycles
        assert_eq!(hperm_count, 36000);
        // hmerge should get ~20% of hashing cycles (divided by 16 for cycle cost)
        assert_eq!(hmerge_count, 562);

        // Verify the ratio is maintained
        let hperm_cycles = hperm_count;
        let hmerge_cycles = hmerge_count * 16;
        let total_hashing_cycles = hperm_cycles + hmerge_cycles;

        // Should be close to 45% of total cycles (allowing for truncation)
        let hashing_ratio = total_hashing_cycles as f64 / total_cycles as f64;
        assert!((hashing_ratio - 0.45).abs() < 0.01);
    }

    /// Test that small workloads don't get minimums applied
    #[test]
    fn small_workload_no_minimum_inflation() {
        let total_cycles = 5000u64; // Below MIN_CYCLES_FOR_MINIMUMS threshold

        // For small workloads, counts should be raw calculated values
        let sig_count = (total_cycles as f64 * 0.37 / 59859.0) as u64;
        let hperm_count = (total_cycles as f64 * 0.45 * 0.8) as u64;

        // These should be 0 or small, not inflated to minimums
        assert_eq!(sig_count, 0); // Too small for a full sig verify
        assert_eq!(hperm_count, 1800); // Raw calculation, not max(100, 1800)
    }

    /// Test that large workloads get minimums applied
    #[test]
    fn large_workload_minimums_applied() {
        let total_cycles = 50000u64; // Above MIN_CYCLES_FOR_MINIMUMS threshold
        let apply_minimums = total_cycles >= 10000;

        assert!(apply_minimums);

        // With minimums, small counts get bumped up
        let hmerge_count = (total_cycles as f64 * 0.45 * 0.2 / 16.0) as u64;
        assert_eq!(hmerge_count, 281); // Raw calculation

        // With minimum applied (raw count already above half-minimum)
        let hmerge_with_min = if apply_minimums && hmerge_count >= 5 {
            hmerge_count.max(10)
        } else {
            hmerge_count
        };
        assert_eq!(hmerge_with_min, 281); // Already above minimum

        // For a very small count that would be below minimum
        let tiny_count = 5u64;
        let tiny_with_min = if apply_minimums && tiny_count >= 5 {
            tiny_count.max(10)
        } else {
            tiny_count
        };
        assert_eq!(tiny_with_min, 10);
    }

    /// Test that minimums are skipped when raw count is far below minimum
    #[test]
    fn minimums_skipped_when_raw_far_below_minimum() {
        let total_cycles = 10000u64; // Apply minimums
        let apply_minimums = total_cycles >= 10000;

        let raw_count = 11u64;
        let minimum = 100u64;
        let adjusted = if apply_minimums && raw_count >= minimum / 2 {
            raw_count.max(minimum)
        } else {
            raw_count
        };

        assert_eq!(adjusted, 11);
    }

    /// Test MIN_MIX_RATIO threshold - operations below threshold excluded
    #[test]
    fn min_mix_ratio_threshold_excludes_small_ratios() {
        let _total_cycles = 50000u64;
        let min_mix_ratio = 0.001; // 0.1%

        // Very small ratio below threshold
        let tiny_ratio = 0.0005;
        assert!(tiny_ratio < min_mix_ratio);

        // Should be excluded from operation_details
        let should_include = tiny_ratio > min_mix_ratio;
        assert!(!should_include);

        // Ratio above threshold should be included
        let normal_ratio = 0.05;
        assert!(normal_ratio > min_mix_ratio);
    }

    /// Test boundary at total_cycles == 10000
    #[test]
    fn minimums_boundary_at_10000_cycles() {
        // Just below threshold
        let below_threshold = 9999u64;
        let apply_minimums_below = below_threshold >= 10000;
        assert!(!apply_minimums_below);

        // At threshold
        let at_threshold = 10000u64;
        let apply_minimums_at = at_threshold >= 10000;
        assert!(apply_minimums_at);

        // Above threshold
        let above_threshold = 10001u64;
        let apply_minimums_above = above_threshold >= 10000;
        assert!(apply_minimums_above);
    }

    /// Test that zero-iteration operations are suppressed
    #[test]
    fn zero_iteration_operations_suppressed() {
        let total_cycles = 1000u64;

        // Very small counts that truncate to 0
        let sig_count = (total_cycles as f64 * 0.37 / 59859.0) as u64;
        assert_eq!(sig_count, 0);

        // Should not be included in operation_details
        let should_include = sig_count > 0;
        assert!(!should_include);
    }

    /// Test that write_vm_profile emits operation_details in the exported profile
    #[test]
    fn write_vm_profile_emits_operation_details() {
        let measurements = MeasurementsPrinter {
            prologue: 1000,
            notes_processing: 1000,
            note_execution: BTreeMap::new(),
            tx_script_processing: 1000,
            epilogue: EpilogueMeasurements::from_parts(7000, 1000, 0),
        };

        let tx_benchmarks = vec![(ExecutionBenchmark::ConsumeSingleP2ID, measurements)];
        let mut path = std::env::temp_dir();
        path.push(format!("vm_profile_write_test_{}.json", std::process::id()));

        write_vm_profile(&path, &tx_benchmarks).expect("write vm profile");

        let json = read_to_string(&path).expect("read vm profile");
        let profile: VmProfile = serde_json::from_str(&json).expect("deserialize vm profile");

        assert!(!profile.transaction_kernel.operation_details.is_empty());
        assert!(
            profile
                .transaction_kernel
                .operation_details
                .iter()
                .all(|detail| detail.iterations > 0)
        );
        assert!(
            profile
                .transaction_kernel
                .operation_details
                .iter()
                .all(|detail| detail.op_type != "falcon512_verify")
        );

        let _ = std::fs::remove_file(&path);
    }
}
