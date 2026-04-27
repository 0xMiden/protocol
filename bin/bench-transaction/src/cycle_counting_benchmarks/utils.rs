extern crate alloc;
pub use alloc::collections::BTreeMap;
pub use alloc::string::String;
use std::fs::{read_to_string, write};
use std::path::Path;

use anyhow::Context;
use miden_processor::trace::TraceLenSummary;
use miden_protocol::transaction::TransactionMeasurements;
use serde::Serialize;
use serde_json::{Value, from_str, to_string_pretty};

use super::ExecutionBenchmark;

// MEASUREMENTS PRINTER
// ================================================================================================

/// Helper structure holding the cycle and trace counts of each transaction stage which could be
/// easily converted to the JSON file.
#[derive(Debug, Clone, Serialize)]
pub struct MeasurementsPrinter {
    prologue: usize,
    notes_processing: usize,
    note_execution: BTreeMap<String, usize>,
    tx_script_processing: usize,
    epilogue: EpilogueMeasurements,
    trace: TraceMeasurements,
}

impl MeasurementsPrinter {
    pub fn from_parts(measurements: TransactionMeasurements, trace: TraceLenSummary) -> Self {
        let note_execution_map = measurements
            .note_execution
            .iter()
            .map(|(id, len)| (id.to_hex(), *len))
            .collect();

        MeasurementsPrinter {
            prologue: measurements.prologue,
            notes_processing: measurements.notes_processing,
            note_execution: note_execution_map,
            tx_script_processing: measurements.tx_script_processing,
            epilogue: EpilogueMeasurements::from_parts(
                measurements.epilogue,
                measurements.auth_procedure,
                measurements.after_tx_cycles_obtained,
            ),
            trace: TraceMeasurements::from(trace),
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

/// Per-component trace row counts from a real `ExecutionTrace`. `core_rows`, `chiplets_rows`,
/// and `range_rows` are the AIR-side totals; `chiplets_shape` is an advisory per-chiplet breakdown
/// that satisfies `chiplets_rows == hasher + bitwise + memory + kernel_rom + ace + 1`.
#[derive(Debug, Clone, Serialize)]
struct TraceMeasurements {
    core_rows: usize,
    chiplets_rows: usize,
    range_rows: usize,
    chiplets_shape: ChipletsTraceShape,
}

#[derive(Debug, Clone, Serialize)]
struct ChipletsTraceShape {
    hasher_rows: usize,
    bitwise_rows: usize,
    memory_rows: usize,
    kernel_rom_rows: usize,
    ace_rows: usize,
}

impl From<TraceLenSummary> for TraceMeasurements {
    fn from(summary: TraceLenSummary) -> Self {
        let chiplets = summary.chiplets_trace_len();
        // The pinned `miden-processor` doesn't expose an ACE accessor yet, so derive it from the
        // total. The chiplet-bus invariant
        // (`chiplets_rows == hasher + bitwise + memory + kernel_rom + ace + 1`) keeps holding
        // when the upstream accessor lands.
        let known = chiplets.hash_chiplet_len()
            + chiplets.bitwise_chiplet_len()
            + chiplets.memory_chiplet_len()
            + chiplets.kernel_rom_len();
        // Guard against the per-chiplet accessors and `trace_len()` going out of sync upstream;
        // without this, `saturating_sub` below would silently produce `ace_rows = 0`.
        debug_assert!(
            known < chiplets.trace_len(),
            "chiplet accessors disagree with trace_len(): known = {} >= trace_len = {}",
            known,
            chiplets.trace_len(),
        );
        let ace_rows = chiplets.trace_len().saturating_sub(known + 1);
        Self {
            core_rows: summary.main_trace_len(),
            chiplets_rows: chiplets.trace_len(),
            range_rows: summary.range_trace_len(),
            chiplets_shape: ChipletsTraceShape {
                hasher_rows: chiplets.hash_chiplet_len(),
                bitwise_rows: chiplets.bitwise_chiplet_len(),
                memory_rows: chiplets.memory_chiplet_len(),
                kernel_rom_rows: chiplets.kernel_rom_len(),
                ace_rows,
            },
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
    let mut serialized =
        to_string_pretty(&benchmark_json).expect("failed to convert json to String");
    serialized.push('\n');
    write(path, serialized).context("failed to write benchmark results to file")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    /// Minimal mirror of the bench-tx.json `trace` section used to validate the committed file
    /// against the producer's contract.
    #[derive(Deserialize)]
    struct ScenarioForTest {
        trace: TraceForTest,
    }

    #[derive(Deserialize)]
    struct TraceForTest {
        core_rows: u64,
        chiplets_rows: u64,
        range_rows: u64,
        chiplets_shape: ChipletsShapeForTest,
    }

    #[derive(Deserialize)]
    struct ChipletsShapeForTest {
        hasher_rows: u64,
        bitwise_rows: u64,
        memory_rows: u64,
        kernel_rom_rows: u64,
        ace_rows: u64,
    }

    const MIN_TRACE_LEN: u64 = 64;
    const COMMITTED_BENCH_TX_JSON: &str = include_str!("../../bench-tx.json");

    /// Expected padded brackets per committed scenario. Mirrors `COMMITTED_SCENARIO_EXPECTATIONS`
    /// in the miden-vm consumer; refresh both together when a kernel change moves a bracket.
    struct ScenarioExpectation {
        name: &'static str,
        padded_core_side: u64,
        padded_chiplets: u64,
    }

    const COMMITTED_SCENARIO_EXPECTATIONS: &[ScenarioExpectation] = &[
        ScenarioExpectation {
            name: "consume single P2ID note",
            padded_core_side: 131_072,
            padded_chiplets: 131_072,
        },
        ScenarioExpectation {
            name: "consume two P2ID notes",
            padded_core_side: 131_072,
            padded_chiplets: 262_144,
        },
        ScenarioExpectation {
            name: "create single P2ID note",
            padded_core_side: 131_072,
            padded_chiplets: 131_072,
        },
        ScenarioExpectation {
            name: "consume CLAIM note (L1 to Miden)",
            padded_core_side: 65_536,
            padded_chiplets: 262_144,
        },
        ScenarioExpectation {
            name: "consume CLAIM note (L2 to Miden)",
            padded_core_side: 65_536,
            padded_chiplets: 262_144,
        },
        ScenarioExpectation {
            name: "consume B2AGG note (bridge-out)",
            padded_core_side: 262_144,
            padded_chiplets: 1_048_576,
        },
    ];

    fn padded_core_side(t: &TraceForTest) -> u64 {
        t.core_rows.max(t.range_rows).next_power_of_two().max(MIN_TRACE_LEN)
    }

    fn padded_chiplets(t: &TraceForTest) -> u64 {
        t.chiplets_rows.next_power_of_two().max(MIN_TRACE_LEN)
    }

    fn assert_scenario(scenarios: &serde_json::Value, expected: &ScenarioExpectation) {
        let name = expected.name;
        let raw = scenarios
            .get(name)
            .unwrap_or_else(|| panic!("scenario `{name}` is missing from bench-tx.json"));
        let scenario: ScenarioForTest = serde_json::from_value(raw.clone())
            .unwrap_or_else(|err| panic!("scenario `{name}` does not match the schema: {err}"));
        let trace = &scenario.trace;
        let chiplets_shape = &trace.chiplets_shape;

        assert!(trace.core_rows > 0, "{name}: core_rows should be > 0");
        assert!(trace.chiplets_rows > 0, "{name}: chiplets_rows should be > 0");
        assert!(trace.range_rows > 0, "{name}: range_rows should be > 0");

        let chiplets_sum = chiplets_shape.hasher_rows
            + chiplets_shape.bitwise_rows
            + chiplets_shape.memory_rows
            + chiplets_shape.kernel_rom_rows
            + chiplets_shape.ace_rows
            + 1;
        assert_eq!(
            trace.chiplets_rows, chiplets_sum,
            "{name}: chiplets_rows must equal sum(chiplets_shape) + 1",
        );

        let core_side = padded_core_side(trace);
        let chiplets = padded_chiplets(trace);
        assert!(core_side.is_power_of_two(), "{name}: padded_core_side not a power of two");
        assert!(chiplets.is_power_of_two(), "{name}: padded_chiplets not a power of two");
        assert_eq!(
            core_side, expected.padded_core_side,
            "{name}: padded_core_side regressed to a different bracket",
        );
        assert_eq!(
            chiplets, expected.padded_chiplets,
            "{name}: padded_chiplets regressed to a different bracket",
        );
    }

    #[test]
    fn committed_bench_tx_matches_trace_contract() {
        let parsed: serde_json::Value = serde_json::from_str(COMMITTED_BENCH_TX_JSON)
            .expect("bench-tx.json should be valid JSON");
        for expected in COMMITTED_SCENARIO_EXPECTATIONS {
            assert_scenario(&parsed, expected);
        }
    }
}
