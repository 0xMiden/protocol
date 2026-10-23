use std::fs::{read_to_string, write};
use std::path::Path;

use anyhow::Context;
use miden_processor::trace::TraceLenSummary;
use miden_protocol::transaction::TransactionMeasurements;
use serde::Serialize;
use serde_json::{Value, from_str, to_string_pretty};

use super::ExecutionBenchmark;
use crate::note_labels::NoteLabels;

// MEASUREMENTS PRINTER
// ================================================================================================

/// Helper structure holding the cycle and trace counts of each transaction stage which could be
/// easily converted to the JSON file.
#[derive(Debug, Clone, Serialize)]
pub struct MeasurementsPrinter {
    provenance: &'static str,
    prologue: usize,
    total_cycles: usize,
    notes_processing: usize,
    note_execution: Vec<NoteExecution>,
    tx_script_processing: usize,
    epilogue: EpilogueMeasurements,
    trace: TraceMeasurements,
}

impl MeasurementsPrinter {
    pub fn from_parts(
        measurements: TransactionMeasurements,
        trace: TraceLenSummary,
        note_labels: &NoteLabels,
    ) -> anyhow::Result<Self> {
        let note_execution = measurements
            .note_execution
            .iter()
            .map(|(measured, cycles)| {
                let note = note_labels.label(*measured).with_context(|| {
                    format!("measured note {measured} matches no input note of the transaction")
                })?;
                Ok(NoteExecution { note: note.to_string(), cycles: *cycles })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(MeasurementsPrinter {
            provenance: "producer_measured",
            prologue: measurements.prologue,
            total_cycles: measurements.total_cycles(),
            notes_processing: measurements.notes_processing,
            note_execution,
            tx_script_processing: measurements.tx_script_processing,
            epilogue: EpilogueMeasurements::from_parts(
                measurements.epilogue,
                measurements.auth_procedure,
            ),
            trace: TraceMeasurements::from(trace),
        })
    }
}

/// Cycles spent executing one input note.
///
/// `note` is the note's label; its `#N` suffix, when present, is the note's ordinal among the
/// same-kind notes in *input-note* order, which need not match this entry's position in the
/// measurement sequence.
#[derive(Debug, Clone, Serialize)]
struct NoteExecution {
    note: String,
    cycles: usize,
}

/// Helper structure holding the cycle count for different intervals in the epilogue, namely:
/// - `total` interval holds the total number of cycles required to execute the epilogue
/// - `auth_procedure` interval holds the number of cycles required to execute the authentication
///   procedure
#[derive(Debug, Clone, Serialize)]
struct EpilogueMeasurements {
    total: usize,
    auth_procedure: usize,
}

impl EpilogueMeasurements {
    pub fn from_parts(total: usize, auth_procedure: usize) -> Self {
        Self { total, auth_procedure }
    }
}

/// Per-component trace row counts from a real `ExecutionTrace`. `core_rows`, `chiplets_rows`,
/// `eidos_compression_rows`, and `byte_pair_lookup_rows` are the AIR-side totals; `chiplets_shape`
/// is an advisory per-chiplet breakdown that satisfies
/// `chiplets_rows == hasher + bitwise + memory + kernel_rom + ace + 1`.
#[derive(Debug, Clone, Serialize)]
struct TraceMeasurements {
    core_rows: usize,
    chiplets_rows: usize,
    eidos_compression_rows: usize,
    byte_pair_lookup_rows: usize,
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
        let chiplets = summary.chiplets();
        Self {
            core_rows: summary.core_rows(),
            chiplets_rows: chiplets.trace_len(),
            eidos_compression_rows: summary.eidos_compression_rows(),
            byte_pair_lookup_rows: summary.byte_pair_lookup_rows(),
            chiplets_shape: ChipletsTraceShape {
                hasher_rows: chiplets.hash_chiplet_len(),
                bitwise_rows: chiplets.bitwise_chiplet_len(),
                memory_rows: chiplets.memory_chiplet_len(),
                kernel_rom_rows: chiplets.kernel_rom_len(),
                ace_rows: chiplets.ace_chiplet_len(),
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
    use miden_processor::trace::{ChipletsLengths, TraceLenSummary};
    use serde::Deserialize;

    use super::{ExecutionBenchmark, TraceMeasurements};

    /// Minimal mirror of the bench-tx.json `trace` section used to validate the committed file
    /// against the producer's contract.
    #[derive(Deserialize)]
    struct ScenarioForTest {
        provenance: String,
        trace: TraceForTest,
    }

    #[derive(Deserialize)]
    struct TraceForTest {
        core_rows: u64,
        chiplets_rows: u64,
        eidos_compression_rows: u64,
        byte_pair_lookup_rows: u64,
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

    const EIDOS_COMPRESSION_CYCLE_LEN: u64 = 32;
    const BYTE_PAIR_LOOKUP_ROWS: u64 = 1 << 16;
    const MIN_TRACE_LEN: u64 = 64;
    const COMMITTED_BENCH_TX_JSON: &str = include_str!("../../bench-tx.json");

    /// Expected padded AIR brackets for the representative scenarios consumed by miden-vm's
    /// synthetic benchmark. Refresh these values and the consumer snapshot together whenever a
    /// kernel change crosses a power-of-two boundary.
    struct ScenarioExpectation {
        name: &'static str,
        padded_core: u64,
        padded_chiplets: u64,
        padded_eidos_compression: u64,
        padded_byte_pair_lookup: u64,
    }

    const COMMITTED_SCENARIO_EXPECTATIONS: &[ScenarioExpectation] = &[
        ScenarioExpectation {
            name: "consume single P2ID note with Falcon signing",
            padded_core: 65_536,
            padded_chiplets: 8_192,
            padded_eidos_compression: 131_072,
            padded_byte_pair_lookup: 65_536,
        },
        ScenarioExpectation {
            name: "consume single P2ID note with ECDSA signing",
            padded_core: 16_384,
            padded_chiplets: 4_096,
            padded_eidos_compression: 65_536,
            padded_byte_pair_lookup: 65_536,
        },
        ScenarioExpectation {
            name: "consume two P2ID notes with Falcon signing",
            padded_core: 65_536,
            padded_chiplets: 8_192,
            padded_eidos_compression: 131_072,
            padded_byte_pair_lookup: 65_536,
        },
        ScenarioExpectation {
            name: "consume two P2ID notes with ECDSA signing",
            padded_core: 32_768,
            // Retain precomputed prologue chaining words while runtime initialization crosses
            // this chiplet bracket.
            padded_chiplets: 4_096,
            padded_eidos_compression: 65_536,
            padded_byte_pair_lookup: 65_536,
        },
        ScenarioExpectation {
            name: "create single P2ID note with Falcon signing",
            padded_core: 65_536,
            padded_chiplets: 8_192,
            padded_eidos_compression: 131_072,
            padded_byte_pair_lookup: 65_536,
        },
        ScenarioExpectation {
            name: "create single P2ID note with ECDSA signing",
            padded_core: 16_384,
            padded_chiplets: 4_096,
            padded_eidos_compression: 65_536,
            padded_byte_pair_lookup: 65_536,
        },
        ScenarioExpectation {
            name: "consume CLAIM note (L1 to Miden)",
            padded_core: 65_536,
            padded_chiplets: 16_384,
            padded_eidos_compression: 131_072,
            padded_byte_pair_lookup: 65_536,
        },
        ScenarioExpectation {
            name: "consume CLAIM note (L2 to Miden)",
            padded_core: 65_536,
            padded_chiplets: 16_384,
            padded_eidos_compression: 131_072,
            padded_byte_pair_lookup: 65_536,
        },
        ScenarioExpectation {
            name: "consume B2AGG note (bridge-out)",
            padded_core: 262_144,
            padded_chiplets: 65_536,
            padded_eidos_compression: 262_144,
            padded_byte_pair_lookup: 65_536,
        },
    ];

    fn padded_height(rows: u64) -> u64 {
        rows.next_power_of_two().max(MIN_TRACE_LEN)
    }

    fn parse_and_assert_trace_contract(name: &str, raw: &serde_json::Value) -> TraceForTest {
        let scenario: ScenarioForTest = serde_json::from_value(raw.clone())
            .unwrap_or_else(|err| panic!("scenario `{name}` does not match the schema: {err}"));
        assert_eq!(
            scenario.provenance, "producer_measured",
            "{name}: trace provenance must identify direct producer measurements",
        );
        let trace = &scenario.trace;
        let chiplets_shape = &trace.chiplets_shape;

        assert!(trace.core_rows > 0, "{name}: core_rows should be > 0");
        assert!(trace.chiplets_rows > 0, "{name}: chiplets_rows should be > 0");
        assert!(trace.eidos_compression_rows > 0, "{name}: eidos_compression_rows should be > 0",);
        assert!(
            trace.eidos_compression_rows.is_multiple_of(EIDOS_COMPRESSION_CYCLE_LEN),
            "{name}: eidos_compression_rows should be a multiple of \
             {EIDOS_COMPRESSION_CYCLE_LEN}",
        );
        assert_eq!(
            trace.byte_pair_lookup_rows, BYTE_PAIR_LOOKUP_ROWS,
            "{name}: byte_pair_lookup_rows should be the fixed byte-pair table height",
        );

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

        scenario.trace
    }

    fn assert_scenario(scenarios: &serde_json::Value, expected: &ScenarioExpectation) {
        let name = expected.name;
        let raw = scenarios
            .get(name)
            .unwrap_or_else(|| panic!("scenario `{name}` is missing from bench-tx.json"));
        let trace = parse_and_assert_trace_contract(name, raw);

        assert_eq!(padded_height(trace.core_rows), expected.padded_core);
        assert_eq!(padded_height(trace.chiplets_rows), expected.padded_chiplets);
        assert_eq!(padded_height(trace.eidos_compression_rows), expected.padded_eidos_compression,);
        assert_eq!(padded_height(trace.byte_pair_lookup_rows), expected.padded_byte_pair_lookup,);
    }

    #[test]
    fn committed_bench_tx_matches_trace_contract() {
        let parsed: serde_json::Value = serde_json::from_str(COMMITTED_BENCH_TX_JSON)
            .expect("bench-tx.json should be valid JSON");
        let scenarios = parsed.as_object().expect("bench-tx.json should contain an object");
        assert_eq!(
            scenarios.len(),
            ExecutionBenchmark::all().len(),
            "bench-tx.json should contain every ExecutionBenchmark scenario",
        );
        for (name, raw) in scenarios {
            parse_and_assert_trace_contract(name, raw);
        }
        for expected in COMMITTED_SCENARIO_EXPECTATIONS {
            assert_scenario(&parsed, expected);
        }
    }

    #[test]
    fn trace_measurements_keep_core_rows_separate_from_total_trace_len() {
        let summary = TraceLenSummary::new(
            10,
            ChipletsLengths::from_parts(30, 40, 50, 60, 70),
            96,
            BYTE_PAIR_LOOKUP_ROWS as usize,
        );
        assert_ne!(
            summary.core_rows(),
            summary.trace_len(),
            "test setup must distinguish core rows from total trace length",
        );

        let measurements = TraceMeasurements::from(summary);

        assert_eq!(measurements.core_rows, summary.core_rows());
        assert_eq!(measurements.chiplets_rows, summary.chiplets_rows());
        assert_eq!(measurements.eidos_compression_rows, summary.eidos_compression_rows());
        assert_eq!(measurements.byte_pair_lookup_rows, summary.byte_pair_lookup_rows());
    }

    #[test]
    fn trace_measurements_preserve_all_four_air_rows() {
        let summary = TraceLenSummary::new_with_padded(
            10,
            ChipletsLengths::from_parts(30, 40, 50, 60, 70),
            96,
            BYTE_PAIR_LOOKUP_ROWS as usize,
            [64, 512, 128, BYTE_PAIR_LOOKUP_ROWS as usize],
        );

        let measurements = TraceMeasurements::from(summary);

        assert_eq!(measurements.core_rows, 10);
        assert_eq!(measurements.chiplets_rows, 251);
        assert_eq!(measurements.eidos_compression_rows, 96);
        assert_eq!(measurements.byte_pair_lookup_rows, BYTE_PAIR_LOOKUP_ROWS as usize);
    }
}
