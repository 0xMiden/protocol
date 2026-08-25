use std::fs::{read_to_string, write};
use std::path::Path;

use anyhow::Context;
use miden_processor::trace::TraceLenSummary;
use miden_protocol::transaction::TransactionMeasurements;
use serde::Serialize;
use serde_json::{Value, from_str, to_string_pretty};

use super::ExecutionBenchmark;
use crate::note_labels::{NoteLabels, measured_note_key};

// MEASUREMENTS PRINTER
// ================================================================================================

/// Helper structure holding the cycle and trace counts of each transaction stage which could be
/// easily converted to the JSON file.
#[derive(Debug, Clone, Serialize)]
pub struct MeasurementsPrinter {
    prologue: usize,
    total_cycles: usize,
    notes_processing: usize,
    /// A sequence rather than a map keyed by note: the entries stay in the order the kernel
    /// measured the notes, so a note whose cycle count moves shows up as a one-line diff instead
    /// of re-sorting the whole section.
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
                let note = note_labels.label(measured_note_key(*measured)).with_context(|| {
                    format!("measured note key {measured} matches no input note of the transaction")
                })?;
                Ok(NoteExecution { note: note.to_string(), cycles: *cycles })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(MeasurementsPrinter {
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
/// `poseidon2_permutation_rows`, and `range_rows` are the AIR-side totals; `chiplets_shape` is an
/// advisory per-chiplet breakdown that satisfies
/// `chiplets_rows == hasher + bitwise + memory + kernel_rom + ace + 1`.
#[derive(Debug, Clone, Serialize)]
struct TraceMeasurements {
    core_rows: usize,
    chiplets_rows: usize,
    poseidon2_permutation_rows: usize,
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
        Self {
            core_rows: summary.core_trace_len(),
            chiplets_rows: chiplets.trace_len(),
            poseidon2_permutation_rows: summary.poseidon2_permutation_trace_len(),
            range_rows: summary.range_trace_len(),
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
    use miden_protocol::Word;
    use miden_protocol::note::{NoteDetailsCommitment, NoteId};
    use miden_protocol::transaction::TransactionMeasurements;
    use miden_standards::note::StandardNote;
    use serde::Deserialize;

    use super::{ExecutionBenchmark, MeasurementsPrinter, TraceMeasurements};
    use crate::note_labels::NoteLabels;

    /// Minimal mirror of a bench-tx.json scenario, used to validate the committed file against
    /// the producer's contract.
    #[derive(Deserialize)]
    struct ScenarioForTest {
        prologue: u64,
        total_cycles: u64,
        notes_processing: u64,
        note_execution: Vec<NoteExecutionForTest>,
        tx_script_processing: u64,
        epilogue: EpilogueForTest,
        trace: TraceForTest,
    }

    #[derive(Deserialize)]
    struct NoteExecutionForTest {
        note: String,
        cycles: u64,
    }

    #[derive(Deserialize)]
    struct EpilogueForTest {
        total: u64,
    }

    #[derive(Deserialize)]
    struct TraceForTest {
        core_rows: u64,
        chiplets_rows: u64,
        poseidon2_permutation_rows: u64,
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
    const POSEIDON2_CYCLE_LEN: u64 = 16;
    const COMMITTED_BENCH_TX_JSON: &str = include_str!("../../bench-tx.json");

    /// Expected padded brackets per committed scenario. Mirrors `COMMITTED_SCENARIO_EXPECTATIONS`
    /// in the miden-vm consumer; refresh both together when a kernel change moves a bracket.
    struct ScenarioExpectation {
        name: &'static str,
        padded_core_side: u64,
        padded_chiplets: u64,
        padded_poseidon2: u64,
    }

    const COMMITTED_SCENARIO_EXPECTATIONS: &[ScenarioExpectation] = &[
        ScenarioExpectation {
            name: "consume single P2ID note with Falcon signing",
            padded_core_side: 131_072,
            padded_chiplets: 16_384,
            padded_poseidon2: 65_536,
        },
        ScenarioExpectation {
            name: "consume single P2ID note with ECDSA signing",
            padded_core_side: 16_384,
            padded_chiplets: 8_192,
            padded_poseidon2: 32_768,
        },
        ScenarioExpectation {
            name: "consume two P2ID notes with Falcon signing",
            padded_core_side: 131_072,
            padded_chiplets: 16_384,
            padded_poseidon2: 65_536,
        },
        ScenarioExpectation {
            name: "consume two P2ID notes with ECDSA signing",
            padded_core_side: 16_384,
            padded_chiplets: 8_192,
            padded_poseidon2: 32_768,
        },
        ScenarioExpectation {
            name: "create single P2ID note with Falcon signing",
            padded_core_side: 131_072,
            padded_chiplets: 16_384,
            padded_poseidon2: 65_536,
        },
        ScenarioExpectation {
            name: "create single P2ID note with ECDSA signing",
            padded_core_side: 16_384,
            padded_chiplets: 8_192,
            padded_poseidon2: 32_768,
        },
        ScenarioExpectation {
            name: "consume CLAIM note (L1 to Miden)",
            padded_core_side: 65_536,
            padded_chiplets: 32_768,
            padded_poseidon2: 65_536,
        },
        ScenarioExpectation {
            name: "consume CLAIM note (L2 to Miden)",
            padded_core_side: 65_536,
            padded_chiplets: 32_768,
            padded_poseidon2: 65_536,
        },
        ScenarioExpectation {
            name: "consume B2AGG note (bridge-out)",
            padded_core_side: 262_144,
            padded_chiplets: 131_072,
            padded_poseidon2: 131_072,
        },
    ];

    fn padded_core_side(t: &TraceForTest) -> u64 {
        t.core_rows.max(t.range_rows).next_power_of_two().max(MIN_TRACE_LEN)
    }

    fn padded_chiplets(t: &TraceForTest) -> u64 {
        t.chiplets_rows.next_power_of_two().max(MIN_TRACE_LEN)
    }

    fn padded_poseidon2(t: &TraceForTest) -> u64 {
        t.poseidon2_permutation_rows.next_power_of_two().max(MIN_TRACE_LEN)
    }

    fn parse_and_assert_scenario_contract(name: &str, raw: &serde_json::Value) -> TraceForTest {
        let scenario: ScenarioForTest = serde_json::from_value(raw.clone())
            .unwrap_or_else(|err| panic!("scenario `{name}` does not match the schema: {err}"));
        let trace = &scenario.trace;
        let chiplets_shape = &trace.chiplets_shape;

        assert_eq!(
            scenario.total_cycles,
            scenario.prologue
                + scenario.notes_processing
                + scenario.tx_script_processing
                + scenario.epilogue.total,
            "{name}: total_cycles must be the sum of the measured stages",
        );

        // only the note-creating scenarios consume nothing
        assert_eq!(
            scenario.note_execution.is_empty(),
            name.starts_with("create"),
            "{name}: a consuming scenario must measure at least one note, a creating one none",
        );
        for entry in &scenario.note_execution {
            assert!(
                !entry.note.is_empty() && !entry.note.starts_with("0x"),
                "{name}: note_execution should be keyed by a label, found `{}`",
                entry.note,
            );
            assert!(entry.cycles > 0, "{name}: note `{}` should cost > 0 cycles", entry.note);
        }
        let note_cycles: u64 = scenario.note_execution.iter().map(|entry| entry.cycles).sum();
        assert!(
            note_cycles <= scenario.notes_processing,
            "{name}: per-note cycles ({note_cycles}) exceed notes_processing ({})",
            scenario.notes_processing,
        );

        assert!(trace.core_rows > 0, "{name}: core_rows should be > 0");
        assert!(trace.chiplets_rows > 0, "{name}: chiplets_rows should be > 0");
        assert!(
            trace.poseidon2_permutation_rows > 0,
            "{name}: poseidon2_permutation_rows should be > 0",
        );
        assert!(
            trace.poseidon2_permutation_rows.is_multiple_of(POSEIDON2_CYCLE_LEN),
            "{name}: poseidon2_permutation_rows should be a multiple of {POSEIDON2_CYCLE_LEN}",
        );
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

        scenario.trace
    }

    fn assert_scenario(scenarios: &serde_json::Value, expected: &ScenarioExpectation) {
        let name = expected.name;
        let raw = scenarios
            .get(name)
            .unwrap_or_else(|| panic!("scenario `{name}` is missing from bench-tx.json"));
        let trace = parse_and_assert_scenario_contract(name, raw);

        let core_side = padded_core_side(&trace);
        let chiplets = padded_chiplets(&trace);
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
        assert_eq!(
            padded_poseidon2(&trace),
            expected.padded_poseidon2,
            "{name}: padded_poseidon2 regressed to a different bracket",
        );
    }

    #[test]
    fn committed_bench_tx_matches_producer_contract() {
        let parsed: serde_json::Value = serde_json::from_str(COMMITTED_BENCH_TX_JSON)
            .expect("bench-tx.json should be valid JSON");
        let scenarios = parsed.as_object().expect("bench-tx.json should contain an object");
        assert_eq!(
            scenarios.len(),
            ExecutionBenchmark::all().len(),
            "bench-tx.json should contain every ExecutionBenchmark scenario",
        );
        for (name, raw) in scenarios {
            parse_and_assert_scenario_contract(name, raw);
        }
        for expected in COMMITTED_SCENARIO_EXPECTATIONS {
            assert_scenario(&parsed, expected);
        }
    }

    #[test]
    fn trace_measurements_keep_core_rows_separate_from_total_trace_len() {
        let summary = TraceLenSummary::new(10, 20, ChipletsLengths::from_parts(30, 40, 50, 60, 70));
        assert_ne!(
            summary.core_trace_len(),
            summary.trace_len(),
            "test setup must distinguish core rows from total trace length",
        );

        let measurements = TraceMeasurements::from(summary);

        assert_eq!(measurements.core_rows, summary.core_trace_len());
        assert_eq!(measurements.chiplets_rows, summary.chiplets_trace_len().trace_len());
        assert_eq!(
            measurements.poseidon2_permutation_rows,
            summary.poseidon2_permutation_trace_len(),
        );
        assert_eq!(measurements.range_rows, summary.range_trace_len());
    }

    // MEASUREMENTS PRINTER
    // --------------------------------------------------------------------------------------------

    /// A note key, in both the form the input notes are labelled by and the form a measurement
    /// entry reports it as.
    fn note_key(seed: u32) -> (NoteDetailsCommitment, NoteId) {
        let word = Word::from([seed, seed, seed, seed]);
        (NoteDetailsCommitment::from_raw(word), NoteId::from_raw(word))
    }

    fn trace_summary() -> TraceLenSummary {
        TraceLenSummary::new(10, 20, ChipletsLengths::from_parts(30, 40, 50, 60, 70))
    }

    /// Measurements whose stages sum to a `total_cycles` of 100.
    fn measurements(note_execution: Vec<(NoteId, usize)>) -> TransactionMeasurements {
        TransactionMeasurements {
            prologue: 10,
            notes_processing: 20,
            note_execution,
            tx_script_processing: 30,
            epilogue: 40,
            auth_procedure: 5,
        }
    }

    /// The emitted entries keep the order the kernel measured the notes in - not the order the
    /// labels were resolved in, and not a sort by label - which is what makes a cycle-count change
    /// a one-line diff.
    #[test]
    fn note_execution_keeps_measurement_order_and_uses_labels() {
        let ((first, first_measured), (second, second_measured)) = (note_key(1), note_key(2));
        let labels = NoteLabels::from_script_roots(
            [
                (first, StandardNote::P2ID.script_root()),
                (second, StandardNote::P2ID.script_root()),
            ]
            .into_iter(),
        )
        .expect("note keys are distinct");

        let printer = MeasurementsPrinter::from_parts(
            measurements(vec![(second_measured, 200), (first_measured, 100)]),
            trace_summary(),
            &labels,
        )
        .expect("every measured note is labelled");

        let entries: Vec<(&str, usize)> = printer
            .note_execution
            .iter()
            .map(|entry| (entry.note.as_str(), entry.cycles))
            .collect();
        assert_eq!(entries, vec![("P2ID#1", 200), ("P2ID#0", 100)]);
        assert_eq!(printer.total_cycles, 100);
    }

    /// A measured note that is not among the transaction's input notes is a defect in the join,
    /// not a note of an unrecognised kind, so it aborts the run rather than being labelled.
    #[test]
    fn measured_note_without_a_label_is_an_error() {
        let labels = NoteLabels::from_script_roots(core::iter::empty()).expect("no notes to label");

        let err = MeasurementsPrinter::from_parts(
            measurements(vec![(note_key(1).1, 100)]),
            trace_summary(),
            &labels,
        )
        .expect_err("an unlabelled note must not be silently emitted");

        assert!(
            err.to_string().contains("matches no input note of the transaction"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn trace_measurements_preserve_poseidon2_permutation_rows() {
        let summary = TraceLenSummary::new_with_padded(
            10,
            20,
            ChipletsLengths::from_parts(30, 40, 50, 60, 70),
            80,
            128,
        );

        let measurements = TraceMeasurements::from(summary);

        assert_eq!(measurements.poseidon2_permutation_rows, 80);
    }
}
