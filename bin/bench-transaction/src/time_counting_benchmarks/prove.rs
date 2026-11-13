use std::hint::black_box;
use std::time::{Duration, Instant};

use bench_transaction::context_setups::build_benchmark_context;
use bench_transaction::cycle_counting_benchmarks::ExecutionBenchmark;
use criterion::{Bencher, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::transaction::TransactionVerifier;
use miden_tx::LocalTransactionProver;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Execute,
    ExecuteAndProve,
}

// Stable IDs let Criterion compare results across runs.
const SCENARIOS: [(ExecutionBenchmark, &str); 7] = [
    (ExecutionBenchmark::ConsumeSingleP2IDFalcon, "falcon/single-p2id-note"),
    (ExecutionBenchmark::ConsumeSingleP2IDEcdsa, "ecdsa/single-p2id-note"),
    (ExecutionBenchmark::ConsumeTwoP2IDFalcon, "falcon/two-p2id-notes"),
    (ExecutionBenchmark::ConsumeTwoP2IDEcdsa, "ecdsa/two-p2id-notes"),
    (ExecutionBenchmark::ConsumeClaimNoteL1ToMiden, "claim-note-l1"),
    (ExecutionBenchmark::ConsumeClaimNoteL2ToMiden, "claim-note-l2"),
    (ExecutionBenchmark::ConsumeB2AggNote, "b2agg-note"),
];

fn core_benchmarks(c: &mut Criterion) {
    for (phase, name) in [
        (Phase::Execute, "Execute transaction"),
        (Phase::ExecuteAndProve, "Execute and prove transaction"),
    ] {
        let mut group = c.benchmark_group(name);
        group
            .sampling_mode(SamplingMode::Flat)
            .sample_size(30)
            .warm_up_time(Duration::from_secs(1))
            .measurement_time(Duration::from_secs(30));

        for (scenario, id) in SCENARIOS {
            let id = match phase {
                Phase::Execute => id.to_owned(),
                Phase::ExecuteAndProve => format!("eidos/{id}"),
            };
            group.bench_function(id, |b| bench_transaction(b, scenario, phase));
        }
        group.finish();
    }
}

/// Excludes fixture construction and proof verification from the measured duration.
fn bench_transaction(b: &mut Bencher<'_>, scenario: ExecutionBenchmark, phase: Phase) {
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let verifier = TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL);
    b.iter_custom(|iters| {
        rt.block_on(async {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mock_tx = build_benchmark_context(scenario)
                    .await
                    .expect("failed to build mock transaction");
                let start = Instant::now();
                let executed = mock_tx.execute().await.expect("execute failed");
                if phase == Phase::Execute {
                    total += start.elapsed();
                    black_box(executed);
                    continue;
                }

                let expected_id = executed.id();
                let proven = black_box(
                    LocalTransactionProver::default().prove(executed).expect("prove failed"),
                );
                total += start.elapsed();

                assert_eq!(proven.id(), expected_id);
                // Check the prover's default output without adding a separate settlement step.
                let _outcome = verifier.verify(&proven).expect("proof verification failed");
            }
            total
        })
    });
}

criterion_group!(benches, core_benchmarks);
criterion_main!(benches);
