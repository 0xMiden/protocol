use std::future::Future;
use std::hint::black_box;
use std::time::{Duration, Instant};

use anyhow::Result;
use bench_transaction::context_setups::{
    ClaimDataSource,
    tx_consume_b2agg_note,
    tx_consume_claim_note,
    tx_consume_single_p2id_note_ecdsa,
    tx_consume_single_p2id_note_falcon,
    tx_consume_two_p2id_notes_ecdsa,
    tx_consume_two_p2id_notes_falcon,
};
use criterion::{BatchSize, Bencher, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_protocol::transaction::{ExecutedTransaction, ProvenTransaction};
use miden_testing::TransactionContext;
use miden_tx::LocalTransactionProver;

// BENCHMARK IDS
// ================================================================================================

// Criterion prints results as `<group>/<id>` and truncates the directory name derived from the
// `<id>` to 64 characters. We build the `<id>` programmatically so it always records what was
// measured: the signing scheme of the benchmarked account's authentication and, for the proving
// group, the hash function used during proving. Network-authenticated transactions (CLAIM, B2AGG)
// carry no signing scheme.
const BENCH_GROUP_EXECUTE: &str = "Execute transaction";
const BENCH_GROUP_EXECUTE_AND_PROVE: &str = "Execute and prove transaction";

// Scenario base names shared by both groups.
const SCENARIO_SINGLE_P2ID: &str = "single-p2id-note";
const SCENARIO_TWO_P2ID: &str = "two-p2id-notes";
const SCENARIO_CLAIM_L1: &str = "claim-note-l1";
const SCENARIO_CLAIM_L2: &str = "claim-note-l2";
const SCENARIO_B2AGG: &str = "b2agg-note";

/// Signing scheme used by the benchmarked account's authentication procedure.
#[derive(Clone, Copy)]
enum Signing {
    Falcon,
    Ecdsa,
}

impl Signing {
    fn as_str(self) -> &'static str {
        match self {
            Signing::Falcon => "falcon",
            Signing::Ecdsa => "ecdsa",
        }
    }
}

/// Builds the Criterion ID for the execute-only group, e.g. `falcon/single-p2id-note`.
/// Network-authenticated scenarios pass `None` and get the bare scenario name.
fn execute_id(signing: Option<Signing>, scenario: &str) -> String {
    match signing {
        Some(signing) => format!("{}/{scenario}", signing.as_str()),
        None => scenario.to_string(),
    }
}

/// Builds the Criterion ID for the execute-and-prove group, prefixing the proving hash function as
/// its own path segment, e.g. `poseidon2/falcon/single-p2id-note` or `poseidon2/claim-note-l1`.
fn prove_id(signing: Option<Signing>, scenario: &str) -> String {
    match signing {
        Some(signing) => format!("poseidon2/{}/{scenario}", signing.as_str()),
        None => format!("poseidon2/{scenario}"),
    }
}

// CORE PROVING BENCHMARKS
// ================================================================================================

fn core_benchmarks(c: &mut Criterion) {
    // EXECUTE GROUP
    // --------------------------------------------------------------------------------------------

    let mut execute_group = c.benchmark_group(BENCH_GROUP_EXECUTE);

    execute_group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(30)
        .warm_up_time(Duration::from_millis(1000))
        .measurement_time(Duration::from_secs(30));

    execute_group.bench_function(execute_id(Some(Signing::Falcon), SCENARIO_SINGLE_P2ID), |b| {
        b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
            .iter_batched(
                || {
                    tx_consume_single_p2id_note_falcon()
                        .expect("failed to create a context which consumes single P2ID note")
                },
                |tx_context| async move { black_box(tx_context.execute().await) },
                BatchSize::SmallInput,
            );
    });

    execute_group.bench_function(execute_id(Some(Signing::Ecdsa), SCENARIO_SINGLE_P2ID), |b| {
        b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
            .iter_batched(
                || {
                    tx_consume_single_p2id_note_ecdsa()
                        .expect("failed to create a context which consumes single P2ID note")
                },
                |tx_context| async move { black_box(tx_context.execute().await) },
                BatchSize::SmallInput,
            );
    });

    execute_group.bench_function(execute_id(Some(Signing::Falcon), SCENARIO_TWO_P2ID), |b| {
        b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
            .iter_batched(
                || {
                    // prepare the transaction context
                    tx_consume_two_p2id_notes_falcon()
                        .expect("failed to create a context which consumes two P2ID notes")
                },
                |tx_context| async move {
                    // benchmark the transaction execution
                    black_box(tx_context.execute().await)
                },
                BatchSize::SmallInput,
            );
    });

    execute_group.bench_function(execute_id(Some(Signing::Ecdsa), SCENARIO_TWO_P2ID), |b| {
        b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
            .iter_batched(
                || {
                    // prepare the transaction context
                    tx_consume_two_p2id_notes_ecdsa()
                        .expect("failed to create a context which consumes two P2ID notes")
                },
                |tx_context| async move {
                    // benchmark the transaction execution
                    black_box(tx_context.execute().await)
                },
                BatchSize::SmallInput,
            );
    });

    execute_group.bench_function(execute_id(None, SCENARIO_CLAIM_L1), |b| {
        bench_async_execute(b, || tx_consume_claim_note(ClaimDataSource::L1ToMiden));
    });

    execute_group.bench_function(execute_id(None, SCENARIO_CLAIM_L2), |b| {
        bench_async_execute(b, || tx_consume_claim_note(ClaimDataSource::L2ToMiden));
    });

    execute_group.bench_function(execute_id(None, SCENARIO_B2AGG), |b| {
        bench_async_execute(b, || tx_consume_b2agg_note(None));
    });

    execute_group.finish();

    // EXECUTE AND PROVE GROUP
    // --------------------------------------------------------------------------------------------

    let mut execute_and_prove_group = c.benchmark_group(BENCH_GROUP_EXECUTE_AND_PROVE);

    execute_and_prove_group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(30)
        .warm_up_time(Duration::from_millis(1000))
        .measurement_time(Duration::from_secs(30));

    execute_and_prove_group.bench_function(
        prove_id(Some(Signing::Falcon), SCENARIO_SINGLE_P2ID),
        |b| {
            b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
                .iter_batched(
                    || {
                        tx_consume_single_p2id_note_falcon()
                            .expect("failed to create a context which consumes single P2ID note")
                    },
                    |tx_context| async move {
                        black_box(prove_transaction(
                            tx_context
                                .execute()
                                .await
                                .expect("execution of the single P2ID note consumption tx failed"),
                        ))
                    },
                    BatchSize::SmallInput,
                );
        },
    );

    execute_and_prove_group.bench_function(
        prove_id(Some(Signing::Ecdsa), SCENARIO_SINGLE_P2ID),
        |b| {
            b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
                .iter_batched(
                    || {
                        tx_consume_single_p2id_note_ecdsa()
                            .expect("failed to create a context which consumes single P2ID note")
                    },
                    |tx_context| async move {
                        black_box(prove_transaction(
                            tx_context
                                .execute()
                                .await
                                .expect("execution of the single P2ID note consumption tx failed"),
                        ))
                    },
                    BatchSize::SmallInput,
                );
        },
    );

    execute_and_prove_group.bench_function(
        prove_id(Some(Signing::Falcon), SCENARIO_TWO_P2ID),
        |b| {
            b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
                .iter_batched(
                    || {
                        tx_consume_two_p2id_notes_falcon()
                            .expect("failed to create a context which consumes two P2ID notes")
                    },
                    |tx_context| async move {
                        // benchmark the transaction execution and proving
                        black_box(prove_transaction(
                            tx_context
                                .execute()
                                .await
                                .expect("execution of the two P2ID note consumption tx failed"),
                        ))
                    },
                    BatchSize::SmallInput,
                );
        },
    );

    execute_and_prove_group.bench_function(
        prove_id(Some(Signing::Ecdsa), SCENARIO_TWO_P2ID),
        |b| {
            b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
                .iter_batched(
                    || {
                        tx_consume_two_p2id_notes_ecdsa()
                            .expect("failed to create a context which consumes two P2ID notes")
                    },
                    |tx_context| async move {
                        // benchmark the transaction execution and proving
                        black_box(prove_transaction(
                            tx_context
                                .execute()
                                .await
                                .expect("execution of the two P2ID note consumption tx failed"),
                        ))
                    },
                    BatchSize::SmallInput,
                );
        },
    );

    execute_and_prove_group.bench_function(prove_id(None, SCENARIO_CLAIM_L1), |b| {
        bench_async_execute_and_prove(b, || tx_consume_claim_note(ClaimDataSource::L1ToMiden));
    });

    execute_and_prove_group.bench_function(prove_id(None, SCENARIO_CLAIM_L2), |b| {
        bench_async_execute_and_prove(b, || tx_consume_claim_note(ClaimDataSource::L2ToMiden));
    });

    execute_and_prove_group.bench_function(prove_id(None, SCENARIO_B2AGG), |b| {
        bench_async_execute_and_prove(b, || tx_consume_b2agg_note(None));
    });

    execute_and_prove_group.finish();
}

fn prove_transaction(executed_transaction: ExecutedTransaction) -> Result<()> {
    let executed_transaction_id = executed_transaction.id();
    let proven_transaction: ProvenTransaction =
        LocalTransactionProver::default().prove(executed_transaction)?;

    assert_eq!(proven_transaction.id(), executed_transaction_id);
    Ok(())
}

/// Times `execute()` for an async-built tx context. Uses `iter_custom` because async builders
/// can't run inside `iter_batched`'s setup under a current_thread runtime (nested `block_on`
/// panics).
fn bench_async_execute<F, Fut>(b: &mut Bencher<'_>, build_context: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<TransactionContext>>,
{
    b.iter_custom(|iters| {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let tx_context = build_context().await.expect("failed to build tx context");
                let start = Instant::now();
                let _ = black_box(tx_context.execute().await);
                total += start.elapsed();
            }
            total
        })
    });
}

/// Same shape as [`bench_async_execute`] but also drives the prover after `execute()`.
fn bench_async_execute_and_prove<F, Fut>(b: &mut Bencher<'_>, build_context: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<TransactionContext>>,
{
    b.iter_custom(|iters| {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let tx_context = build_context().await.expect("failed to build tx context");
                let start = Instant::now();
                let executed = tx_context.execute().await.expect("execute failed");
                let _ = black_box(prove_transaction(executed));
                total += start.elapsed();
            }
            total
        })
    });
}

criterion_group!(benches, core_benchmarks);
criterion_main!(benches);
