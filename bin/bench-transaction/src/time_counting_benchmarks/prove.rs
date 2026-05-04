use std::future::Future;
use std::hint::black_box;
use std::time::{Duration, Instant};

use anyhow::Result;
use bench_transaction::context_setups::{
    ClaimDataSource,
    tx_consume_b2agg_note,
    tx_consume_claim_note,
    tx_consume_single_p2id_note,
    tx_consume_two_p2id_notes,
};
use criterion::{BatchSize, Bencher, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_protocol::transaction::{ExecutedTransaction, ProvenTransaction};
use miden_testing::TransactionContext;
use miden_tx::LocalTransactionProver;

// BENCHMARK NAMES
// ================================================================================================

const BENCH_GROUP_EXECUTE: &str = "Execute transaction";
const BENCH_EXECUTE_TX_CONSUME_SINGLE_P2ID: &str =
    "Execute transaction which consumes single P2ID note";
const BENCH_EXECUTE_TX_CONSUME_TWO_P2ID: &str = "Execute transaction which consumes two P2ID notes";
const BENCH_EXECUTE_TX_CONSUME_CLAIM_L1: &str =
    "Execute transaction which consumes CLAIM note (L1 to Miden)";
const BENCH_EXECUTE_TX_CONSUME_CLAIM_L2: &str =
    "Execute transaction which consumes CLAIM note (L2 to Miden)";
const BENCH_EXECUTE_TX_CONSUME_B2AGG: &str =
    "Execute transaction which consumes B2AGG note (bridge-out)";

const BENCH_GROUP_EXECUTE_AND_PROVE: &str = "Execute and prove transaction";
const BENCH_EXECUTE_AND_PROVE_TX_CONSUME_SINGLE_P2ID: &str =
    "Execute and prove transaction which consumes single P2ID note";
const BENCH_EXECUTE_AND_PROVE_TX_CONSUME_TWO_P2ID: &str =
    "Execute and prove transaction which consumes two P2ID notes";
const BENCH_EXECUTE_AND_PROVE_TX_CONSUME_CLAIM_L1: &str =
    "Execute and prove transaction which consumes CLAIM note (L1 to Miden)";
const BENCH_EXECUTE_AND_PROVE_TX_CONSUME_CLAIM_L2: &str =
    "Execute and prove transaction which consumes CLAIM note (L2 to Miden)";
const BENCH_EXECUTE_AND_PROVE_TX_CONSUME_B2AGG: &str =
    "Execute and prove transaction which consumes B2AGG note (bridge-out)";

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

    execute_group.bench_function(BENCH_EXECUTE_TX_CONSUME_SINGLE_P2ID, |b| {
        b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
            .iter_batched(
                || {
                    // prepare the transaction context
                    tx_consume_single_p2id_note()
                        .expect("failed to create a context which consumes single P2ID note")
                },
                |tx_context| async move {
                    // benchmark the transaction execution
                    black_box(tx_context.execute().await)
                },
                BatchSize::SmallInput,
            );
    });

    execute_group.bench_function(BENCH_EXECUTE_TX_CONSUME_TWO_P2ID, |b| {
        b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
            .iter_batched(
                || {
                    // prepare the transaction context
                    tx_consume_two_p2id_notes()
                        .expect("failed to create a context which consumes two P2ID notes")
                },
                |tx_context| async move {
                    // benchmark the transaction execution
                    black_box(tx_context.execute().await)
                },
                BatchSize::SmallInput,
            );
    });

    execute_group.bench_function(BENCH_EXECUTE_TX_CONSUME_CLAIM_L1, |b| {
        bench_async_execute(b, || tx_consume_claim_note(ClaimDataSource::L1ToMiden));
    });

    execute_group.bench_function(BENCH_EXECUTE_TX_CONSUME_CLAIM_L2, |b| {
        bench_async_execute(b, || tx_consume_claim_note(ClaimDataSource::L2ToMiden));
    });

    execute_group.bench_function(BENCH_EXECUTE_TX_CONSUME_B2AGG, |b| {
        bench_async_execute(b, tx_consume_b2agg_note);
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

    execute_and_prove_group.bench_function(BENCH_EXECUTE_AND_PROVE_TX_CONSUME_SINGLE_P2ID, |b| {
        b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
            .iter_batched(
                || {
                    // prepare the transaction context
                    tx_consume_single_p2id_note()
                        .expect("failed to create a context which consumes single P2ID note")
                },
                |tx_context| async move {
                    // benchmark the transaction execution and proving
                    black_box(
                        prove_transaction(
                            tx_context
                                .execute()
                                .await
                                .expect("execution of the single P2ID note consumption tx failed"),
                        )
                        .await,
                    )
                },
                BatchSize::SmallInput,
            );
    });

    execute_and_prove_group.bench_function(BENCH_EXECUTE_AND_PROVE_TX_CONSUME_TWO_P2ID, |b| {
        b.to_async(tokio::runtime::Builder::new_current_thread().build().unwrap())
            .iter_batched(
                || {
                    // prepare the transaction context
                    tx_consume_two_p2id_notes()
                        .expect("failed to create a context which consumes two P2ID notes")
                },
                |tx_context| async move {
                    // benchmark the transaction execution and proving
                    black_box(
                        prove_transaction(
                            tx_context
                                .execute()
                                .await
                                .expect("execution of the two P2ID note consumption tx failed"),
                        )
                        .await,
                    )
                },
                BatchSize::SmallInput,
            );
    });

    execute_and_prove_group.bench_function(BENCH_EXECUTE_AND_PROVE_TX_CONSUME_CLAIM_L1, |b| {
        bench_async_execute_and_prove(b, || tx_consume_claim_note(ClaimDataSource::L1ToMiden));
    });

    execute_and_prove_group.bench_function(BENCH_EXECUTE_AND_PROVE_TX_CONSUME_CLAIM_L2, |b| {
        bench_async_execute_and_prove(b, || tx_consume_claim_note(ClaimDataSource::L2ToMiden));
    });

    execute_and_prove_group.bench_function(BENCH_EXECUTE_AND_PROVE_TX_CONSUME_B2AGG, |b| {
        bench_async_execute_and_prove(b, tx_consume_b2agg_note);
    });

    execute_and_prove_group.finish();
}

async fn prove_transaction(executed_transaction: ExecutedTransaction) -> Result<()> {
    let executed_transaction_id = executed_transaction.id();
    let proven_transaction: ProvenTransaction =
        LocalTransactionProver::default().prove(executed_transaction).await?;

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
                let _ = black_box(prove_transaction(executed).await);
                total += start.elapsed();
            }
            total
        })
    });
}

criterion_group!(benches, core_benchmarks);
criterion_main!(benches);
