use std::hint::black_box;
use std::time::Duration;

use anyhow::Result;
use bench_transaction::context_setups::{tx_consume_single_p2id_note, tx_consume_two_p2id_notes};
use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_protocol::transaction::{ExecutedTransaction, ProvenTransaction};
use miden_tx::LocalTransactionProver;

// BENCHMARK NAMES
// ================================================================================================

const BENCH_GROUP_EXECUTE: &str = "Execute transaction";
const BENCH_EXECUTE_TX_CONSUME_SINGLE_P2ID: &str =
    "Execute transaction which consumes single P2ID note";
const BENCH_EXECUTE_TX_CONSUME_TWO_P2ID: &str = "Execute transaction which consumes two P2ID notes";

const BENCH_GROUP_EXECUTE_AND_PROVE: &str = "Execute and prove transaction";
const BENCH_EXECUTE_AND_PROVE_TX_CONSUME_SINGLE_P2ID: &str =
    "Execute and prove transaction which consumes single P2ID note";
const BENCH_EXECUTE_AND_PROVE_TX_CONSUME_TWO_P2ID: &str =
    "Execute and prove transaction which consumes two P2ID notes";

// CORE PROVING BENCHMARKS
// ================================================================================================

fn core_benchmarks(c: &mut Criterion) {
    // EXECUTE GROUP
    // --------------------------------------------------------------------------------------------

    let mut execute_group = c.benchmark_group(BENCH_GROUP_EXECUTE);

    execute_group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_millis(1000));

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

    execute_group.finish();

    // EXECUTE AND PROVE GROUP
    // --------------------------------------------------------------------------------------------

    let mut execute_and_prove_group = c.benchmark_group(BENCH_GROUP_EXECUTE_AND_PROVE);

    execute_and_prove_group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_millis(1000));

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
                    black_box(prove_transaction(
                        tx_context
                            .execute()
                            .await
                            .expect("execution of the single P2ID note consumption tx failed"),
                    ))
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
                    black_box(prove_transaction(
                        tx_context
                            .execute()
                            .await
                            .expect("execution of the two P2ID note consumption tx failed"),
                    ))
                },
                BatchSize::SmallInput,
            );
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

criterion_group!(benches, core_benchmarks);
criterion_main!(benches);
