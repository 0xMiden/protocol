use std::hint::black_box;
use std::time::Duration;

use bench_note_checker::benchmark_names::{BENCH_GROUP, BENCH_MIXED_NOTES};
use bench_note_checker::{MixedNotesConfig, run_mixed_notes_check, setup_mixed_notes_benchmark};
use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use miden_tx::MAX_NUM_CHECKER_NOTES;

fn note_checker_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group(BENCH_GROUP);

    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(10));

    // Benchmark with different numbers of failing notes.
    for failing_count in [1, 10, MAX_NUM_CHECKER_NOTES] {
        group.bench_function(format!("{BENCH_MIXED_NOTES}_{failing_count}_failing"), |b| {
            let setup =
                setup_mixed_notes_benchmark(MixedNotesConfig { failing_note_count: failing_count })
                    .expect("failed to set up mixed notes benchmark");

            b.to_async(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("failed to build tokio runtime"),
            )
            .iter(|| async { black_box(run_mixed_notes_check(&setup).await) });
        });
    }

    group.finish();
}

criterion_group!(benches, note_checker_benchmarks);
criterion_main!(benches);
