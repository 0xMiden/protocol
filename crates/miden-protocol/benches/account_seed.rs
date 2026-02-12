use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_protocol::Word;
use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
use rand::{Rng, SeedableRng};

/// Running this benchmark with --no-default-features will use the single-threaded account seed
/// computation.
///
/// Passing --features concurrent will use the multi-threaded account seed computation.
///
/// To produce a flamegraph, run with the `--profile-time` argument.
///
/// ```sh
/// cargo bench -p miden-protocol --no-default-features -- --profile-time 10
/// ```
///
/// The flamegraph will be saved as `target/criterion/grind-seed/Grind regular public account
/// seed/profile/flamegraph.svg`.
fn grind_account_seed(c: &mut Criterion) {
    let mut group = c.benchmark_group("grind-seed");
    // Increase measurement time (= target time) from the default 5s as suggested by criterion
    // during a run.
    group.measurement_time(Duration::from_secs(20));

    let init_seed = [
        1, 18, 222, 14, 56, 94, 222, 213, 12, 57, 86, 1, 22, 34, 187, 100, 210, 1, 18, 222, 14, 56,
        94, 43, 213, 12, 57, 86, 1, 22, 34, 187,
    ];
    // Use an rng to ensure we're starting from different seeds for each iteration.
    let mut rng = rand_xoshiro::Xoshiro256PlusPlus::from_seed(init_seed);

    group.bench_function("Grind regular public account seed", |bench| {
        bench.iter(|| {
            AccountId::compute_account_seed(
                rng.random(),
                AccountType::RegularAccountImmutableCode,
                AccountStorageMode::Public,
                AccountIdVersion::Version0,
                Word::empty(),
                Word::empty(),
            )
        })
    });

    group.finish();
}

fn with_pprof_profiler() -> Criterion {
    Criterion::default().with_profiler(pprof::criterion::PProfProfiler::new(
        1_000_000,
        pprof::criterion::Output::Flamegraph(None),
    ))
}

criterion_group! {
  name = account_seed;
  config = with_pprof_profiler();
  targets = grind_account_seed
}
criterion_main!(account_seed);
