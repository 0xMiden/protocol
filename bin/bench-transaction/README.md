# Miden Transaction Benchmarking

Below we describe how to benchmark Miden transactions.

### Benchmarked Transactions

The following transactions are benchmarked:

- **P2ID notes**: Consume single P2ID notes, consume two P2ID notes, and create single P2ID note - each with both Falcon and ECDSA signing
- **CLAIM notes (agglayer bridge-in)**: Consume CLAIM note for L1-to-Miden bridging and L2-to-Miden bridging
- **B2AGG note (agglayer bridge-out)**: Consume B2AGG note for Miden-to-AggLayer bridging
- **Network-account note consumption**: one scenario per standard note script and execution path, consumed in the canonical network-account transaction (see below)

The CLAIM note benchmarks measure the full bridge-in flow: the benchmark setup executes prerequisite transactions (CONFIG_AGG_BRIDGE and UPDATE_GER) to prepare the bridge account, then benchmarks the CLAIM note consumption transaction itself.

The B2AGG note benchmark measures the bridge-out flow: the benchmark setup registers a faucet in the bridge via CONFIG_AGG_BRIDGE, then benchmarks the B2AGG note consumption which validates the faucet, performs FPI to get origin asset data, computes the Keccak leaf hash for the MMR, and creates a BURN note.

### Network-Account Consumption Scenarios

These scenarios measure what consuming each note in `miden-standards` and `miden-agglayer` costs a network account - the basis for configuring network-account fee policies (see issue [#3344](https://github.com/0xMiden/protocol/issues/3344)). Each scenario builds the canonical network-account transaction as it exists today: the consuming account authenticates with `AuthNetworkAccount` (allowlisting exactly the consumed note's script root), carries the functional components the note requires, holds the native fee asset, and pays the transaction fee by creating a TX_FEE note during its auth procedure (the chain charges a verification base fee of 500).

Covered scenarios, with one variant per distinct execution path:

- standards, consumed by a network basic wallet: P2ID (1 vs 16 assets); P2IDE (claim, claim with 16 assets, reclaim); SWAP (public vs private payback); PSWAP (full vs partial fill); FEE_SPONSORSHIP (consumed with its sponsored feature note; the sponsor-side reclaim path is benchmarked separately on a regular wallet, since a network account cannot consume a lone sponsorship note)
- standards, consumed by a network faucet: MINT (fungible vs non-fungible faucet); BURN
- standards, consumed by a network account with the matching management components: CONSTANT_FEE_POLICY_CONFIG, FAUCET_POLICY_CONFIG, FAUCET_METADATA_CONFIG, ALLOWLIST_CONFIG, BLOCKLIST_CONFIG, PAUSE_CONFIG, OWNER_CONFIG, RBAC_CONFIG, NETWORK_ACCOUNT_CONFIG (one representative action selector each; other selectors run the identical dispatch path)
- agglayer, consumed by the bridge account (a network account): CLAIM (L1 vs L2 origin, with fee payment), B2AGG (empty vs `2^31 - 1`-leaf frontier, with fee payment), CONFIG_AGG_BRIDGE, DEREGISTER_AGG_FAUCET, UPDATE_GER, REMOVE_GER

The original CLAIM/B2AGG scenarios (without fee payment) are kept unchanged for continuity; the `with fee payment` variants are the network-account pricing baseline.

The network-account auth procedure collects sponsored fees and answers sponsorship fee estimates natively, so every fee-paying network-account scenario's cost includes the fee-collection scan and TX_FEE creation.

### Note Consumption Cost Tables

The network-account scenarios feed two checked-in, generated cost tables: `crates/miden-standards/src/note/costs/table.rs` and `crates/miden-agglayer/src/costs/table.rs`. Each table entry is the note's consumption cost in VM cycles - the total cycle count of the canonical network-account transaction consuming it, taken as the maximum across the note's benchmarked execution paths. The values are estimates, not guaranteed worst cases - see the caveats in `miden_standards::note::costs` (e.g. asset counts are benchmarked at the planned, not current, protocol maximum).

Regenerate the tables (and `bench-tx.json`) with:

```bash
make update-note-costs
```

Freshness is enforced in CI: the `checked_in_cost_matches_benched_cycles` snapshot tests in `src/note_costs.rs` re-execute every priced scenario during the regular test run and fail when a measured cost drifts more than 5% from its checked-in constant. Drift within the tolerance (from unrelated changes landing on the base branch) is absorbed without regeneration - fee-wise this is safe, since the fee is logarithmic in cycles and the pricing safety margin dwarfs it. A PR that meaningfully changes cycle counts must run `make update-note-costs` and commit the updated tables - which doubles as review signal, since cost regressions show up as table diffs.

### Benchmark Groups

Each of the above transactions is measured in two groups:
- Benchmarking the transaction execution.

  For each transaction, data is collected on the number of cycles required to complete:
  - Prologue
  - All notes processing
  - Each note execution
  - Transaction script processing
  - Epilogue:
    - Total number of cycles
    - Authentication procedure
    - After tx cycles were obtained (The number of cycles the epilogue took to execute after the number of transaction cycles were obtained)

  In the same pass we also rebuild the `ExecutionTrace` for each scenario and emit per-component trace row counts (`core_rows`, `chiplets_rows`, `range_rows`) plus the per-chiplet shape breakdown (`hasher_rows`, `bitwise_rows`, `memory_rows`, `kernel_rom_rows`, `ace_rows`).

  Results of this benchmark will be stored in the [`bin/bench-tx/bench-tx.json`](bench-tx.json) file.
- Benchmarking the transaction execution and proving.
  
  For each transaction in this group we measure how much time it takes to execute the transaction and to execute and prove the transaction.

  Notice that the `Poseidon2` hash function is used during the proving process.

  This group uses the [Criterion.rs](https://github.com/bheisler/criterion.rs) to collect the elapsed time. The benchmark ID encodes what was measured as separate path segments: the signing scheme of the benchmarked account (`falcon`/`ecdsa`) and, for the proving group, the hash function used during proving (`poseidon2`). Network-authenticated transactions (CLAIM, B2AGG) carry no signing scheme. Results are printed to the terminal and look like so:
  ```zsh
  Execute transaction/falcon/single-p2id-note
                          time:   [4.3236 ms 4.3544 ms 4.3862 ms]
                          change: [-7.0844% -4.9883% -3.4045%] (p = 0.00 < 0.05)
                          Performance has improved.

  Execute transaction/ecdsa/single-p2id-note
                          time:   [2.1275 ms 2.1294 ms 2.1317 ms]
                          change: [-6.5976% -6.1261% -5.7058%] (p = 0.00 < 0.05)
                          Performance has improved.

  Execute transaction/falcon/two-p2id-notes
                          time:   [5.1385 ms 5.1585 ms 5.1815 ms]
                          change: [-8.6872% -8.0431% -7.4236%] (p = 0.00 < 0.05)
                          Performance has improved.

  Execute transaction/ecdsa/two-p2id-notes
                          time:   [3.0454 ms 3.0503 ms 3.0567 ms]
                          change: [-5.9796% -5.5470% -5.1069%] (p = 0.00 < 0.05)
                          Performance has improved.

  Execute transaction/claim-note-l1
                          time:   [3.9404 ms 3.9586 ms 3.9790 ms]
                          change: [-7.4014% -6.1927% -5.0437%] (p = 0.00 < 0.05)
                          Performance has improved.

  Execute transaction/claim-note-l2
                          time:   [4.4660 ms 4.4774 ms 4.4902 ms]
                          change: [-9.7807% -8.4338% -7.1374%] (p = 0.00 < 0.05)
                          Performance has improved.

  Execute transaction/b2agg-note
                          time:   [30.228 ms 30.283 ms 30.367 ms]
                          change: [-6.6415% -6.1561% -5.6679%] (p = 0.00 < 0.05)
                          Performance has improved.


  Execute and prove transaction/poseidon2/falcon/single-p2id-note
                          time:   [3.3744 s 3.3833 s 3.3942 s]
                          change: [-11.007% -10.319% -9.7045%] (p = 0.00 < 0.05)
                          Performance has improved.

  Execute and prove transaction/poseidon2/ecdsa/single-p2id-note
                          time:   [870.68 ms 874.08 ms 877.59 ms]
                          change: [-12.232% -10.510% -8.9920%] (p = 0.00 < 0.05)
                          Performance has improved.

  Execute and prove transaction/poseidon2/falcon/two-p2id-notes
                          time:   [3.4046 s 3.4149 s 3.4255 s]
                          change: [-1.9928% -1.0219% -0.2023%] (p = 0.03 < 0.05)
                          Change within noise threshold.

  Execute and prove transaction/poseidon2/ecdsa/two-p2id-notes
                          time:   [873.72 ms 876.86 ms 880.41 ms]
                          change: [-3.7161% -2.4053% -1.1572%] (p = 0.00 < 0.05)
                          Performance has improved.

  Execute and prove transaction/poseidon2/claim-note-l1
                          time:   [1.7146 s 1.7209 s 1.7276 s]
                          change: [-15.987% -13.815% -11.896%] (p = 0.00 < 0.05)
                          Performance has improved.

  Execute and prove transaction/poseidon2/claim-note-l2
                          time:   [1.7157 s 1.7250 s 1.7364 s]
                          change: [-8.5252% -6.8302% -5.0772%] (p = 0.00 < 0.05)
                          Performance has improved.

  Execute and prove transaction/poseidon2/b2agg-note
                          time:   [6.8425 s 6.8683 s 6.8967 s]
                          change: [-10.551% -9.8033% -9.0014%] (p = 0.00 < 0.05)
                          Performance has improved.
  ```

  The results above were obtained on the MacBook Pro M2 with 32 GB of RAM.

## Running Benchmarks

You can run the benchmarks in two ways:

### Option 1: Using Make (from protocol directory)

```bash
make bench-tx
```

This command will run both the cycle counting and the time counting benchmarks.

### Option 2: Running each benchmark individually (from protocol directory)

```bash
# Run the cycle counting benchmarks
cargo run --bin bench-transaction --features concurrent

# Run the time counting benchmarks
cargo bench --bin bench-transaction --bench time_counting_benchmarks --features concurrent
```

## Trace shape and miden-vm's synthetic benchmark

The `trace` section in `bench-tx.json` is the input contract for miden-vm's `miden-vm-synthetic-bench`. Its hard targets are the AIR-side row totals (`trace.core_rows`, `trace.chiplets_rows`, `trace.range_rows`); the `trace.chiplets_shape.*` per-chiplet breakdown is advisory profiling metadata and is required to satisfy the chiplet-bus invariant `chiplets_rows == hasher + bitwise + memory + kernel_rom + ace + 1`.

The consumer's hard match is on padded power-of-two brackets, not raw row equality:

- `padded_core_side = max(64, next_pow2(max(core_rows, range_rows)))`
- `padded_chiplets  = max(64, next_pow2(chiplets_rows))`

These two can land in different brackets on the same workload (e.g. `consume two P2ID notes with Falcon signing` has `padded_core_side = 131072` but `padded_chiplets = 262144`).

To feed the snapshot into `miden-vm`, regenerate `bench-tx.json` here and copy it across:

```bash
cargo run --release --bin bench-transaction --features concurrent
cp bin/bench-transaction/bench-tx.json \
   ../miden-vm/benches/synthetic-bench/snapshots/bench-tx.json
cargo bench -p miden-vm-synthetic-bench
```

The schema is maintained manually; bench-tx.json's `trace` section is what the consumer's loader keys off. When changing the shape of the trace section, bump both repos together.

## License

This project is [MIT licensed](../../LICENSE).
