# Miden Transaction Benchmarking

Below we describe how to benchmark Miden transactions.

### Benchmarked Transactions

The following transactions are benchmarked:

- **P2ID notes**: Consume single P2ID notes, consume two P2ID notes, and create single P2ID note - each with both Falcon and ECDSA signing
- **CLAIM notes (agglayer bridge-in)**: Consume CLAIM note for L1-to-Miden bridging and L2-to-Miden bridging
- **B2AGG note (agglayer bridge-out)**: Consume B2AGG note for Miden-to-AggLayer bridging

The CLAIM note benchmarks measure the full bridge-in flow: the benchmark setup executes prerequisite transactions (CONFIG_AGG_BRIDGE and UPDATE_GER) to prepare the bridge account, then benchmarks the CLAIM note consumption transaction itself.

The B2AGG note benchmark measures the bridge-out flow: the benchmark setup registers a faucet in the bridge via CONFIG_AGG_BRIDGE, then benchmarks the B2AGG note consumption which validates the faucet, performs FPI to get origin asset data, computes the Keccak leaf hash for the MMR, and creates a BURN note.

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
                        time:   [4.5477 ms 4.5691 ms 4.5900 ms]
                        change: [+0.6557% +1.4158% +2.1447%] (p = 0.00 < 0.05)
                        Change within noise threshold.
  Execute transaction/ecdsa/two-p2id-notes
                        time:   [3.1504 ms 3.1623 ms 3.1764 ms]
                        change: [-3.7669% -3.0640% -2.3537%] (p = 0.00 < 0.05)
                        Performance has improved.
  Execute transaction/claim-note-l2
                        time:   [4.6662 ms 4.6822 ms 4.6996 ms]
                        change: [-3.0893% -2.2258% -1.4266%] (p = 0.00 < 0.05)
                        Performance has improved.

  Execute and prove transaction/poseidon2/falcon/single-p2id-note
                        time:   [3.4986 s 3.5265 s 3.5558 s]
                        change: [-0.1326% +0.6794% +1.5087%] (p = 0.15 > 0.05)
                        No change in performance detected.
  Execute and prove transaction/poseidon2/ecdsa/two-p2id-notes
                        time:   [865.50 ms 869.96 ms 875.46 ms]
                        change: [-4.1704% -3.3025% -2.4024%] (p = 0.00 < 0.05)
                        Performance has improved.
  Execute and prove transaction/poseidon2/claim-note-l1
                        time:   [1.7053 s 1.7118 s 1.7194 s]
                        change: [-4.2221% -3.5400% -2.8705%] (p = 0.00 < 0.05)
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
