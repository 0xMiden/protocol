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
- standards, consumed by a network account with the matching management components: CONSTANT_FEE_POLICY_CONFIG, FAUCET_POLICY_CONFIG, FAUCET_METADATA_CONFIG, MIN_BURN_AMOUNT_CONFIG, ALLOWLIST_CONFIG, BLOCKLIST_CONFIG, PAUSE_CONFIG, OWNER_CONFIG, RBAC_CONFIG, NETWORK_ACCOUNT_CONFIG (one representative action selector each; other selectors run the identical dispatch path); UPGRADE (the new code is taken from the note attachment)
- agglayer, consumed by the bridge account (a network account): CLAIM (L1 vs L2 origin, with fee payment), B2AGG (empty vs `2^31 - 1`-leaf frontier, with fee payment), CONFIG_AGG_BRIDGE, DEREGISTER_AGG_FAUCET, UPDATE_GER, REMOVE_GER

The original CLAIM/B2AGG scenarios (without fee payment) are kept unchanged for continuity; the `with fee payment` variants are the network-account pricing baseline.

The network-account auth procedure collects sponsored fees and answers sponsorship fee estimates natively, so every fee-paying network-account scenario's cost includes the fee-collection scan and TX_FEE creation.

### Note Consumption Cost Tables

The network-account scenarios feed two checked-in, generated cost tables: `crates/miden-standards/src/note/costs/table.rs` and `crates/miden-agglayer/src/costs/table.rs`. Each table entry is the note's consumption cost in VM cycles - the total cycle count of the canonical network-account transaction consuming it, taken as the maximum across the note's benchmarked execution paths. The values are estimates, not guaranteed worst cases - see the caveats in `miden_standards::note::costs` (e.g. asset counts are benchmarked at the planned, not current, protocol maximum).

Regenerate the tables (and `bench-tx.json`) with:

```bash
make update-generated
```

Freshness is enforced in CI: the `checked_in_note_costs_match_executed_scenarios` snapshot test in `src/note_costs.rs` re-executes every priced scenario during the regular test run and fails when a measured cost drifts more than 5% from its checked-in constant, or when a note's declared `created_notes` do not match what its scenarios actually create. It walks `PricedNote::all` - so all priced notes are covered. Drift within the tolerance (from unrelated changes landing on the base branch) is absorbed without regeneration - fee-wise this is safe, since the fee is logarithmic in cycles and the pricing safety margin dwarfs it. Regenerate only when this test fails, committing both artifacts together; between refreshes `bench-tx.json` may lag the current tree.

### Benchmark Groups

Each of the above transactions is measured in two groups:
- Benchmarking the transaction execution.

  For each transaction, data is collected on the number of cycles required to complete:
  - Prologue
  - `total_cycles`: the sum of the prologue, notes-processing, tx-script and epilogue intervals,
    and the figure the cost tables above are derived from
  - All notes processing
  - Each note execution, in consumption order and labelled by note kind (`P2ID`, or `P2ID#0` /
    `P2ID#1` when a scenario consumes several notes of one kind). Notes whose script is neither a
    standard nor an agglayer one are labelled `UNKNOWN`.
  - Transaction script processing
  - Epilogue:
    - Total number of cycles
    - Authentication procedure
    - After tx cycles were obtained (The number of cycles the epilogue took to execute after the number of transaction cycles were obtained)

  The same pass rebuilds the `ExecutionTrace` for each scenario. It records the AIR row totals (`core_rows`, `chiplets_rows`, `eidos_compression_rows`, and `byte_pair_lookup_rows`) and the per-chiplet breakdown (`hasher_rows`, `bitwise_rows`, `memory_rows`, `kernel_rom_rows`, and `ace_rows`).

  Results of this benchmark will be stored in the [`bin/bench-tx/bench-tx.json`](bench-tx.json) file.
- Benchmarking the transaction execution and proving.
  
  For each transaction in this group we measure how much time it takes to execute the transaction and to execute and prove the transaction.

  Proving benchmarks use Eidos, matching the protocol proof-hash policy.

  This group uses [Criterion.rs](https://github.com/bheisler/criterion.rs) to measure elapsed time. Benchmark IDs use separate path segments for the account's signing scheme (`falcon` or `ecdsa`) and, for proving benchmarks, the proof hash (`eidos`). Network-authenticated CLAIM and B2AGG transactions omit the signing-scheme segment. Example IDs include `Execute transaction/falcon/single-p2id-note` and `Execute and prove transaction/eidos/falcon/single-p2id-note`.

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

The `trace` section in `bench-tx.json` is the input contract for miden-vm's `miden-vm-synthetic-bench`. Its hard targets are the four AIR row totals: `trace.core_rows`, `trace.chiplets_rows`, `trace.eidos_compression_rows`, and `trace.byte_pair_lookup_rows`. The `trace.chiplets_shape.*` breakdown is profiling metadata. It must satisfy the chiplet-bus invariant `chiplets_rows == hasher + bitwise + memory + kernel_rom + ace + 1`.

The consumer's hard match is on padded power-of-two brackets, not raw row equality:

- `padded_core              = max(64, next_pow2(core_rows))`
- `padded_chiplets          = max(64, next_pow2(chiplets_rows))`
- `padded_eidos_compression = max(64, next_pow2(eidos_compression_rows))`
- `padded_byte_pair_lookup  = max(64, next_pow2(byte_pair_lookup_rows))`

These values can fall into different brackets for the same workload. For example, `consume two P2ID notes with Falcon signing` has `padded_core = 65536`, `padded_chiplets = 8192`, `padded_eidos_compression = 131072`, and `padded_byte_pair_lookup = 65536`.

The checked contract is the generated scenario, its four authoritative AIR row counts, and the
independently pinned padded brackets rather than byte stability across separate executions.

To feed the snapshot into `miden-vm`, regenerate `bench-tx.json` here and copy it across:

```bash
cargo run --release --bin bench-transaction --features concurrent
cp bin/bench-transaction/bench-tx.json \
   ../miden-vm/benches/synthetic-bench/snapshots/bench-tx.json
cd ../miden-vm
cargo bench -p miden-vm-synthetic-bench
```

The VM keeps a byte-for-byte copy of this generated file but selects only its canonical six
Falcon/ECDSA P2ID scenarios for the default synthetic suite. The schema is maintained manually;
`bench-tx.json`'s `trace` section is what the consumer's loader keys off. When changing the shape
of the trace section, update both repositories together.

## License

This project is [MIT licensed](../../LICENSE).
