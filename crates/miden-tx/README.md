# Miden Transaction

This crate contains tool for creating, executing, and proving Miden blockchain transaction.

## Usage

This crate exposes a few components to compile, run, and prove transactions.

The first requirement is to have a `DataStore` implementation. `DataStore` objects are responsible to load the data needed by the transactions executor, especially the account's code, the reference block data, and the note's storage.

```rust
let store = DataStore:new();
```

Once a store is available, a `TransactionExecutor` object can be used to execute a transaction. Consuming a zero or more notes, and possibly calling some of the account's code.

```rust
let executor = TransactionExecutor::new(store);
let executed_transaction = executor.execute_transaction(account_id, block_ref, notes, tx_args);
```

With the transaction execution done, it is then possible to create a proof:

```rust
let prover = LocalTransactionProver::new(ProvingOptions::default());
let proven_transaction = prover.prove(executed_transaction);
```

And to verify a proof:

```rust
let verifier = TransactionVerifier::new(SECURITY_LEVEL);
verifier.verify(proven_transaction);
```

## Features

| Features     | Description                                                                                   |
| ------------ | --------------------------------------------------------------------------------------------- |
| `std`        | Enable usage of Rust's `std`, use `--no-default-features` for `no-std` support.               |
| `concurrent` | Enables concurrent code to speed up runtime execution.                                        |

## License

This project is [MIT licensed](../../LICENSE).
