# Miden Protocol

This crates contains core components defining the Miden protocol including the Miden protocol kernels.

## Modules

Here is a broad overview of each module, with links to additional documentation.


### Accounts

Structures used to define accounts, including abstractions over its code, storage, and vault.

[Documentation](https://0xmiden.github.io/miden-base/account/overview.html).

### Assets

Structures used to define fungible and non-fungible assets. Accounts own assets and store them in their vaults.

[Documentation](https://0xMiden.github.io/miden-base/asset.html)


### Block

Structures used to define a block. These objects contain authentication structures, merkle trees, used to represent the state of the chain at a given point in time.

### Notes

Structures used to define notes. Notes are messages that contain code and assets. They describe their own behavior and allow for interaction among accounts. Notes come in multiple flavors, refer to the docs for additional details.

[Documentation](https://0xMiden.github.io/miden-base/note.html)

### Transaction

Structures used to define Miden blockchain transactions. Transactions describe changes to an account, and may include consumption and production of notes. The objects in this module allow for the representation of transactions at multiple stages of its lifecycle, from creation, to data aggregation, execution with trace collection, and finally an executed transaction with a corresponding STARK proof.

[Documentation](https://0xMiden.github.io/miden-base/transaction.html).

## Features

Description of this crate's feature:

| Features     | Description                                                                                   |
|--------------|-----------------------------------------------------------------------------------------------|
| `std`        | Enable usage of Rust's `std`, use `--no-default-features` for `no-std` support.               |
| `concurrent` | Enables concurrent code to speed up runtime execution.                                        |
| `testing`    | Enables testing utilities and reduces proof-of-work requirements to speed up tests' runtimes. |

## License

This project is [MIT licensed](../../LICENSE).
