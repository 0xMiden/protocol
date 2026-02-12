---
sidebar_position: 5
title: "Storage"
---

# Account Storage

:::note
A flexible, arbitrary data store within the `Account`.
:::

The [storage](https://docs.rs/miden-protocol/latest/miden_protocol/account/struct.AccountStorage.html) consists of up to 256 individual [storage slots](https://docs.rs/miden-protocol/latest/miden_protocol/account/enum.StorageSlot.html), where each slot consists of:
- Key: Slot name.
- Value: either a single [`Word`](#storage-units) or a key-value map of [`Word`](#storage-units)s.

So, account storage can be thought of as a map from slot name to slot value.

#### Storage units

The basic storage unit in account storage is a `Word`. A `Word` consists of 4 elements where each element is slightly less than a 64-bit value. Specifically, a maximum value of an element is $2^{64} - 2^{32}$. Thus, a single `Word` can contain almost 32 bytes of data.

Since a `Word` cannot store exactly 32 bytes of data, we may need to use multiple words to store such binary data as Keccak or SHA256 hashes. At the minimum, a 32-byte hash would require 5 elements to store, but it is recommended to encode such hashes into 8 elements with each element containing 32 bits of data. In both cases, two words would be used to store the hash.

## Slot Name

Each slot has a name associated with it that uniquely identifies it in the account's storage.

One example for a slot name is:

```text
miden::standards::fungible_faucets::metadata
```

Slot names are intended to be _globally unique_. This means `miden::standards::fungible_faucets::metadata` should always identify a slot that contains the standardized metadata for a fungible faucet. [Account components](components.md) that define their own storage slots should therefore choose names that avoid collisions.

To reduce the chance of slot name collisions, it is recommended that slot names have at least three components separated by `::`. A recommended pattern is:

```text
project_name::component_name::slot_name
```

### Slot ID

Because slot names are too large to be used directly in the transaction kernel, a _slot ID_ is used instead. The slot ID is derived from the hash of the slot name. Miden Assembly APIs will always work with the slot ID instead of the slot name.

## Slot types

Each slot has one of the following types:

- **Value slot:** Contains a single `Word` of arbitrary data.
- **Map slot:** Contains a [StorageMap](#map-slots), a key-value store where both keys and values are `Word`s. The slot's value is set to the root of the map.

An account's storage is typically the result of merging multiple [account components](./components).

### Value Slots

A value slot can be used whenever a single `Word` (almost 32 bytes) of data is enough, e.g. for storing a single public key commitment for use in [authentication procedures](code#authentication).

Value slots can be used with `set_item`, `get_item` and `get_initial_item` APIs.

### Map Slots

A map slot contains a `StorageMap` which is a key-value store implemented as a sparse Merkle tree (SMT). This allows an account to store a much larger amount of data than would be possible using only the account's storage slots. The root of the underlying SMT is stored in a single account storage slot, and each map entry is a leaf in the tree. When retrieving an entry (e.g., via `active_account::get_map_item`), its inclusion is proven using a Merkle proof.

Key properties of `StorageMap`:

- **Efficient, scalable storage:** The SMT structure enables efficient storage and proof of inclusion for a large number of entries, while only storing the root in the account's storage slot.
- **Partial presence:** Not all entries of the map need to be present at transaction execution time to access or modify the map. It is sufficient if only the accessed or modified items are present in the advice provider.
- **Key hashing:** Since map keys are user-chosen and may not be uniformly distributed, keys are hashed before being inserted into the SMT. This ensures a more balanced tree and mitigates efficiency issues due to key clustering. The original keys are retained in a separate map, allowing for introspection (e.g., querying the set of stored original keys for debugging or explorer scenarios). This introduces some redundancy, but enables useful features such as listing all stored keys.

This design allows for flexible, scalable, and privacy-preserving storage within accounts, supporting both large datasets and efficient proof generation.

Map slots can be used with `set_map_item`, `get_map_item` and `get_initial_map_item` APIs.

Additionally, `get_item` and `get_initial_item` can also be used to access the root of the storage map.
