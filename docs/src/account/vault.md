---
sidebar_position: 6
title: "Vault"
---

# Account Vault

:::note
A cryptographically committed container for an account's [assets](../asset.md).
:::

The vault stores both [fungible and non-fungible](../asset.md#type) assets and reduces to a single 32-byte commitment (the root of its sparse Merkle tree). Only the account's own [code](./code.md) can modify its vault; external callers must go through the account's exported procedures (e.g., `receive_asset` and `move_asset_to_note` in a basic wallet [component](./components.md)).

## Data structure

The vault is implemented as a **Sparse Merkle Tree (SMT)**. All assets are stored as leaves in this tree, and the root of the tree serves as the vault commitment. The tree uses a depth equal to the global `SMT_DEPTH`.

Assets are keyed differently depending on their type:

- **Fungible assets:** The leaf index is derived from the issuing faucet's [account ID](./id.md). There is at most one leaf per faucet; when more of the same fungible asset is added, the amounts are aggregated into a single entry.
- **Non-fungible assets:** The leaf index is derived from the asset itself. Each unique non-fungible asset occupies its own leaf.

This keying scheme enables the vault to contain an unbounded number of distinct assets while keeping inclusion proofs logarithmic in the key space.

## Operations

### Adding assets

Adding an asset inserts or updates a leaf in the underlying SMT:

- **Fungible:** If the vault already contains an asset from the same faucet, the new amount is added to the existing balance. The combined amount must stay below $2^{63}$.
- **Non-fungible:** The asset is inserted as a new leaf. Adding a duplicate non-fungible asset that already exists in the vault is an error.

### Removing assets

Removing an asset updates or deletes a leaf:

- **Fungible:** The specified amount is subtracted from the current balance. If the remaining balance is zero, the leaf is removed from the tree. Attempting to remove more than the current balance, or removing an asset that does not exist, is an error.
- **Non-fungible:** The leaf is set to the empty value. Attempting to remove a non-fungible asset that is not in the vault is an error.

All vault modifications are tracked in a per-transaction delta, which records every addition and removal that occurred during the transaction.

## Commitment and capacity

- **Commitment:** The vault root is part of the account's overall state commitment. It can be queried via `get_vault_root` (current state) and `get_initial_vault_root` (state at the start of the transaction).
- **Capacity:** The SMT structure allows accounts to store a practically unlimited number of assets. Notes, by contrast, use a simple list and can hold at most 255 assets. See [asset storage](../asset.md#storage) for a comparison.
