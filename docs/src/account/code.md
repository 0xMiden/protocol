---
sidebar_position: 4
title: "Code"
---

# Account Code

:::note
A collection of procedures defining the `Account`'s programmable interface.
:::

Every Miden `Account` is essentially a smart contract. The `Code` defines the account's procedures, which can be invoked through both [note scripts](../note#script) and [transaction scripts](../transaction#inputs). Key characteristics include:

- **Mutable access:** Only the `Account`'s own procedures can modify its storage and vault. All state changes — such as updating storage slots or transferring assets — must occur through these procedures.
- **Function commitment:** Each function can be called by its [MAST](https://0xMiden.github.io/miden-vm/user_docs/assembly/main.html) root. The root represents the underlying code tree as a 32-byte commitment. This ensures integrity which means a function's behavior cannot change without changing the MAST root.
- **Asset creation:** Faucet `Accounts` can create assets.

## Interface

An account's code is typically the result of merging multiple [account components](./components). This results in a set of procedures that make up the _interface_ of the account. As an example, a typical wallet uses the so-called _basic wallet_ interface, which is defined in `miden::standards::wallets::basic`. It consists of the `receive_asset` and `move_asset_to_note` procedures. If an account has this interface, i.e. this set of procedures, it can consume standard [P2ID notes](../note#p2id-pay-to-id). If it doesn't, it can't consume this type of note. So, adhering to standard interfaces such as the basic wallet will generally make an account more interoperable.

## Authentication

Authenticating a transaction, and therefore the changes to the account, is done with an _authentication procedure_. Every account's code must provide exactly one authentication procedure. It is automatically called during the transaction epilogue, i.e. after all note scripts and the transaction script have been executed.

Such an authentication procedure typically inspects the transaction and then decides whether a signature is required to authenticate the changes. It does this by:

- checking which account procedures have been called
  - Example: Authentication is required if the `distribute` procedure was called but not if `burn` was called.
- inspecting the account delta.
  - Example: Authentication is required if a cryptographic key in storage was updated.
  - Example: Authentication is required if an asset was removed from the vault.
- checking whether notes have been consumed.
- checking whether notes have been created.

Recall that an [account's nonce](index.md#nonce) must be incremented whenever its state changes. Only authentication procedures are allowed to do so, to prevent accidental or unintended authorization of state changes.

### Procedure invocation checks

The authentication procedure can base its authentication decision on whether a specific account procedure was called during the transaction. A procedure invocation is tracked by the kernel only if it invokes account-restricted kernel APIs (procedures that are only allowed to be called from the account context, e.g. `exec.faucet::mint`). Invocation of procedures that execute only local instructions (e.g., a noop `push.0 drop`) will not be tracked by the kernel.
