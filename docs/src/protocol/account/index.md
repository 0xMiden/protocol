---
sidebar_position: 1
---

# Accounts / Smart Contracts

An `Account` represents the primary entity in Miden. It is capable of holding assets, storing data, and executing custom code. Each `Account` is a smart contract with a programmable interface through which note and transaction scripts can interact with the account's state and assets. By executing [transactions](../transaction) against an account, its state can be modified.

## What is the purpose of an account?

In Miden's hybrid UTXO- and account-based model, accounts enable the creation of expressive smart contracts via a Turing-complete language. For example, an account with a wallet interface can hold the assets of a user while a DEX account could have an interface to trade assets.

## Account composition

An `Account` is composed of several core parts, illustrated below:

<p style={{textAlign: 'center'}}>
    <img src={require('../img/account/account-definition.png').default} style={{width: '30%'}} alt="Account diagram"/>
</p>

These parts are:

1. [ID](id.md)
2. [Code](code.md)
3. [Storage](storage.md)
4. [Vault](#vault)
5. [Nonce](#nonce)

### Vault

:::note
A collection of [assets](../asset.md) stored by the `Account`.
:::

Large amounts of fungible and non-fungible assets can be stored in the account's vault.

### Nonce

:::note
A counter incremented with each state update to the `Account`.
:::

The nonce ensures that an account has a unique _commitment_ (or "hash") after every transaction, even if it contains the same assets and has the same storage state. That in turn allows ordering of transactions and prevents replay attacks. Whenever the state of an account changes in a transaction, its nonce must be incremented and it can only be incremented exactly once per transaction.

Note that a transaction does not always change the state of an account. For instance, a transaction in which two SWAP notes are matched together does not necessarily change anything about the account state. Consequently, the nonce does not have to be incremented.

## Account creation

For an `Account` to be recognized by the network, it must exist in the [account database](../state#account-database) maintained by Miden node(s).

However, a user can locally create a new `Account` ID before it's recognized network-wide. The typical process might be:

1. Alice generates a new `Account` ID locally (according to the desired `Account` type) using the Miden client.
2. The Miden client checks with a Miden node to ensure the ID does not already exist.
3. Alice shares the new ID with Bob to receive an asset.
4. Bob executes a transaction against his account, creating a note with assets for Alice.
5. Alice consumes Bob's note in a transaction against her new account to claim the asset. This
   transaction is the first transaction against Alice's account and so it will register the account
   ID in the account database.
