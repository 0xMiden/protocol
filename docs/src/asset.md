---
sidebar_position: 4
---

# Assets

An `Asset` is a unit of value that can be transferred from one [account](./account) to another using [notes](note).

## What is the purpose of an asset?

In Miden, assets serve as the primary means of expressing and transferring value between [accounts](./account) through [notes](note). They are designed with four key principles in mind:

1. **Parallelizable exchange:**  
   By managing ownership and transfers directly at the account level instead of relying on global structures like ERC20 contracts, accounts can exchange assets concurrently, boosting scalability and efficiency.

2. **Self-sovereign ownership:**  
   Assets are stored in the accounts directly. This ensures that users retain complete control over their assets.

3. **Censorship resistance:**  
   Users can transact freely and privately with no single contract or entity controlling `Asset` transfers. This reduces the risk of censored transactions, resulting in a more open and resilient system.

4. **Fee payment in native asset:**  
   Transaction fees are paid in the chain's native asset as defined by the current reference block's fee parameters. See [Fees](fees.md).

## Native asset

:::note
All data structures following the Miden asset model that can be exchanged.
:::

Native assets adhere to the Miden `Asset` model (encoding, issuance, storage). Every native `Asset` is encoded using 64 bytes (vault key and value), including both the [ID](./account/id) of the issuing account and the `Asset` details.

### Issuance

Accounts that issue assets are referred to as faucets. They can issue either fungible or non-fungible assets as defined at asset creation. The faucet's code specifies the `Asset` minting conditions: i.e., how, when, and by whom these assets can be minted. Once minted, they can be transferred to other accounts using notes.

<p style={{textAlign: 'center'}}>
    <img src={require('./img/asset/asset-issuance.png').default} style={{width: '70%'}} alt="Asset issuance"/>
</p>

:::tip
An account can technically issue different types of assets simultaneously, for example, both a fungible asset with [callbacks](#callbacks) disabled and a non-fungible asset with callbacks enabled. It is highly recommended that accounts issue only one type of asset, in order to have a simple 1-to-1 relationship between faucets and asset types.
:::

### Encoding

Every asset is stored as a key-value pair of two `Word`s: The vault key and the asset value.

While the asset value is unique to each type of asset, the vault key has a common structure for all types of assets:

```text
[
  asset_id_suffix (64 bits),
  asset_id_prefix (64 bits),
  [faucet_id_suffix (56 bits) | reserved (5 bits) | callback_flag (1 bit) | composition (2 bits)],
  faucet_id_prefix (64 bits)
]
```

- `faucet_id_suffix` and `faucet_id_prefix` is the ID of the faucet which issues the asset. The transaction kernel ensures that a given account can only issue assets when the faucet ID matches its own ID.
- `asset_id_suffix` and `asset_id_prefix` is an ID that determines if two assets issued by the same faucet are considered to be the same asset. It is set by the asset creator arbitrarily - see [identity](#identity) for more.
- `callback_flag` is the flag that determines whether callbacks are enabled (see also [callbacks](#callbacks)).
- `composition` describes how assets compose. Read on for more details.
- `reserved` bits are reserved for future use and should be assumed to be undefined and therefore not relied upon.

:::note
The `callback_flag` and `composition` are also referred to as "asset metadata".
:::

### Composition

Assets can compose in two ways: They can be merged or split. This is automatically done by the transaction kernel when assets are added to an account's vault or to the assets in a note.

Example: If an account has 10 USDC in its vault and 20 are added, the transaction kernel merges these two instances into one instance with amount 30.

The transaction kernel needs two pieces of information to work with assets:
1. _Whether_ an asset need to be merged or split with another instance. This comes down to whether two assets have the same _identity_.
2. If so, _how_ do these two instances compose, if at all? This comes down to the `composition` defined by the asset.

When an asset is added or removed from an account's vault or added to a note, the transaction kernel may have to compose assets:
- If 10 USDC are added to an account vault that already contains 20 USDC, then these two instances must be _merged_.
- If 10 USDC are removed from an account vault that contains 20 USDC, then 10 USDC must be _split_ off the 20 USDC.
- If 10 USDC are added to an empty account vault, then the asset can be written directly into the vault without needing to merge or split anything.

#### Identity

Note that for example's sake, we use "USDC" as the _identifier_ of an asset, and so 10 USDC and 20 USDC are instances of the same type of asset. In practice, the identity of an asset is determined by its [vault key](#encoding).

:::info
Two assets are of the same type whenever their vault keys match.
:::

The transaction kernel relies on this rule and so creators of assets need to ensure that:
- Instances of assets that should compose, should have identical vault keys.
- Instances of assets that should _not_ compose, should have different vault keys.

The asset ID can be used by asset creators to ensure this. Let's look at the native fungible and non-fungible assets:
- Fungible assets should _always_ compose and so by construction, their asset ID limbs are set to zero. This ensures two instances of a fungible asset have the same vault key.
- Non-fungible assets should _never_ compose and so by construction, their asset ID limbs are set to parts of their hash value. In practice, this ensures that two instances of non-fungible assets have unique vault keys. The transaction kernel never attempts to compose these.

#### Composition

Now that the transaction kernel knows _whether_ two assets need to compose, it also needs to know _how_ these instances compose. This is where the `composition` flag comes into play. It can fall into one of three categories:

- `None`: Instances do not compose. Used by non-fungible assets.
- `Fungible`: Instances compose according to the native fungible asset, by summing their amounts, up to the maximum supply.
- `Custom`: Instances compose according to faucet-defined logic. Currently disabled and reserved for future use.

:::danger
If the transaction kernel encounters two assets that need to be merged and their composition is set to `None`, it will abort. It is therefore important to ensure that assets that do not compose have unique [_identities_](#identity).
:::

The `Fungible` composition is a specialization of the transaction kernel for native fungible assets. The advantage of this built-in way of composing assets is that the issuing faucet does not need to be called.

On the other hand, `Custom` would involve invoking `merge` and `split` implementations defined by the issuing faucet via a callback.

### Fungible Assets

The native fungible asset has the following vault key and value layout:

- Vault key: `[0, 0, faucet_id_suffix | callback_flag | composition, faucet_id_prefix]`.
  - Its `callback_flag` can be disabled or enabled.
  - Its `composition` must be set to `Fungible`.
- Value: `[amount, 0, 0, 0]`.
  - The amount is always $2^{63}-2^{31}$ or smaller, representing the maximum supply for any fungible `Asset`.

Note how the `Fungible` composition variant together with the asset ID limbs set to zero, ensure that instances of fungible assets can always be merged and split.

Examples of such assets include ETH and various stablecoins (e.g. DAI, USDT, USDC).

### Non-Fungible Assets

The native non-fungible asset is encoded by hashing arbitrary data into 32 bytes, which results in the asset value.

- Vault key: `[hash0, hash1, faucet_id_suffix | callback_flag | composition, faucet_id_prefix]`.
  - Its `callback_flag` can be disabled or enabled.
  - Its `composition` must be set to `None`.
- Value: `[hash0, hash1, hash2, hash3]`.

Note how the `None` composition variant together with the asset ID limbs set to hashes from the asset value, ensure that instances of non-fungible assets are never attempted to be merged or split by the transaction kernel.

Examples of such assets include NFTs like a DevCon ticket.

### Storage

[Accounts](./account) and [notes](note) have vaults used to store assets. Accounts use a sparse Merkle tree as a vault while notes use a simple list. This enables an account to store a practically unlimited number of assets while a note can only store up to 64 assets.

<p style={{textAlign: 'center'}}>
    <img src={require('./img/asset/asset-storage.png').default} style={{width: '70%'}} alt="Asset storage"/>
</p>

### Burning

Assets in Miden can be burned through various methods, such as rendering them unspendable by storing them in an unconsumable note, or sending them back to their original faucet for burning using it's dedicated function.

### Callbacks

Asset callbacks allow a faucet to execute custom logic whenever one of its assets is added to an account vault or to an output note. This gives asset issuers a mechanism to enforce policies on their assets. For example, maintaining a block list of accounts that are not allowed to receive the asset or globally pausing transfers of assets.

#### How callbacks work

Callbacks involve two parts: a **per-asset flag** and **faucet-level callback procedures**.

**Per-asset callback flag.** Every asset carries a single-bit callback flag in its vault key. When the flag is `Enabled`, the kernel checks for and invokes callbacks on the issuing faucet whenever the asset is added to a vault or note. When the flag is `Disabled`, callbacks are skipped entirely. This flag is set at asset creation time and the protocol does not prevent issuing assets with different flags from the same faucet. Technically, this gives faucets the ability to issue a callback-enabled and a callback-disabled variant of their assets.

:::warning
Two assets issued by the same faucet with _different_ callback flags are considered completely different assets by the protocol.
:::

It is recommended that faucets issue all of their assets with the same flag to ensure all assets issued by a faucet are treated as one type of asset. This is ensured when using `faucet::create_fungible_asset` or `faucet::create_non_fungible_asset`.

**Faucet callback procedures.** A faucet registers callbacks by storing the procedure root (hash) of one if its public account procedures in a well-known storage slot. Two callbacks are supported:

| Callback | Storage slot name | Triggered when |
|---|---|---|
| `on_before_asset_added_to_account` | `miden::protocol::faucet::callback::on_before_asset_added_to_account` | The asset is added to an account's vault (via `native_account::add_asset`). |
| `on_before_asset_added_to_note` | `miden::protocol::faucet::callback::on_before_asset_added_to_note` | The asset is added to an output note (via `output_note::add_asset`). |

Account components that need to add callbacks to an account's storage should use the `AssetCallbacks` type, which provides an easy-to-use abstraction over these details.

#### Callback interfaces

The transaction kernel invokes the callback on the issuing faucet and the callback receives the asset key and value and is expected to return the processed asset value.

:::warning
At this time, the processed asset value must be the same as the asset value, but in the future this limitation may be lifted.
:::

The **account callback** receives:

```
Inputs:  [ASSET_KEY, ASSET_VALUE, pad(8)]
Outputs: [PROCESSED_ASSET_VALUE, pad(12)]
```

The **note callback** receives the additional `note_idx` identifying which output note the asset is being added to:

```
Inputs:  [ASSET_KEY, ASSET_VALUE, note_idx, pad(7)]
Outputs: [PROCESSED_ASSET_VALUE, pad(12)]
```

Both callbacks are invoked via `call`, so they must follow the convention of accepting and returning 16 stack elements (input + padding).

#### Callback skipping

A callback is not invoked in any of these cases:

- The asset's callback flag is `Disabled`.
- The issuing faucet does not have the corresponding callback storage slot.
- The callback storage slot contains the empty word.

This means assets with callbacks enabled can still be used even if the faucet has not (yet) registered a callback procedure.

## Alternative asset models

:::note
All data structures not following the Miden asset model that can be exchanged.
:::

Miden is flexible enough to support other `Asset` models. For example, developers can replicate Ethereum’s ERC20 pattern, where fungible `Asset` ownership is recorded in a single account. To transact, users send a note to that account, triggering updates in the global hashmap state.
