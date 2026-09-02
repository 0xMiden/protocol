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
   Transaction fees are denominated in the chain's native asset as defined by the current reference block's fee parameters, and paid in the asset committed via the transaction's auth args (the native asset at rate 1/1, or a different asset at a committed conversion rate). See [Fees](fees.md).

## Native asset

:::note
All data structures following the Miden asset model that can be exchanged.
:::

Native assets adhere to the Miden `Asset` model (encoding, issuance, storage). Every native `Asset` is encoded using 64 bytes (asset ID and value), including both the [ID](./account/id) of the issuing account and the `Asset` details.

### Issuance

Accounts that issue assets are referred to as faucets. They can issue either fungible or non-fungible assets as defined at asset creation. The faucet's code specifies the `Asset` minting conditions: i.e., how, when, and by whom these assets can be minted. Once minted, they can be transferred to other accounts using notes.

<p style={{textAlign: 'center'}}>
    <img src={require('./img/asset/asset-issuance.png').default} style={{width: '70%'}} alt="Asset issuance"/>
</p>

:::tip
An account can technically issue different types of assets simultaneously, for example, both a fungible and a non-fungible asset. It is highly recommended that accounts issue only one type of asset, in order to have a simple 1-to-1 relationship between faucets and asset types.
:::

### Encoding

Every asset is stored as a key-value pair of two `Word`s: The asset ID and the asset value.

While the asset value is unique to each type of asset, the asset ID has a common structure for all types of assets:

```text
[
  asset_class_suffix (64 bits),
  asset_class_prefix (64 bits),
  [faucet_id_suffix (56 bits) | reserved (2 bits) | composition (2 bits) | version (4 bits)],
  faucet_id_prefix (64 bits)
]
```

- `faucet_id_suffix` and `faucet_id_prefix` is the ID of the faucet which issues the asset. The transaction kernel ensures that a given account can only issue assets when the faucet ID matches its own ID.
- `asset_class_suffix` and `asset_class_prefix` is a class that determines if two assets issued by the same faucet are considered to be the same asset. It is set by the asset creator arbitrarily - see [identity](#identity) for more.
- `composition` describes how assets compose. Read on for more details.
- `version` determines how the remainder of the asset is decoded. The only valid version is currently `1`. Version `0` is unassigned and invalid, which means an empty word is guaranteed to _not_ be a valid asset ID.
- `reserved` bits are reserved for future use and should be assumed to be undefined and therefore not relied upon.

Whether the asset triggers [callbacks](#callbacks) is not part of the asset ID: it is an immutable property of the issuing faucet's account ID.

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

Note that for example's sake, we use "USDC" as the _identifier_ of an asset, and so 10 USDC and 20 USDC are instances of the same type of asset. In practice, the identity of an asset is determined by its [asset ID](#encoding).

:::info
Two assets are of the same type whenever their asset IDs match.
:::

The transaction kernel relies on this rule and so creators of assets need to ensure that:
- Instances of assets that should compose, should have identical asset IDs.
- Instances of assets that should _not_ compose, should have different asset IDs.

The asset class can be used by asset creators to ensure this. Let's look at the native fungible and non-fungible assets:
- Fungible assets should _always_ compose and so by construction, their asset class limbs are set to zero. This ensures two instances of a fungible asset have the same asset ID.
- Non-fungible assets should _never_ compose and so by construction, their asset class limbs are set to parts of their hash value. In practice, this ensures that two instances of non-fungible assets have unique asset IDs. The transaction kernel never attempts to compose these.

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

The native fungible asset has the following asset ID and value layout:

- Asset ID: `[0, 0, faucet_id_suffix | composition | version, faucet_id_prefix]`.
  - Its `composition` must be set to `Fungible`.
- Value: `[amount, 0, 0, 0]`.
  - The amount is always $2^{63}-2^{31}$ or smaller, representing the maximum supply for any fungible `Asset`.

Note how the `Fungible` composition variant together with the asset class limbs set to zero, ensure that instances of fungible assets can always be merged and split.

Examples of such assets include ETH and various stablecoins (e.g. DAI, USDT, USDC).

### Non-Fungible Assets

The native non-fungible asset is encoded by hashing arbitrary data into 32 bytes, which results in the asset value.

- Asset ID: `[hash0, hash1, faucet_id_suffix | composition | version, faucet_id_prefix]`.
  - Its `composition` must be set to `None`.
- Value: `[hash0, hash1, hash2, hash3]`.

Note how the `None` composition variant together with the asset class limbs set to hashes from the asset value, ensure that instances of non-fungible assets are never attempted to be merged or split by the transaction kernel.

Examples of such assets include NFTs like a DevCon ticket.

### Storage

[Accounts](./account) and [notes](note) have vaults used to store assets. Accounts use a sparse Merkle tree as a vault while notes use a simple list. This enables an account to store a practically unlimited number of assets while a note can only store up to 16 assets.

Asset IDs are hashed before being used as keys in the underlying sparse Merkle tree. Hashing the raw key ensures a uniform leaf distribution: in particular, it prevents non-fungible assets issued by the same faucet from sharing an SMT leaf (their raw asset IDs share the fourth element - the faucet ID prefix - which the SMT uses to determine leaf membership).

<p style={{textAlign: 'center'}}>
    <img src={require('./img/asset/asset-storage.png').default} style={{width: '70%'}} alt="Asset storage"/>
</p>

### Burning

Assets in Miden can be burned through various methods, such as rendering them unspendable by storing them in an unconsumable note, or sending them back to their original faucet for burning using it's dedicated function.

### Callbacks

Asset callbacks allow a faucet to execute custom logic whenever one of its assets is added to an account vault or to an output note. This gives asset issuers a mechanism to enforce policies on their assets. For example, maintaining a block list of accounts that are not allowed to receive the asset or globally pausing transfers of assets.

#### How callbacks work

Callbacks involve two parts: a **faucet-level capability flag** and **faucet-level callback procedures**.

**Faucet callback flag.** Whether a faucet's assets trigger callbacks is an immutable single-bit flag of the faucet's account ID, fixed at account creation. When the flag is `Enabled`, the kernel checks for and invokes callbacks on the issuing faucet whenever one of its assets is added to a vault or note. When the flag is `Disabled`, callbacks are skipped entirely and no foreign-account read is performed. Because the flag lives in the account ID (which is carried in every asset ID) rather than in each asset, all assets issued by a faucet share the same callback behavior and cannot be fragmented.

**Faucet callback procedures.** A faucet registers callbacks by storing the procedure root (hash) of one if its public account procedures in a well-known storage slot. Two callbacks are supported:

| Callback | Storage slot name | Triggered when |
|---|---|---|
| `on_before_asset_added_to_account` | `miden::protocol::faucet::callback::on_before_asset_added_to_account` | The asset is added to an account's vault (via `native_account::add_asset`). |
| `on_before_asset_added_to_note` | `miden::protocol::faucet::callback::on_before_asset_added_to_note` | The asset is added to an output note (via `output_note::add_asset`). |

Account components that need to add callbacks to an account's storage should use the `AssetCallbacks` type, which provides an easy-to-use abstraction over these details.

#### Callback interfaces

The transaction kernel invokes the callback on the issuing faucet as a validation hook. The callback receives the asset ID and value for inspection. The callback either completes successfully or aborts the transaction.

The **account callback** receives:

```
Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
Outputs: [pad(16)]
```

The **note callback** receives the additional `note_idx` identifying which output note the asset is being added to:

```
Inputs:  [ASSET_ID, ASSET_VALUE, note_idx, pad(7)]
Outputs: [pad(16)]
```

Both callbacks are invoked via `dyncall`, so they must follow the convention of accepting and returning 16 stack elements (input + padding).

#### Expiration requirement

Asset callbacks execute against the issuing faucet through FPI. Any callback or callback-dispatched
policy that reads mutable security state must call `tx::update_expiration_block_delta` in the
execution path that reads that state. This includes checks against blocklists, allowlists, pause
flags, active policy roots, oracle values, risk parameters, or similar state.

Without an expiration delta, a prover can choose an older reference block where the callback state
allowed the transfer. The expiration delta bounds how stale that reference block may be when the
transaction is included. Standards components that need the common limit can use
`miden::standards::expiration::apply_default`; custom callbacks can call
`tx::update_expiration_block_delta` directly with a tighter limit.

Callbacks that only inspect immutable data, or for which stale data is acceptable, do not need to
set an expiration delta.

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

Alternative or programmable asset models that expose FPI-callable checks must follow the same
expiration rule as native asset callbacks: if a check reads mutable security state, it must set a
transaction expiration delta in that execution path.
