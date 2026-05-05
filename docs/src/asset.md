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

Native assets adhere to the Miden `Asset` model (encoding, issuance, storage). Every native `Asset` is encoded using 32 bytes, including both the [ID](./account/id) of the issuing account and the `Asset` details.

### Issuance

:::note
Only [faucet](./account/id#account-type) accounts can issue assets.
:::

Faucets can issue either fungible or non-fungible assets as defined at account creation. The faucet's code specifies the `Asset` minting conditions: i.e., how, when, and by whom these assets can be minted. Once minted, they can be transferred to other accounts using notes.

<p style={{textAlign: 'center'}}>
    <img src={require('./img/asset/asset-issuance.png').default} style={{width: '70%'}} alt="Asset issuance"/>
</p>

### Type

#### Fungible asset

Fungible assets are encoded with the amount and the `faucet_id` of the issuing faucet. The amount is always $2^{63}-1$ or smaller, representing the maximum supply for any fungible `Asset`. Examples include ETH and various stablecoins (e.g., DAI, USDT, USDC).

#### Non-fungible asset

Non-fungible assets are encoded by hashing the `Asset` data into 32 bytes and placing the `faucet_id` as the second element. Examples include NFTs like a DevCon ticket.

### Storage

[Accounts](./account) and [notes](note) have vaults used to store assets. Accounts use a sparse Merkle tree as a vault while notes use a simple list. This enables an account to store a practically unlimited number of assets while a note can only store 255 assets.

<p style={{textAlign: 'center'}}>
    <img src={require('./img/asset/asset-storage.png').default} style={{width: '70%'}} alt="Asset storage"/>
</p>

### Encoding

Every asset in an account vault is stored as a key/value pair of two `Word`s (eight field elements). The same encoding is used by both the kernel and the standard library, and is the canonical layout when assets cross the MASM/Rust boundary.

```
ASSET_KEY   = [asset_id_suffix, asset_id_prefix, faucet_id_suffix_with_metadata, faucet_id_prefix]
ASSET_VALUE = [amount, 0, 0, 0]   # fungible
ASSET_VALUE = DATA_HASH           # non-fungible
```

The `asset_id_*` limbs distinguish different assets issued by the same faucet:

- For fungible assets they are always `0`. A faucet only ever issues one asset, so the faucet ID alone identifies it.
- For non-fungible assets they are `DATA_HASH[0]` and `DATA_HASH[1]` — the first two field elements of the hash of the asset data.

The third element of the key, `faucet_id_suffix_with_metadata`, packs the faucet's account-ID suffix together with a small metadata byte. The lower 8 bits of every account-ID suffix are reserved zero by construction (`validate_suffix` in `account/account_id/v0/mod.rs`), and `AssetVaultKey::to_word()` (`asset/vault/vault_key.rs`) bit-OR's the metadata byte into those reserved bits. There is no left-shift; the suffix is already aligned.

Today only the lowest of those 8 bits is used, holding the per-asset callback flag from `AssetCallbackFlag` (`asset/asset_callbacks_flag.rs`):

- `Disabled = 0` — the kernel skips faucet callbacks for this asset.
- `Enabled  = 1` — the kernel checks for and invokes the faucet's callback procedures (see [Callbacks](#callbacks) below).

The remaining 7 bits are reserved for future asset-level metadata.

#### Worked example

A fungible asset with `amount = 10000`, callbacks enabled, issued by a faucet whose ID has `suffix = 447750849984126720` and `prefix = 12959558562786060576` lays out in vault memory as:

```text
[ 0,                       ← asset_id_suffix (zero for fungible)
  0,                       ← asset_id_prefix (zero for fungible)
  447750849984126721,      ← faucet_id_suffix | callbacks_enabled (suffix ends in 0x00, OR'd with 0x01)
  12959558562786060576,    ← faucet_id_prefix
  10000,                   ← amount
  0, 0, 0 ]                ← ASSET_VALUE padding
```

For a non-fungible asset the last four elements are replaced with `DATA_HASH` and the first two elements of the key are filled from `DATA_HASH[0..2]`. See `FungibleAsset::to_value_word()` and `NonFungibleAsset::to_value_word()` in `asset/fungible.rs` and `asset/nonfungible.rs`.

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
