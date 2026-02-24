# AggLayer <> Miden Bridge Integration Specification

**Scope:** Implementation-accurate specification of the AggLayer bridge integration on
Miden, covering contracts, note flows, storage, and encoding semantics.

**Baseline:** Commit `be765b035`. All statements in sections 1–8 describe current
implementation behaviour and are cross-checked against the test suite in
`crates/miden-testing/tests/agglayer/`. Planned changes that diverge from the current
implementation are isolated in section 8.

**Conventions:**

- *Word* = 4 field elements (felts), each < p (Goldilocks prime 2^64 − 2^32 + 1).
- *Felt* = a single Goldilocks field element.
- Word values in this spec use **element-index notation** matching Rust's
  `Word::new([e0, e1, e2, e3])`. MASM doc comments use **stack notation** (top-first),
  which reverses the order: stack `[a, b, c, d]` = Word `[d, c, b, a]`.
- Procedure input/output signatures use **stack notation** (top-first), matching the
  MASM doc comments.
- `TODO (Future)` marks non-implemented design points; see section 8 for the full list.

---

## 1. Entities and Trust Model

| Entity | Description | Account type |
|--------|-------------|--------------|
| **User** | End-user Miden account that holds assets and initiates bridge-out deposits, or recieves assets from a bridge-in claim. | Any account with `basic_wallet` component |
| **AggLayer Bridge** | Onchain bridge account that manages the Local Exit Tree (LET), faucet registry, and GER state. Consumes B2AGG, CONFIG, and UPDATE_GER notes. | Network-mode account with `bridge_out` + `bridge_in` components (TODO: consolidate into single component)|
| **AggLayer Faucet** | Fungible faucet that represents a single bridged token. Mints on bridge-in claims, burns on bridge-out. Each foreign token has its own faucet instance. | `FungibleFaucet`, network-mode, with `agglayer_faucet` component |
| **Integration Service** (offchain) | Observes L1 events (deposits, GER updates) and creates UPDATE_GER and CLAIM notes on Miden. Trusted to provide correct proofs and data. | Not an onchain entity; creates notes targeting bridge/faucet |
| **Bridge Operator** (offchain) | Deploys bridge and faucet accounts. Creates CONFIG_AGG_BRIDGE notes to register faucets. | Not an onchain entity; creates config notes |

### Current permissions

| Note type | Issuer (sender check) | Consumer (consuming-account check) |
|-----------|----------------------|-----------------------------------|
| B2AGG (bridge-out) | Any user — not restricted | Bridge account — **enforced** via `NetworkAccountTarget` attachment. |
| B2AGG (reclaim) | Any user — not restricted | Original sender only — **enforced**: script checks `sender == consuming account` |
| CONFIG_AGG_BRIDGE | Anyone — **not enforced** ([TODO #2450](https://github.com/0xMiden/miden-base/issues/2450)) | Bridge account — **enforced** via `NetworkAccountTarget` attachment |
| UPDATE_GER | Anyone — **not enforced** ([TODO #2467](https://github.com/0xMiden/miden-base/issues/2467)) | Bridge account — **enforced** via `NetworkAccountTarget` attachment |
| CLAIM | Anyone — not restricted | Target faucet only — **enforced**: script checks `consuming account == target_faucet_account_id` from note storage ([TODO #2468](https://github.com/0xMiden/miden-base/issues/2468)) |

---

## 2. Contracts and Public Interfaces

### 2.1 Bridge Account Components

The bridge account is composed of two components:
([TODO #2294](https://github.com/0xMiden/miden-base/issues/2294): consolidate into single component)

1. **`bridge_out` component** — includes `bridge_out.masm`, `bridge_config.masm`,
   `local_exit_tree.masm`, and supporting modules
2. **`bridge_in` component** — includes `bridge_in.masm`

#### `bridge_out::bridge_out`

| | |
|-|-|
| **Invocation** | `call` |
| **Inputs** | `[ASSET, dest_network_id, dest_addr₀, dest_addr₁, dest_addr₂, dest_addr₃, dest_addr₄, pad(4)]` |
| **Outputs** | `[]` |
| **Context** | Consuming a `B2AGG` note on the bridge account |
| **Panics** | Faucet not in registry; FPI to faucet fails |

Bridges an asset out of Miden into the AggLayer:

1. Validates the asset's faucet is registered in the faucet registry.
2. FPIs to `agglayer_faucet::asset_to_origin_asset` on the faucet account to obtain the scaled U256 amount, origin token address, and origin network.
3. Builds a leaf-data structure in memory (leaf type, origin network, origin token address, destination network, destination address, amount, metadata hash).
4. Computes the Keccak-256 leaf value and appends it to the Local Exit Tree (MMR frontier).
5. Creates a public `BURN` note targeting the faucet, tagged with `NoteTag::with_account_target(faucet_id)` ([TODO #2470](https://github.com/0xMiden/miden-base/issues/2470): should be a network note).

#### `bridge_config::register_faucet`

| | |
|-|-|
| **Invocation** | `call` |
| **Inputs** | `[faucet_id_prefix, faucet_id_suffix, pad(14)]` |
| **Outputs** | `[pad(16)]` |
| **Context** | Consuming a `CONFIG_AGG_BRIDGE` note on the bridge account |
| **Panics** | None (no authorization check) |

Writes `[0, 0, faucet_suffix, faucet_prefix] → [1, 0, 0, 0]` into the
`faucet_registry` map slot.

> **TODO (Future):** No sender validation — anyone can register. See [#2450](https://github.com/0xMiden/miden-base/issues/2450).

#### `bridge_in::update_ger`

| | |
|-|-|
| **Invocation** | `call` |
| **Inputs** | `[GER_LOWER(4), GER_UPPER(4), pad(8)]` |
| **Outputs** | `[pad(16)]` |
| **Context** | Consuming an `UPDATE_GER` note on the bridge account |
| **Panics** | None |

Computes `KEY = rpo256::merge(GER_UPPER, GER_LOWER)` and stores
`KEY → [1, 0, 0, 0]` in the `ger` map slot. This marks the GER as "known".

#### `bridge_in::verify_leaf_bridge`

| | |
|-|-|
| **Invocation** | `call` (invoked via FPI from the faucet) |
| **Inputs** | `[LEAF_DATA_KEY, PROOF_DATA_KEY, pad(8)]` on the operand stack; proof data and leaf data in the advice map |
| **Outputs** | `[pad(16)]` |
| **Context** | FPI target — called by the faucet during `CLAIM` consumption |
| **Panics** | GER not known; global index not mainnet; rollup index non-zero; Merkle proof verification failed |

Verifies a bridge-in claim:

1. Retrieves leaf data from the advice map, computes the Keccak-256 leaf value.
2. Retrieves proof data from the advice map: SMT proofs, global index, exit roots.
3. Computes the GER from `mainnet_exit_root` and `rollup_exit_root`, asserts it is in
   the known GER set.
4. Extracts the leaf index from the global index (must be mainnet, rollup index = 0). (TODO: rollup indices are not processed yet [#2394](https://github.com/0xMiden/miden-base/issues/2394)).
5. Verifies the Merkle proof: leaf value at `leaf_index` against `mainnet_exit_root`.

#### Bridge Account Storage

| Slot name | Slot type | Key encoding | Value encoding | Purpose |
|-----------|-----------|-------------|----------------|---------|
| `miden::agglayer::bridge::faucet_registry` | Map | `[0, 0, faucet_suffix, faucet_prefix]` | `[1, 0, 0, 0]` if registered; `[0, 0, 0, 0]` if absent | Registered faucet lookup |
| `miden::agglayer::bridge::ger` | Map | `rpo256::merge(GER_UPPER, GER_LOWER)` | `[1, 0, 0, 0]` if known; `[0, 0, 0, 0]` if absent | Known Global Exit Root set |
| `miden::agglayer::let` | Map | `[h, 0, 0, 0]` → first word; `[h, 1, 0, 0]` → second word (for h = 0..31) | Per index h: two keys yield one double-word (2 words = 8 felts, a Keccak-256 digest). Absent keys return zeros. | Local Exit Tree MMR frontier |
| `miden::agglayer::let::root_lo` | Value | — | `[root₀, root₁, root₂, root₃]` | LET root low word (Keccak-256 lower 16 bytes) |
| `miden::agglayer::let::root_hi` | Value | — | `[root₄, root₅, root₆, root₇]` | LET root high word (Keccak-256 upper 16 bytes) |
| `miden::agglayer::let::num_leaves` | Value | — | `[count, 0, 0, 0]` | Number of leaves appended to the LET |

Initial state: all map slots empty, all value slots `[0, 0, 0, 0]`.

### 2.2 Faucet Account Component

The faucet account has the `agglayer_faucet` component, which bundles the `agglayer_faucet.masm`,
`asset_conversion.masm`, and `eth_address.masm` modules.

#### `agglayer_faucet::claim`

| | |
|-|-|
| **Invocation** | `call` |
| **Inputs** | `[PROOF_DATA_KEY, LEAF_DATA_KEY, OUTPUT_NOTE_DATA_KEY, pad(4)]` |
| **Outputs** | `[pad(16)]` |
| **Context** | Consuming a `CLAIM` note on the faucet account |
| **Panics** | Invalid proof; bridge ID not set; FPI to bridge fails; faucet distribution fails |

Processes a bridge-in claim:

1. Loads and verifies three advice map entries (proof data, leaf data, output note data).
2. Extracts the destination account ID from the leaf data's destination address (via `eth_address::to_account_id`).
3. Extracts the raw U256 claim amount from the leaf data.
4. FPI to `bridge_in::verify_leaf_bridge` on the bridge account to validate the proof.
5. Scales the amount down (TODO PR WIP [#2460](https://github.com/0xMiden/miden-base/pull/2460)).
6. Mints the asset via `faucets::distribute` and creates a public P2ID output note for the recipient.

#### `agglayer_faucet::asset_to_origin_asset`

| | |
|-|-|
| **Invocation** | `call` (invoked via FPI from the bridge) |
| **Inputs** | `[amount, pad(15)]` |
| **Outputs** | `[AMOUNT_U256₀(4), AMOUNT_U256₁(4), addr₀..addr₄, origin_network, pad(2)]` |
| **Context** | FPI target — called by the bridge during bridge-out |
| **Panics** | Scale exceeds 18 |

Converts a Miden-native asset amount to the origin chain's U256 representation:

1. Reads the scale from storage, calls `asset_conversion::scale_native_amount_to_u256`.
2. Returns the origin token address and origin network from storage.

#### `agglayer_faucet::burn`

This is a re-export of `miden::standards::faucets::basic_fungible::burn`. It burns the fungible asset from the active note, decreasing the faucet's token supply.

| | |
|-|-|
| **Invocation** | `call` |
| **Inputs** | `[pad(16)]` |
| **Outputs** | `[pad(16)]` |
| **Context** | Consuming a `BURN` note on the faucet account |
| **Panics** | Note context invalid; asset count wrong; faucet/supply checks fail |

#### Faucet Account Storage

| Slot name | Slot type | Value encoding | Purpose |
|-----------|-----------|----------------|---------|
| Faucet metadata (standard) | Value | `[token_supply, max_supply, decimals, token_symbol]` | Standard `NetworkFungibleFaucet` metadata |
| `miden::agglayer::faucet` (TODO change name in [#2356](https://github.com/0xMiden/miden-base/issues/2356)) | Value | `[0, 0, bridge_suffix, bridge_prefix]` | Bridge account ID this faucet is paired with |
| `miden::agglayer::faucet::conversion_info_1` | Value | `[addr₀, addr₁, addr₂, addr₃]` | Origin token address, first 4 u32 limbs |
| `miden::agglayer::faucet::conversion_info_2` | Value | `[addr₄, origin_network, scale, 0]` | Origin token address 5th limb, origin network ID, scale exponent |

---

## 3. Note Types and Storage Layouts

### 3.1 B2AGG (Bridge-to-AggLayer)

**Purpose:** User bridges an asset from Miden to the AggLayer.

| Property | Value |
|----------|-------|
| Script | `B2AGG.masb` |
| Note type | Public |
| Assets | Exactly 1 fungible asset |
| Attachment | `NetworkAccountTarget` — target is the bridge account |
| Note tag | `NoteTag::default()` |

**Storage layout (6 felts):**

| Index | Field | Encoding |
|-------|-------|----------|
| 0 | `destination_network` | u32 |
| 1–5 | `destination_address` | 5 × u32 felts (20-byte Ethereum address) |

**Consumption:**

- **Bridge-out:** Consuming account is the bridge → note validates attachment target,
  loads storage and asset, calls `bridge_out::bridge_out`.
- **Reclaim:** Consuming account is the original sender → assets are added back to the
  account via `basic_wallet::add_assets_to_account`. No output notes.

### 3.2 CLAIM

**Purpose:** Claim assets, which were deposited on any AggLayer-connected rollup, on Miden. Consumed by
the faucet (TODO [Re-orient `CLAIM` note flow](https://github.com/0xMiden/protocol/issues/2506)), which mints the asset and sends it to the recipient.

| Property | Value |
|----------|-------|
| Script | `CLAIM.masb` |
| Note type | Public |
| Assets | None |
| Attachment | `NetworkAccountTarget` — target is the faucet account |
| Note tag | `NoteTag::default()` |

**Storage layout (576 felts):**

| Range | Field | Size (felts) | Encoding |
|-------|-------|-------------|----------|
| 0–255 | `smt_proof_local_exit_root` | 256 | 32 × Keccak-256 nodes (8 felts each) |
| 256–511 | `smt_proof_rollup_exit_root` | 256 | 32 × Keccak-256 nodes (8 felts each) |
| 512–519 | `global_index` | 8 | U256 as 8 × u32 felts |
| 520–527 | `mainnet_exit_root` | 8 | Keccak-256 hash as 8 × u32 felts |
| 528–535 | `rollup_exit_root` | 8 | Keccak-256 hash as 8 × u32 felts |
| 536 | `leaf_type` | 1 | u32 (0 = asset) |
| 537 | `origin_network` | 1 | u32 |
| 538–542 | `origin_token_address` | 5 | 5 × u32 felts |
| 543 | `destination_network` | 1 | u32 |
| 544–548 | `destination_address` | 5 | 5 × u32 felts |
| 549–556 | `amount` | 8 | U256 as 8 × u32 felts |
| 557–564 | `metadata_hash` | 8 | Keccak-256 hash as 8 × u32 felts |
| 565–567 | padding | 3 | zeros |
| 568–571 | `output_p2id_serial_num` | 4 | Word — serial number for the P2ID output note |
| 572–573 | `target_faucet_account_id` | 2 | `[prefix, suffix]` of the target faucet |
| 574 | `output_note_tag` | 1 | NoteTag for the P2ID output note |
| 575 | padding | 1 | zero |

**Consumption:**

1. All 576 felts are loaded into memory.
2. Script asserts consuming account == target faucet (TODO unify how we enforce the consumer of CLAIM note [#2468](https://github.com/0xMiden/miden-base/issues/2468)).
3. Storage regions are hashed and inserted into the advice map as three keyed entries
   (proof data, leaf data, output note data).
4. `agglayer_faucet::claim` is called, which validates the proof via FPI to the bridge,
   then mints and creates a P2ID output note.

### 3.3 CONFIG_AGG_BRIDGE

**Purpose:** Registers a faucet in the bridge's faucet registry.

| Property | Value |
|----------|-------|
| Script | `CONFIG_AGG_BRIDGE.masb` |
| Note type | Public |
| Assets | None |
| Attachment | `NetworkAccountTarget` — target is the bridge account |
| Note tag | `NoteTag::default()` |

**Storage layout (2 felts):**

| Index | Field | Encoding |
|-------|-------|----------|
| 0 | `faucet_id_prefix` | Felt (AccountId prefix) |
| 1 | `faucet_id_suffix` | Felt (AccountId suffix) |

**Consumption:** Script validates attachment target, loads storage, calls
`bridge_config::register_faucet`.

### 3.4 UPDATE_GER

**Purpose:** Stores a new Global Exit Root (GER) in the bridge account so that subsequent
CLAIM notes can be verified against it.

| Property | Value |
|----------|-------|
| Script | `UPDATE_GER.masb` |
| Note type | Public |
| Assets | None |
| Attachment | `NetworkAccountTarget` — target is the bridge account |
| Note tag | `NoteTag::default()` |

**Storage layout (8 felts):**

| Range | Field | Encoding |
|-------|-------|----------|
| 0–3 | `GER_LOWER` | First 16 bytes as 4 × u32 felts |
| 4–7 | `GER_UPPER` | Last 16 bytes as 4 × u32 felts |

**Consumption:** Script validates attachment target, loads storage, calls
`bridge_in::update_ger`, which computes `rpo256::merge(GER_UPPER, GER_LOWER)` and
stores the result in the GER map.

### 3.5 BURN (generated)

**Purpose:** Created by `bridge_out::bridge_out` to burn the bridged asset on the faucet.

| Property | Value |
|----------|-------|
| Script | `StandardNote::BURN` (standard Miden burn script) |
| Note type | Public |
| Assets | The single asset from the originating B2AGG note |
| Attachment | None (TODO `BURN` note should have an attachment [#2470](https://github.com/0xMiden/miden-base/issues/2470)) |
| Note tag | `NoteTag::with_account_target(faucet_id)` (TODO same as above) |

**Storage layout (0 felts):**

No fields — this is a standard burn note with no custom data.

**Consumption:**

The standard BURN script calls `faucets::burn` on the consuming faucet account. This
validates that the note contains exactly one fungible asset issued by that faucet and
decreases the faucet's total token supply by the burned amount.

### 3.6 P2ID (generated)

**Purpose:** Created by `agglayer_faucet::claim` to deliver minted assets to the recipient.

| Property | Value |
|----------|-------|
| Script | Standard P2ID script |
| Note type | Public |
| Assets | Minted fungible asset for the claim amount |
| Attachment | None |
| Note tag | From CLAIM note storage (`output_note_tag` in output note data) |

**Storage layout (2 felts):**

| Index | Field | Encoding |
|-------|-------|----------|
| 0 | `target_account_id_prefix` | Felt (AccountId prefix) |
| 1 | `target_account_id_suffix` | Felt (AccountId suffix) |

**Consumption:**

Consuming account must match `target_account_id` from note storage (enforced by the P2ID
script). All note assets are added to the consuming account via
`basic_wallet::add_assets_to_account`.
