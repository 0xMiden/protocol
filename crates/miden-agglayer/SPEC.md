# AggLayer <> Miden Bridge Integration Specification

**Scope:** Implementation-accurate specification of the AggLayer bridge integration on
Miden, covering contracts, note flows, storage, and encoding semantics.

**Baseline:** Commit `be765b035`. All statements in sections 1–8 describe current
implementation behaviour and are cross-checked against the test suite in
`crates/miden-testing/tests/agglayer/`. Planned changes that diverge from the current
implementation are isolated in section 9.

**Conventions:**

- *Word* = 4 field elements (felts), each < p (Goldilocks prime 2^64 − 2^32 + 1).
- *Felt* = a single Goldilocks field element.
- Word values in this spec use **element-index notation** matching Rust's
  `Word::new([e0, e1, e2, e3])`. MASM doc comments use **stack notation** (top-first),
  which reverses the order: stack `[a, b, c, d]` = Word `[d, c, b, a]`.
- Procedure input/output signatures use **stack notation** (top-first), matching the
  MASM doc comments.
- `TODO (Future)` marks non-implemented design points; see section 9 for the full list.

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
| CONFIG_AGG_BRIDGE | Anyone — **not enforced** (TODO #2450) | Bridge account — **enforced** via `NetworkAccountTarget` attachment |
| UPDATE_GER | Anyone — **not enforced** (TODO #2467) | Bridge account — **enforced** via `NetworkAccountTarget` attachment |
| CLAIM | Anyone — not restricted | Target faucet only — **enforced**: script checks `consuming account == target_faucet_account_id` from note storage (TODO #2468) |

---
