---
name: masm-rust-constant-parity
description: Use when changing a numeric or string constant in Rust or MASM that has a counterpart on the other side — keep the two definitions from drifting apart.
---

# Keep Rust and MASM Constants Aligned

## Rule

Constants that exist on both the MASM and the Rust side must not drift. Prefer a single source of truth: define the constant in MASM and generate the Rust counterpart from it, rather than hand-maintaining the same literal in two places.

This repo already does that in `crates/miden-protocol/build.rs`: it scans the MASM sources for `const ERR_... = "..."` and `const X = event("...")` definitions and emits Rust files (`tx_kernel_errors.rs`, `protocol_errors.rs`, `transaction_events.rs`) that are pulled in with `include!(concat!(env!("OUT_DIR"), ...))` (see `src/errors/mod.rs` and `src/transaction/kernel/tx_event_id.rs`). A new error or event constant added in MASM gets its Rust binding automatically.

For constants not covered by codegen (memory offsets, capacity limits, field widths still duplicated in `src/constants.rs` / `memory.rs`), update both sides in the same PR — and prefer extending the generation over adding another hand-copied literal.

## Why

The kernel reads memory at offsets the Rust host wrote. If one side changes `ACCOUNT_HEADER_LEN` and the other doesn't, every transaction misreads its state, and the bug stays invisible until a value happens to straddle the changed offset. Generating one side from the other removes the chance to forget.

## Examples

Source of truth in MASM:

```masm
const ERR_PROLOGUE_NEW_ACCOUNT_VAULT_MUST_BE_EMPTY="new account must have an empty vault"
```

Generated into `OUT_DIR` by `build.rs` and included via `include!(concat!(env!("OUT_DIR"), "/tx_kernel_errors.rs"))`:

```rust
pub const ERR_PROLOGUE_NEW_ACCOUNT_VAULT_MUST_BE_EMPTY: MasmError =
    MasmError::from_static_str("new account must have an empty vault");
```

For a constant that is still hand-duplicated, change both in the same PR:

```rust
// crates/miden-protocol/src/constants.rs
pub const MAX_INPUT_NOTES_PER_TX: usize = 1024;
```

```masm
# crates/miden-protocol/asm/.../constants.masm — must equal the Rust constant
pub const MAX_INPUT_NOTES_PER_TX = 1024
```
