---
name: masm-rust-constant-parity
description: Use when changing a numeric constant in Rust or MASM that has a counterpart on the other side (MAX_NUM_SLOTS, ACCOUNT_ID_SIZE, header field widths, version numbers) — cross-check both sides in the same PR so they stay aligned.
---

# Keep Rust and MASM Constants Aligned

## Rule

Numeric constants that exist in both Rust and MASM and must agree (memory layouts, capacity limits, version numbers, field widths) need to be updated on both sides in the same PR. Specifically:

- When changing a Rust constant, search the MASM source tree for its counterpart and update it.
- When changing a MASM constant, search for its Rust counterpart and update it.
- Where possible, generate one side from the other (build script, codegen) so the cross-check is automatic.

A PR that updates only one side is incomplete — the kernel and the Rust host will disagree at runtime.

## Why

The kernel reads memory based on offsets the Rust client wrote. If one side updates `ACCOUNT_HEADER_LEN` and the other doesn't, every transaction misreads its own state. This class of bug is invisible until a real value happens to straddle the changed offset, which is often well after the PR has landed.

A reviewer-enforced cross-check (or, better, a codegen'd shared definition) catches it before merge.

## Examples

```rust
// In Rust
impl AccountHeader {
    pub const LEN_FELTS: usize = 8;
}
```

```masm
# In MASM — must equal the Rust constant
const ACCOUNT_HEADER_LEN_FELTS = 8
```

If you change either to `9`, change both in the same PR. Add a comment at one declaration pointing to the other (or a build-script assertion) if the relationship isn't obvious.

## Evidence

- PR #2795 (mmagician): "Numeric limits must agree across Rust and MASM; cross-check Rust constants against their MASM counterparts when changing either side."
- PR #1532 (bobbinth): "This constant also needs to change in MASM."
- PR #1353 (PhilippGackstatter): "MASM side is now out of sync with the Rust constant."
- PR #1982 (bobbinth): "Cross-check the kernel side."
