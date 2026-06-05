---
name: domain-newtypes-over-primitives
description: Use when introducing API parameters, struct fields, or return types that conceptually carry a domain value (asset amount, faucet ID, slot index, fee rate) — wrap them in a newtype that enforces invariants.
---

# Use Domain Newtypes, Not Raw Primitives

## Rule

When an API boundary takes or returns a value with a domain meaning, define a newtype that:

- Validates the value at construction time (see `validate-in-constructor`).
- Exposes the inner representation only through deliberate accessors.
- Is used at every API boundary touching the concept (not raw `u64`/`Word`/tuples).

Raw `(AccountId, u64)` tuples, bare `Word` parameters, and primitive-typed amounts must be replaced with a named type like `FungibleAsset`, `FaucetId`, `BlockNumber`.

## Why

A typed wrapper is the only place invariants get enforced. Once a function accepts `u64` for "amount", every caller is responsible for not passing a value above the max supply, and every reviewer has to check. With `FungibleAsset` (or similar) the type system enforces the rule once and everyone benefits.

Newtypes also make refactors safer: changing a representation (e.g. moving from `(prefix, suffix)` to a single `[u8; 16]`) touches one type, not every signature.

## Examples

```rust
// Good
pub fn mint(asset: FungibleAsset, to: AccountId) -> Result<Receipt, Error>;

// Bad
pub fn mint(faucet_id: AccountId, amount: u64, to: AccountId) -> Result<Receipt, Error>;
```

```rust
// Good: validated wrapper with explicit constructor
pub struct BlockNumber(u32);
impl BlockNumber {
    pub fn new(n: u32) -> Result<Self, Error> {
        if n > MAX_BLOCK_NUMBER { return Err(Error::OutOfRange); }
        Ok(Self(n))
    }
}

// Bad: raw u32 leaks into every signature, every caller checks the bound
pub fn lookup_block(n: u32) -> Option<Block>;
```
