---
name: domain-newtypes-over-primitives
description: Use when introducing API parameters, struct fields, or return types that carry a domain value — represent them with a domain newtype that enforces their invariants.
---

# Use Domain Newtypes, Not Raw Primitives

## Rule

When an API boundary takes or returns a value with a domain meaning, define a newtype that:

- Validates the value at construction time (see `validate-in-constructor`).
- Exposes the inner representation only through deliberate accessors.
- Is used at every API boundary touching the concept (not raw `u64`/`Word`/tuples).

Raw `(AccountId, u64)` tuples, bare `Word` parameters, and primitive-typed amounts must be replaced with a named type like `FungibleAsset`, `FaucetId`, `BlockNumber`.

## Why

A newtype is the one place an invariant gets enforced; once a function takes a raw `u64` for an amount, every caller and reviewer must re-check the bound. It also localizes representation changes to a single type instead of every signature.

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
