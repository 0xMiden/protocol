---
name: validate-in-constructor
description: Use when writing or reviewing a Rust constructor, `try_new`, or builder `build` — centralize validation so every instance is valid by construction.
---

# Validate Invariants in Constructors

## Rule

Every fallible construction path for a struct must run all invariants in a single canonical constructor (or builder `build`). The constructor must:

1. Validate every invariant the type promises to uphold.
2. Return `Err` on any input that would make the resulting value unusable — empty allowlists, zero thresholds, mutually inconsistent fields, etc.
3. Be the only externally callable way to produce an instance (struct literal construction must not be possible from outside the module).

Do not split validation across the constructor and downstream methods; do not allow direct field initialization that bypasses checks.

## Why

If a type can be constructed in an invalid or in-between state, every consumer has to defend against it; centralizing validation means holding a `T` is proof its invariants hold. Rejecting unusable configurations early keeps bugs from surfacing far from their cause.

## Examples

```rust
// Good: single validating constructor, no public fields
pub struct ProcedurePolicyMode {
    immediate_threshold: u32,
}

impl ProcedurePolicyMode {
    pub fn new(immediate_threshold: u32) -> Result<Self, PolicyError> {
        if immediate_threshold == 0 {
            return Err(PolicyError::ZeroThreshold);
        }
        Ok(Self { immediate_threshold })
    }
}

// Good: reject empty allowlist that would brick the account
impl ScriptRoots {
    pub fn new(roots: BTreeSet<Digest>) -> Result<Self, Error> {
        if roots.is_empty() {
            return Err(Error::EmptyAllowlist);
        }
        Ok(Self { roots })
    }
}

// Bad: in-between invalid state possible
let mut metadata = FungibleTokenMetadata::default();
metadata.set_name(name);
metadata.set_supply(supply);
metadata.validate()?;  // can be forgotten
```
