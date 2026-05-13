---
name: validate-in-constructor
description: Use when writing or reviewing a Rust constructor, `try_new`, or builder `build` — centralize validation so every instance is valid by construction, and reject configurations (empty allowlists, zero thresholds, mutually inconsistent fields) that render the object unusable.
---

# Validate Invariants in Constructors

## Rule

Every fallible construction path for a struct must run all invariants in a single canonical constructor (or builder `build`). The constructor must:

1. Validate every invariant the type promises to uphold.
2. Return `Err` on any input that would make the resulting value unusable — empty allowlists, zero thresholds, mutually inconsistent fields, etc.
3. Be the only externally callable way to produce an instance (struct literal construction must not be possible from outside the module).

Do not split validation across the constructor and downstream methods; do not allow direct field initialization that bypasses checks.

## Why

If the type can be constructed in an intermediate or invalid state, every consumer has to defend against it. Centralizing validation means once you hold a `T`, you can trust its invariants without re-checking.

Rejecting unusable configurations early (e.g. an empty script-roots allowlist that "bricks" the account, a zero threshold for a policy that requires `count >= threshold`) prevents bugs from surfacing far from their cause.

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

## Evidence

- PR #2795 (mmagician): "Constructors should validate inputs and centralize derived-state computation so callers cannot bypass invariants."
- PR #2883 (bobbinth): "Reject configurations that would render an object permanently unusable at construction time."
- PR #2439 (PhilippGackstatter): "I would in any case suggest validating before building the struct, so that once you have a FungibleTokenMetadata, you know it is valid and do not have an in-between state where the struct could be invalid."
- PR #2670 (PhilippGackstatter): "Ideally, what this function validates should be enforced in `ProcedurePolicyMode`. We should not be able to construct a `ProcedurePolicyMode` with immediate threshold = 0 if this is never a valid state."
- PR #2382 (bobbinth): "Validation should happen in the constructor."
