---
name: private-fields-with-accessors
description: Use when adding a public struct or changing a struct field's visibility in a Rust library crate — keep fields private and expose them through accessor methods so the layout can evolve without breaking callers.
---

# Keep Struct Fields Private; Expose Accessors

## Rule

Public structs in library crates have private fields. Read access goes through an `pub fn field(&self) -> &T` accessor; mutation goes through dedicated methods (no `pub fn field_mut`).

Exceptions:

- "Open" data types whose layout is part of the contract (e.g. `Point { x, y }`) may have public fields, but they should be `#[non_exhaustive]`.
- Internal/`pub(crate)` types may have public fields when keeping them private adds no value.

## Why

Public fields freeze the struct's representation. You cannot rename, retype, split, or compute-on-read a public field without breaking every caller. Accessor methods let the type evolve internally — a `pub fn supply(&self) -> u64` can become a computed expression next release without anyone noticing.

## Examples

```rust
// Good
pub struct FungibleTokenMetadata {
    name: Box<str>,
    supply: u64,
}

impl FungibleTokenMetadata {
    pub fn name(&self) -> &str { &self.name }
    pub fn supply(&self) -> u64 { self.supply }
}

// Bad: every consumer locked to these field names and types forever
pub struct FungibleTokenMetadata {
    pub name: String,
    pub supply: u64,
}
```

## Evidence

- PR #2439 (PhilippGackstatter): "Keep fields of public structs private to preserve the ability to extend them non-breakingly after release."
- PR #2670 (PhilippGackstatter): "Make these fields private and add accessors."
- PR #2712 (PhilippGackstatter): "This field should be private."
- PR #1934 (bobbinth): "We should not expose these fields directly."
