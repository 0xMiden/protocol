---
name: private-fields-with-accessors
description: Use when adding a public struct or changing a field's visibility in a Rust library crate — keep fields encapsulated so the layout can evolve without breaking callers.
---

# Keep Struct Fields Private; Expose Accessors

## Rule

Public structs in library crates have private fields. Read access goes through an `pub fn field(&self) -> &T` accessor; mutation goes through dedicated methods (no `pub fn field_mut`).

Exceptions:

- "Open" data types whose layout is part of the contract (e.g. `Point { x, y }`) may have public fields, but they should be `#[non_exhaustive]`.
- Internal/`pub(crate)` types may have public fields when keeping them private adds no value.

## Why

Public fields freeze the representation: you can't rename, retype, split, or compute-on-read them without breaking every caller. An accessor lets a field become a computed expression in a later release with no one noticing.

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
