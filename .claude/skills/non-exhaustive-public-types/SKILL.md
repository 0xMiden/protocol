---
name: non-exhaustive-public-types
description: Use when defining a new public `enum` or `struct` in a library crate that may grow new variants/fields in future releases — mark it `#[non_exhaustive]` so adding variants is not a breaking change.
---

# Mark Public Types `#[non_exhaustive]`

## Rule

Public enums and public-fielded structs in library crates whose variants/fields are expected to grow should be marked `#[non_exhaustive]`:

```rust
#[non_exhaustive]
pub enum AssetKind { Fungible, NonFungible }

#[non_exhaustive]
pub struct Header {
    pub version: u8,
    pub flags: u32,
}
```

This forces external code to use a wildcard match arm (or default field syntax) and lets the library add new variants/fields in a minor release without breaking downstreams.

Don't mark types `#[non_exhaustive]` when the closed set is part of the contract (e.g. a primitive-like wrapper, a fixed protocol enum that must match a spec).

## Why

In a downstream crate, an exhaustive match on a non-`#[non_exhaustive]` enum compiles successfully — but a future minor release that adds a variant breaks every such match. `#[non_exhaustive]` makes the wildcard arm mandatory and shifts variant-additions from breaking to non-breaking.

The same applies to public-fielded structs: without `#[non_exhaustive]`, every `Header { version, flags }` literal must list every field, and adding a field is a breaking change.

## Examples

```rust
// Good
#[non_exhaustive]
pub enum AccountStorageMode {
    Public,
    Private,
}

// Internal callers still match exhaustively (in-crate exhaustiveness is allowed)
match mode {
    AccountStorageMode::Public => ...,
    AccountStorageMode::Private => ...,
}

// External callers are forced to a wildcard
match mode {
    AccountStorageMode::Public => ...,
    AccountStorageMode::Private => ...,
    _ => ...,   // adding a variant in a minor release: compiles
}

// Bad: closed public enum, additions are breaking
pub enum AccountStorageMode {
    Public,
    Private,
}
```

## Evidence

- PR #2712 (PhilippGackstatter): "Public enums in library APIs should be marked non_exhaustive when new variants are anticipated."
- PR #1924 (PhilippGackstatter): "Mark this `#[non_exhaustive]`."
- PR #1713 (PhilippGackstatter): "We anticipate more variants — make it non_exhaustive."
- PR #1721 (bobbinth): "Public struct, add non_exhaustive."
