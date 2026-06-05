---
name: non-exhaustive-public-types
description: Use when defining a public `enum` or `struct` in a library crate that may gain variants or fields later — keep future additions from being breaking changes.
---

# Mark Public Types `#[non_exhaustive]`

## Rule

Public enums and public-fielded structs in library crates whose variants/fields are expected to grow should be marked `#[non_exhaustive]`:

```rust
#[non_exhaustive]
pub enum Authority {
    AuthControlled,
    OwnerControlled,
    RbacControlled { role: RoleSymbol },
}

#[non_exhaustive]
pub struct Header {
    pub version: u8,
    pub flags: u32,
}
```

This forces external code to use a wildcard match arm (or default field syntax) and lets the library add new variants/fields in a minor release without breaking downstreams.

Don't mark types `#[non_exhaustive]` when the closed set is part of the contract — e.g. `NoteType`, a protocol-level enum fixed by the spec and serialized with a fixed-width discriminant, where adding a variant is a breaking protocol change anyway.

## Why

Without `#[non_exhaustive]`, a downstream exhaustive `match` or struct literal compiles today but breaks the moment a minor release adds a variant or field. The attribute makes the wildcard arm mandatory, turning those additions from breaking to non-breaking.

## Examples

```rust
// Good: a standards-level enum that is expected to gain variants over time
#[non_exhaustive]
pub enum TransferPolicy {
    AllowAll,
    Blocklist,
    Allowlist { allow_list: AllowlistStorage },
    Custom(AccountProcedureRoot),
}

// External callers are forced to include a wildcard, so a future variant
// (e.g. a time-locked or volume-limited policy) stays non-breaking:
match policy {
    TransferPolicy::AllowAll => ...,
    TransferPolicy::Blocklist => ...,
    TransferPolicy::Allowlist { .. } => ...,
    TransferPolicy::Custom(_) => ...,
    _ => ...,   // adding a variant in a minor release: still compiles
}

// Bad: closed public enum, so any new transfer policy is a breaking change
pub enum TransferPolicy {
    AllowAll,
    Blocklist,
    Allowlist { allow_list: AllowlistStorage },
    Custom(AccountProcedureRoot),
}
```
