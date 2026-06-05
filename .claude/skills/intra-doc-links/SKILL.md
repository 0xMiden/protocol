---
name: intra-doc-links
description: Use when writing or editing a Rust doc comment that references a type, method, or module — write the reference as an intra-doc link with brackets (`[TypeName]`) so renames produce rustdoc warnings.
---

# Use Intra-Doc Links in Rust Doc Comments

## Rule

When a doc comment mentions a type, method, trait, constant, or module that exists in scope, write it as an intra-doc link:

```rust
/// Returns the [`AccountId`] associated with this [`Account`].
///
/// See also [`AccountStorage::commitment`] for the storage commitment.
```

Use `[`Name`]` for items already in scope; use `[`Name`](crate::path::Name)` for items elsewhere; use `[`Name`]: ...` reference-style at the bottom for long paths.

Do not write type names as plain text or inside single backticks alone (e.g. `` `AccountId` `` without brackets) when the item is reachable from rustdoc.

## Why

Intra-doc links are checked by `rustdoc` (with `-D rustdoc::broken-intra-doc-links` or the project's lints). When you rename a type, every intra-doc link to it surfaces as a warning. Plain-text references go silently stale and accumulate over time.

Intra-doc links also render as clickable in the generated docs, which makes navigation much easier for readers.

## Examples

```rust
// Good
/// Returns the [`AccountId`] of this account.
///
/// # Errors
///
/// Returns [`AccountError::NotFound`] if the storage slot is empty.
pub fn account_id(&self) -> Result<AccountId, AccountError> { ... }

// Bad
/// Returns the `AccountId` of this account.
///
/// # Errors
///
/// Returns `AccountError::NotFound` if the storage slot is empty.
pub fn account_id(&self) -> Result<AccountId, AccountError> { ... }
```
