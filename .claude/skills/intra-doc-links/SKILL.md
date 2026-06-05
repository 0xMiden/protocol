---
name: intra-doc-links
description: Use when writing or editing a Rust doc comment that references a type, method, or module — link the reference so renames are caught by rustdoc.
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

Intra-doc links are checked by rustdoc, so renaming a linked item produces a warning while plain-text references silently go stale. They also render as clickable navigation in the generated docs.

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
