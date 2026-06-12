---
name: workspace-shared-dependencies
description: Use when adding or modifying a dependency in a crate's `Cargo.toml` that is or may become shared by multiple workspace crates — keep its version defined in one place.
---

# Workspace-Level Shared Dependencies

## Rule

When adding a dependency that another crate in the workspace already uses (or that you anticipate adding to another crate), declare it once in the root `Cargo.toml`'s `[workspace.dependencies]` table. In each crate that uses it, write:

```toml
[dependencies]
serde = { workspace = true }
```

Don't duplicate version strings across crates. Don't keep a dependency crate-local once a second crate adopts it — promote it to the workspace.

For dependencies used in only one crate, keep them crate-local. Promote when a second crate starts using them.

## Why

A workspace declaration is the single source of truth for a shared version. Without it, each crate pins its own, versions drift, cargo resolves duplicates, and compile times grow.

## Examples

```toml
# Good (workspace root)
[workspace.dependencies]
serde = "1.0"
thiserror = "1.0"

# Good (crate)
[dependencies]
serde = { workspace = true, features = ["derive"] }
thiserror = { workspace = true }
```

```toml
# Bad: two crates pinning the same dep at potentially different versions
# crates/foo/Cargo.toml
[dependencies]
serde = "1.0"

# crates/bar/Cargo.toml
[dependencies]
serde = "1.0.130"
```
