---
name: workspace-shared-dependencies
description: Use when adding or modifying a dependency entry in a crate's `Cargo.toml` — if the dependency is used by more than one crate in the workspace, declare it once in the workspace root `[workspace.dependencies]` and reference it from each crate with `dep = { workspace = true }`.
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

Workspace-level declarations are the single source of truth for shared versions. Without them, every crate pins its own version, which inevitably drifts — two crates ending up on different minor versions, cargo resolving a duplicate dependency graph, larger compile times, and version-mismatch bugs.

Promoting on second use (rather than upfront) keeps the workspace table from accumulating one-off entries.

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
