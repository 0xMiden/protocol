---
name: preserve-error-source
description: Use when defining a new error variant or wrapping a lower-level error — keep the underlying error's source chain intact.
---

# Preserve Error Source Chains

## Rule

When a new error wraps a lower-level error, preserve the source so the chain remains traversable:

- Use `thiserror`'s `#[source]` attribute (or `#[from]`) to attach the underlying error.
- For dynamic sources, `Box<dyn Error + Send + Sync + 'static>`.
- Do not call `.to_string()` on the source and embed it into the wrapper's message — that breaks `Error::source()` traversal and destroys structured information.

## Why

Tools like anyhow, tracing, and logging walk `Error::source()` to render full chains and group by root cause. Stringifying the source into the message flattens it to one opaque string — the chain can't be walked and the inner error's fields are gone.

## Examples

```rust
// Good
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("failed to deserialize account storage")]
    StorageDeser(#[source] DeserializationError),

    #[error("failed to load account from {path}")]
    Load { path: PathBuf, #[source] io: io::Error },
}

// Bad: source is stringified, chain is lost
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("failed to deserialize account storage: {0}")]
    StorageDeser(String),
}

// Bad: source baked into the message via format!
return Err(AccountError::StorageDeser(format!("{e}")));
```
