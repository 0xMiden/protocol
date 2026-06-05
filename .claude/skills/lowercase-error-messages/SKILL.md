---
name: lowercase-error-messages
description: Use when writing or editing a Rust error message, panic message, assertion string, or MASM `ERR_*` constant value — start with a lowercase letter and end without trailing punctuation, unless the first word is a proper noun.
---

# Lowercase Error Messages, No Trailing Punctuation

## Rule

Error messages (in `Error` enum `#[error("...")]` attributes, `panic!`, `assert!` messages, MASM `ERR_*` constant strings) follow Rust's convention:

- Start with a lowercase letter (unless beginning with a proper noun or acronym).
- No trailing period, exclamation, or other punctuation.
- Imperative or descriptive, not "ERROR: ..." or "Failed to ...".

Examples of correct shape: `"invalid account id length"`, `"note not found"`, `"failed to deserialize storage"`.

## Why

Error messages get composed into chains (`Display`/`source`) and into anyhow contexts. A trailing period or a capital letter mid-chain ("X failed: Y failed: Z failed.") makes the chain read like a sequence of unrelated sentences instead of a single error. Lowercase-and-no-punctuation is the convention `std::io::Error`, `thiserror`, and most ecosystem crates already follow.

## Examples

```rust
// Good
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("invalid account id length, expected {expected} bytes, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("account not found")]
    NotFound,
}

// Bad
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("Invalid account id length: expected {expected} bytes, got {got}.")]
    InvalidLength { ... },
    #[error("Account not found!")]
    NotFound,
}
```

```masm
# Good
const ERR_NOTE_NOT_FOUND = "note not found"

# Bad
const ERR_NOTE_NOT_FOUND = "Note not found!"
```
