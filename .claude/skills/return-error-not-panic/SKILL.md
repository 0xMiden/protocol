---
name: return-error-not-panic
description: Use when writing a public Rust API, a deserialization path, or any code reachable from untrusted input — surface recoverable failures as a `Result`.
---

# Return Errors, Don't Panic on External Input

## Rule

Functions that touch external input — public API entry points, `Deserializable::read_from`, RPC handlers, advice-provider readers, parsing of user data — must surface failures as `Err`, not panics:

- No `unwrap()`, `expect()`, or `panic!` on values whose validity depends on external data.
- No `unwrap_or_default()` to silently substitute a fallback for invalid input.
- No `Option<T>` return type that hides the cause of failure when a real error is available.
- Missing required input is itself an error — don't substitute zero/empty/default and continue.

Convert any internal panic on external-derived values into a typed error variant.

### Two-tier API for the trusted case

When a no-check fast path is genuinely needed for callers operating on already-validated in-memory state, expose it as a separate constructor (e.g. `new_unchecked`, `from_parts_unchecked`) with a `# Safety` doc comment spelling out the caller's obligation. The default constructor stays fallible.

## Why

A panic on untrusted input is a denial-of-service vector and a debugging black hole, and `unwrap_or_default()` is worse — it fabricates a valid-looking value the caller never sent. A named `*_unchecked` entry point keeps the default path strict while forcing opt-in callers to acknowledge what they skip.

## Examples

```rust
// Good
pub fn parse_account_id(bytes: &[u8]) -> Result<AccountId, AccountError> {
    if bytes.len() != ACCOUNT_ID_LEN {
        return Err(AccountError::InvalidLength { expected: ACCOUNT_ID_LEN, got: bytes.len() });
    }
    AccountId::try_from(bytes)
}

// Bad: panics on bad input
pub fn parse_account_id(bytes: &[u8]) -> AccountId {
    AccountId::try_from(bytes).unwrap()
}

// Bad: silently substitutes a default
pub fn parse_account_id(bytes: &[u8]) -> AccountId {
    AccountId::try_from(bytes).unwrap_or_default()
}
```

Two-tier API when a trusted fast path is justified:

```rust
impl AccountId {
    /// Fallible default — validates the bytes.
    pub fn try_from_bytes(b: &[u8]) -> Result<Self, AccountError> { /* ... */ }

    /// # Safety
    /// Caller must guarantee `b` came from a previously validated source
    /// (e.g. a value already constructed via `try_from_bytes`).
    pub fn from_bytes_unchecked(b: &[u8]) -> Self { /* ... */ }
}
```

For the MASM analog (validating against a commitment, content-addressed advice keys, erroring on missing advice), see `advice-provider-hygiene`.
