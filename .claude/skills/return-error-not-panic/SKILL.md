---
name: return-error-not-panic
description: Use when writing a public Rust API function, a deserialization path, or any code reachable from external/untrusted input — return a `Result` for recoverable failures (never panic/unwrap/silent-default), and when a genuinely-trusted fast path is needed, expose it as a separate `_unchecked` entry point rather than weakening the default.
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

A panic on untrusted input is a denial-of-service vector and a debugging black hole. `unwrap_or_default()` is worse: the function silently produces a value that "looks valid" but represents data the caller never sent, and the bug surfaces far from the actual error.

Silently defaulting on missing input is particularly dangerous in kernel-adjacent code: a malicious prover (or buggy upstream) can skip data the kernel would have used to enforce a check; the kernel runs to completion against zeros and produces a "proof" that doesn't actually witness the property the user wanted.

Splitting the trusted entry point out by name (`*_unchecked`) keeps the default path strict while still giving performance-sensitive callers an explicit opt-out — and the name forces them to acknowledge what they're skipping.

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

## Evidence

- PR #2439 (PhilippGackstatter): "Return errors rather than silently swallowing them with Option or defaults in conversion logic."
- PR #2246 (bobbinth): "Treat missing required data as an error rather than silently defaulting or skipping."
- PR #2123 (PhilippGackstatter): "Don't unwrap on deserialized data."
- PR #2006 (PhilippGackstatter): "Deserialization constructors must treat input as untrusted; provide a separate trusted constructor for in-memory use."
- PR #1934 (PhilippGackstatter): "Surface this as a Result variant; users could trigger it."
- PR #1995 (PhilippGackstatter): "Absent advice key must produce a typed error."
- PR #1531 (bobbinth): "Replace this panic with a typed error."
