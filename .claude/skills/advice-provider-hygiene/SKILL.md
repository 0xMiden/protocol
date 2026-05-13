---
name: advice-provider-hygiene
description: Use when writing kernel, account, or note MASM code that reads from or writes to the advice provider (advice stack / advice map) — key entries by content hash, validate every piece of advice data against a commitment the kernel already trusts, and treat missing required entries as errors rather than silent zeros.
---

# Advice Provider Hygiene

## Rules

The advice provider is untrusted input supplied by the (potentially adversarial) prover. Any kernel, account, or note procedure that touches it must follow three rules.

### 1. Validate advice data against a commitment

Before consuming data loaded from the advice provider:

1. Read the data from the advice stack / advice map into memory.
2. Compute its hash with the appropriate hasher (typically `Rpo256` over the loaded region).
3. Assert the computed hash equals an expected commitment that the kernel already trusts — on-chain storage, a prior input, or a value already on the stack.

Do not consume advice data before this check passes. The advice provider's only role is to supply witness data for commitments the kernel has already received.

### 2. Key advice map entries by content hash

When inserting into the advice map, the key must be a hash of the value it indexes (or a derived commitment of the same data):

- Use `Rpo256(value)` (or whichever hash matches the consumer's check) as the key.
- Do not hard-code keys like `0x0000_0000_0000_0001`, `ADVICE_KEY_NOTE_DATA`, or per-procedure magic constants.

Readers retrieve the entry by recomputing the same hash from data they already trust; rule 1's commitment check binds the lookup result to that trusted hash.

### 3. Missing advice is an error

A missing advice-map entry, an empty advice stack, or an absent required value is an error — not a default. Surface it with `assert.err=ERR_...`. Don't substitute zero / empty / a fallback and continue.

## Why

The advice provider is filled by the prover, who is potentially adversarial. Each of the three rules closes a different attack:

- Without commitment validation, a malicious prover injects any data and the kernel runs against it.
- Without content-addressed keys, two procedures (or one procedure plus an adversarial write) can silently collide on the same key in the global per-transaction namespace.
- Without erroring on missing data, the prover skips inputs the kernel would have used to enforce a check; the kernel runs to completion against zeros and produces a "proof" that doesn't actually witness the intended property.

Content addressing makes collisions cryptographically negligible. The load/hash/assert pattern binds untrusted advice to trusted state. Treating absence as an error preserves the kernel's invariants under adversarial input.

The pattern is universal in the kernel and account procedures: **load → hash → assert against commitment → use**, with content-addressed keys throughout and `assert.err=...` on absence.

## Examples

```masm
# Good: load → hash → check commitment → use
adv_pipe                                # load advice into memory at the pointer
exec.hash_data                          # compute hash of the loaded region
push.EXPECTED_COMMITMENT
assert_eqw.err=ERR_COMMITMENT_MISMATCH
# ... safe to use the data here

# Good: content-addressed advice map insert
push.NOTE_DATA_COMMITMENT
adv.push_mapval                         # key is the commitment itself

# Good: missing entry is an error
adv.has_mapkey
assert.err=ERR_MISSING_REQUIRED_ADVICE

# Bad: consume advice data without validating it
adv_pipe
exec.consume_data                       # data could be anything the prover wants

# Bad: hard-coded magic key
push.0x1234_5678_0000_0001
adv.push_mapval

# Bad: silent zero on missing key
adv.push_mapval                         # no-op if key absent; proceed as if zero
```

For the Rust analog (returning `Err` on bad/missing external input rather than panicking or defaulting), see `return-error-not-panic`.

## Evidence

- PR #1648 (bobbinth): "Verify that data received from the advice provider matches an expected hash to prevent malicious injection." / "Validate the advice data against the on-chain commitment before using it."
- PR #1871 (bobbinth): "Avoid hard-coded advice-map keys; the advice map is a global per-transaction namespace and predictable keys risk collisions." / "The advice data must be checked against the on-chain commitment."
- PR #1896 (PhilippGackstatter): "Use the data commitment as the key rather than a fixed constant." / "Don't silently treat missing data as zero."
- PR #1995 (PhilippGackstatter): "Add a commitment check after the advice pipe." / "Absent advice key must produce a typed error."
- PR #1360 (bobbinth): "Advice map keys should be the hash of the underlying data they index."
- PR #2439 (PhilippGackstatter): "When piping advice data into memory, validate that the supplied hash matches the data rather than blindly inserting from the advice provider."
