---
name: advice-provider-hygiene
description: Use when writing kernel, account, or note MASM code that reads from or writes to the advice provider (advice stack / advice map) — validate advice data.
---

# Advice Provider Hygiene

## Rules

The advice provider is untrusted input supplied by the (potentially adversarial) prover. Any kernel, account, or note procedure that touches it must follow three rules.

### 1. Validate advice data against a commitment

Before consuming data loaded from the advice provider:

1. Read the data from the advice stack / advice map into memory.
2. Compute its hash with Poseidon2 over the loaded region.
3. Assert the computed hash equals an expected commitment that the kernel already trusts — on-chain storage, a prior input, or a value already on the stack.

Do not consume advice data before this check passes. The advice provider's only role is to supply witness data for commitments the kernel has already received.

### 2. Key advice map entries by content hash

When inserting into the advice map, the key must be a hash of the value it indexes (or a derived commitment of the same data):

- Use `Poseidon2(value)` (or whichever commitment matches the consumer's check) as the key.
- Do not hard-code keys like `0x0000_0000_0000_0001`, `ADVICE_KEY_NOTE_DATA`, or per-procedure magic constants.

Readers retrieve the entry by recomputing the same hash from data they already trust; rule 1's commitment check binds the lookup result to that trusted hash.

### 3. Missing advice is an error

A missing advice-map entry, an empty advice stack, or an absent required value is an error — not a default. Surface it with `assert.err=ERR_...`. Don't substitute zero / empty / a fallback and continue.

## Why

The advice provider is filled by a potentially adversarial prover. Validating every value against a commitment the kernel already trusts, keying map entries by content hash, and erroring on missing entries are what stop untrusted advice from silently corrupting the kernel's invariants.

## Examples

Advice data is tied to a commitment by piping it into memory. There are two mechanisms, and they differ in whether the commitment check happens for you.

### Piping words to memory — you must validate

`adv_pipe`, `adv_loadw`, and `mem::pipe_double_words_to_memory` copy advice data into memory but do *not* check it against any commitment. Hash the loaded region with Poseidon2 yourself and assert it equals a commitment the kernel already trusts.

```masm
# Good: pipe words while hashing, then assert against the trusted commitment
# (permute rounds abbreviated; the real path pipes the full region before squeezing)
exec.poseidon2::init_no_padding
adv_pipe exec.poseidon2::permute
# ... one permute per piped block ...
exec.poseidon2::squeeze_digest
# => [COMPUTED_COMMITMENT, ...]
exec.memory::get_block_commitment
assert_eqw.err=ERR_PROLOGUE_GLOBAL_INPUTS_PROVIDED_DO_NOT_MATCH_BLOCK_COMMITMENT

# Good: pipe double words while hashing, then assert against the provided commitment
exec.poseidon2::init_no_padding
exec.mem::pipe_double_words_to_memory
exec.poseidon2::squeeze_digest
# => [COMPUTED_ASSETS_COMMITMENT, ...]
exec.memory::get_input_note_assets_commitment
assert_eqw.err=ERR_PROLOGUE_PROVIDED_INPUT_ASSETS_INFO_DOES_NOT_MATCH_ITS_COMMITMENT

# Bad: pipe advice into memory and use it without the hash/assert step
adv_pipe
# ... data could be anything the prover supplied
```

### Piping a preimage to memory — validated for you

`mem::pipe_preimage_to_memory` takes the commitment on the stack, copies the preimage from the advice stack into memory, and asserts its sequential Poseidon2 hash equals that commitment — all in one step.

```masm
# Good: data is checked against COMMITMENT as part of the pipe
# stack: [num_words, write_ptr, COMMITMENT]
exec.mem::pipe_preimage_to_memory
# => [write_ptr'] — data in memory is guaranteed to match COMMITMENT
```

### Content-addressed keys and missing entries

```masm
# Good: key the advice map entry by the commitment itself
push.NOTE_DATA_COMMITMENT
adv.push_mapval

# Bad: hard-coded magic key
push.0x1234_5678_0000_0001
adv.push_mapval

# Good: a missing required entry is an error
adv.has_mapkey
assert.err=ERR_MISSING_REQUIRED_ADVICE

# Bad: silent zero on missing key
adv.push_mapval                         # no-op if key absent; proceed as if zero
```

For the Rust analog (returning `Err` on bad/missing external input rather than panicking or defaulting), see `return-error-not-panic`.
