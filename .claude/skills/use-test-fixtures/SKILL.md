---
name: use-test-fixtures
description: Use when a Rust or MASM test needs to construct an account, note, transaction, or other domain object — use the existing fixture builder (`NoteBuilder`, `ScriptBuilder`, `AccountIdBuilder`, `rand_value()`).
---

# Use Existing Test Fixtures, Don't Hand-Roll

## Rule

When a test needs a domain object, reach for the existing fixture infrastructure:

- Notes: `NoteBuilder`.
- Scripts: `ScriptBuilder`.
- Account IDs: `AccountIdBuilder` (or the existing `ACCOUNT_ID_*` constants).
- Random felts/words: `rand_value()` (deterministic seed-driven RNG).
- Accounts: `AccountBuilder` with the `testing` feature.

Don't write a new `AccountId::dummy(...)`, `Note::test_only(...)`, or one-off random helper. If the existing fixtures can't express what you need, extend them — don't fork.

## Why

Shared fixtures encode the domain's validation rules and keep tests honest: an `AccountIdBuilder`-built ID has the right tag bits, the right storage-mode bits, and survives a round-trip through serialization. A hand-rolled `dummy()` typically doesn't, which means tests pass against invariants the real code doesn't enforce — or fail randomly on the few invariants that do leak through.

Reusing fixtures also keeps tests short and lets a single fixture upgrade (e.g. adding a new required field to `Note`) propagate to every test via a single edit.

## Examples

```rust
// Good
let note = NoteBuilder::new()
    .recipient(test_recipient())
    .with_asset(rand_value())
    .build()?;

let account_id = AccountIdBuilder::new().build();

// Bad
let note = Note {
    metadata: NoteMetadata::default(),
    inputs: NoteInputs::default(),
    assets: NoteAssets::default(),
    recipient: NoteRecipient::dummy(),
};

let account_id = AccountId::try_from(Word::default()).unwrap();
```
