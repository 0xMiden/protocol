---
name: use-test-fixtures
description: Use when a Rust or MASM test needs to construct an account, note, transaction, or other domain object — build it with the existing test fixtures.
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

Shared fixtures encode the domain's validation rules, so a fixture-built object has the right bits and survives serialization; a hand-rolled `dummy()` usually doesn't, letting tests pass against invariants the real code never enforces. Reusing fixtures also lets one upgrade propagate to every test.

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
