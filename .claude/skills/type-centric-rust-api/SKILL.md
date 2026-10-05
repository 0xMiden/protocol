---
name: type-centric-rust-api
description: Use when adding a public Rust function, or adding a new case or check to an existing flow (a new note type, enum variant, validation rule) - put the behavior on the type that owns it and reshape the flow, instead of adding a free function or one more special case.
---

# Type-Centric Rust API

## Rule

Behavior lives on the type it belongs to. Public API is a method or associated function on a type, about 98% of the time. Free functions are for private helpers.

When a new requirement arrives, reshape the existing structure so that it fits the requirement:

1. Find the home type. The home of a rule is the type whose data the rule reads, in the crate that owns that type (and the MASM the rule mirrors). The type owns the rule:
   - A rule about the type's own data is an invariant. The constructor enforces it (see `validate-in-constructor`) and every mutating method upholds it, so holding a value proves the rule.
   - A rule that also needs outside context (the consuming account, the current block) is a method that takes that context as parameters.
2. Find the existing decision point. If a `match` or loop already classifies the input, add the new case as an arm of it. Each input is classified and parsed in one place.
3. Hold shared context in a type. When several functions take the same parameters (`account_id`, `block_ref`, `fee_asset_id`), make a struct that holds them and has the operations as methods.
4. Put each operation at its level. A function that returns many `T`s, or needs context that one `T` does not have, belongs on a higher-level type, not on `T`.
5. Delete what the new structure replaces: the follow-up pass, the special-case block, the second parse, the `expect` on a shape that only the old pass knew.

Each caller maps the result of the shared method to its own output type (a status enum, a failure record). The rule itself stays in one place.

Signs that the structure needs reshaping:

- A function derives again a classification that an earlier step already made (it parses every note again, or infers "head vs. bound note" from the position in a `Vec`).
- A `_ => None` arm for a variant, followed by a special-case block for the same variant after the `match`.
- A free function whose first parameter is a type from another crate. The function belongs on that type, in that crate.
- Three or more functions pass along the same parameter list.

## Why

A rule with one home is one place to change and one place to review. Each special case added next to an existing structure repeats part of the decision that the structure already makes. The copies drift apart, and a reader must find all of them to know the real behavior. A method is found through its type (IDE completion, rustdoc). A free function is found only if you already know its name.

## Example

The note consumption checker had to reject FEE_SPONSORSHIP notes that the account cannot consume.

```rust
// Bad: free functions and special cases next to the existing structure.

// miden-tx: a second pass parses every note again, after `NoteBundle::group` already did,
// and infers from the bundle layout what `group` already knew.
pub(super) fn reject_unconsumable_sponsorships(
    bundles: &[NoteBundle],
    native_account_id: AccountId,
    block_ref: BlockNumber,
    collected_fee_asset_id: Option<AssetId>,
) -> Vec<FailedNote> {
    for bundle in bundles {
        let (head, bound_notes) = bundle.notes().split_first().expect("...");
        // ...
    }
}

// miden-tx: the reclaim rule mirrors MASM in miden-standards, but lives in another crate.
fn reject_orphan_sponsorship(sponsorship: &FeeSponsorshipNote, /* ... */) -> Option<SponsorshipRejection>;

// can_consume: `StandardNote::is_consumable` returns `None` for FEE_SPONSORSHIP,
// then one more special case follows.
if let Some(status) = sponsorship_consumption_status(note, target_account_id, block_ref) {
    return Ok(status);
}
```

```rust
// Good: the structure is reshaped.

// miden-standards: the reclaim rule is on the note type, next to the MASM it mirrors.
impl FeeSponsorshipNote {
    pub fn check_reclaim(&self, account_id: AccountId, block_ref: BlockNumber) -> Result<(), ReclaimError>;
}

// miden-standards: FEE_SPONSORSHIP is one more arm of the existing match.
StandardNote::FEE_SPONSORSHIP => {
    match FeeSponsorshipNote::try_from(note)?.check_reclaim(target_account_id, block_ref) {
        Ok(()) => Ok(Some(NoteConsumptionStatus::ConsumableWithAuthorization)),
        // ...
    }
},

// miden-tx: the context is a type. The loop that already classifies each note also rejects it.
// `bundle` moved off `NoteBundle` because it returns many bundles.
struct NoteBundler {
    native_account_id: AccountId,
    block_ref: BlockNumber,
    collected_fee_asset_id: Option<AssetId>,
}

impl NoteBundler {
    fn bundle(&self, notes: &[Note]) -> (Vec<NoteBundle>, Vec<FailedNote>) {
        // ...
        match (sponsorship, feature_idx) {
            (Some(sponsorship), None) => match sponsorship.check_reclaim(self.native_account_id, self.block_ref) {
                // ...
            },
            // ...
        }
    }
}
```
