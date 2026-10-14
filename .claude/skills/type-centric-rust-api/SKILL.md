---
name: type-centric-rust-api
description: Use when adding a public Rust function, or adding a new case or check to an existing flow (a new note type, enum variant, validation rule) - put the behavior on the type that owns it and reshape the flow, instead of adding a free function or one more special case.
---

# Type-Centric Rust API

## Rule

Behavior lives on the type whose data it reads. Public behavior is a method (with a `self`, `&self` or `&mut self` receiver) on that type. Use a free function only when no single type owns the behavior, for example a private helper or when a type would only be introduced to hold the function as a method.

When a new requirement arrives, reshape the existing structure so that it fits the requirement:

1. Find the home type. The home type of a rule is the type whose data the rule reads. Put the rule in the crate that defines that type, next to the MASM that the rule mirrors (if there is one). The type owns the rule:
   - A rule about the type's own data is an invariant. The constructor enforces it (see `validate-in-constructor`) and every mutating method upholds it, so holding a value proves the rule.
   - A rule that also needs outside context (the consuming account, the current block) is a method that takes that context as parameters.
2. Find the existing decision point. This is the `match` or loop that already classifies the input, for example the `match` on the `StandardNote` variants. Add the new case as an arm or branch of it, not as a new pass before or after it. Parse and classify each input only one time.
3. Hold shared context in a type. When three or more functions take the same parameters (`account_id`, `block_ref`, `fee_asset_id`), make a struct that holds them and has the operations as methods.
4. Put each operation on the type it operates on. A method on `T` operates on one `T` value. A function that builds a collection of `T` (for example a `Vec<T>` from a slice of inputs), does not belong on `T`. Put it on the type that holds that input or context, for example the context struct from step 3.
5. Delete what the new structure replaces: the follow-up pass, the special-case block, the second parse, and each `expect` that relies on a shape that only the old pass guaranteed.

Each caller maps the result of the shared method to its own output type (a status enum, a failure record). The rule itself stays in one place.

Signs that the structure needs reshaping:

- A function classifies its input again after an earlier step already did (it parses every note again, or infers "head vs. bound note" from the position in a `Vec`).
- A `match` returns `None` for a variant (often through `_ => None`), and a special-case block after the `match` handles the same variant.
- A free function takes a type from another crate as its first parameter. The function belongs on that type, in that crate.
- An associated function without a receiver does not construct `Self`, for example `NoteBundle::group(&[Note]) -> Vec<NoteBundle>`.
- Three or more functions take the same parameter list.

## Why

A rule with one home is one place to change and one place to review. Each special case added next to an existing structure repeats part of the decision that the structure already makes. The copies drift apart, and a reader must find all of them to know the real behavior. A method is found through its type (IDE completion, rustdoc). A free function is found only if you already know its name.

## Examples

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
// `NoteBundle::group` became `NoteBundler::bundle`, because it builds a `Vec<NoteBundle>`, not one bundle.
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
