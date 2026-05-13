---
name: use-bon-builder
description: Use when introducing a Rust type whose constructor takes more than ~3 optional or named parameters — derive a builder with `#[bon::builder]` instead of hand-writing a separate Builder module or adding overloaded constructors.
---

# Use `bon` for Builders With Many Optional Fields

## Rule

When a type's constructor has many optional or named parameters, derive its builder with `#[bon::builder]`:

```rust
#[bon::builder]
pub fn new(
    required: Foo,
    #[builder(default)] optional: Option<Bar>,
    #[builder(into)] name: String,
) -> Self { ... }
```

Don't hand-write a separate `FooBuilder` module just to expose a fluent API. Don't add a constellation of `new`, `new_with_x`, `new_with_x_and_y` constructors.

`bon` handles compile-time required-field enforcement, optional defaults, and `impl Into<T>` parameters for free.

## Why

Hand-written builders are repetitive boilerplate that drifts over time: a new field gets added to the struct, the builder forgets to set it, and the bug surfaces on the next refactor. `bon` derives the builder from the constructor signature, so the two cannot diverge.

`bon` also enforces required-field-set at compile time (calling `.build()` without setting a required field is a type error), which most hand-written builders skip.

## Examples

```rust
// Good
#[bon::builder]
impl Account {
    pub fn new(
        id: AccountId,
        #[builder(default)] storage: AccountStorage,
        #[builder(into)] code: AccountCode,
    ) -> Self { ... }
}

let acc = Account::builder()
    .id(my_id)
    .code(my_code)
    .build();

// Bad: bespoke builder module that drifts
pub struct AccountBuilder { id: Option<AccountId>, storage: Option<AccountStorage>, ... }
impl AccountBuilder { ... 80 lines ... }
```

## Evidence

- PR #2890 (PhilippGackstatter): "Replace hand-written builder modules with `#[bon::builder]` when the builder has many optional fields."
- PR #2636 (PhilippGackstatter): "Use bon here instead of the custom builder."
- PR #2439 (PhilippGackstatter): "This is a perfect case for `#[bon::builder]`."
- PR #1713 (PhilippGackstatter): "bon would replace this boilerplate."
