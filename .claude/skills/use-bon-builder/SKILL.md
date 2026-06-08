---
name: use-bon-builder
description: Use when introducing a Rust type whose constructor takes more than ~3 optional or named parameters — give it a generated builder instead of hand-written boilerplate.
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

Hand-written builders are boilerplate that drifts — add a struct field, forget to set it in the builder, and the bug surfaces later. `bon` derives the builder from the constructor signature so the two can't diverge, and enforces required fields at compile time.

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
