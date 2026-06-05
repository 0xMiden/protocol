---
name: conversion-method-naming
description: Use when naming a conversion or accessor method in Rust — follow the API guideline prefixes (`as_` for free borrows, `to_` for expensive conversions, `into_` for ownership transfers, `from_` for type-associated constructors).
---

# Rust Conversion Method Naming

## Rule

Pick the prefix that matches the cost and ownership of the conversion:

- `as_<type>` — free or near-free, returns a borrow (e.g. `as_bytes() -> &[u8]`).
- `to_<type>` — non-trivial cost, returns an owned value, leaves `self` intact (e.g. `to_string() -> String`).
- `into_<type>` — consumes `self`, returns the inner/converted value.
- `from_<type>` — associated function on the target type that constructs it.
- `with_<field>` — *only* for builder-style methods that take and return `Self` with a field set.

Do not name a non-borrowing method `as_*`. Do not name a non-builder method `with_*`. Do not use `to_*` for a free borrow.

## Why

The conventions come from the Rust API guidelines and are deeply baked into the standard library and the wider ecosystem. A reader expects `as_x` to be cheap, `to_x` to allocate, `into_x` to consume — violating that costs every reader a moment of confusion and trains them to distrust the rest of the API.

`with_*` is especially load-bearing: when readers see `foo.with_bar(b)`, they expect `foo` back with `bar` set. Naming an unrelated method `with_` derails that intuition.

## Examples

```rust
// Good
impl Header {
    pub fn as_bytes(&self) -> &[u8] { ... }              // cheap borrow
    pub fn to_vec(&self) -> Vec<u8> { ... }              // allocates
    pub fn into_payload(self) -> Payload { self.payload } // consumes
}

impl HeaderBuilder {
    pub fn with_version(mut self, v: u8) -> Self { self.version = v; self }
}

// Bad
impl Header {
    pub fn as_vec(&self) -> Vec<u8> { ... }  // allocates, should be to_vec
    pub fn to_bytes(&self) -> &[u8] { ... }  // borrow, should be as_bytes
}

// Bad: with_* on a non-builder method
fn with_seed(rng: &mut Rng, seed: u64) { ... }   // not returning Self
```
