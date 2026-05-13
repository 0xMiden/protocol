---
name: parametrize-related-tests
description: Use when writing two or more tests that differ only by inputs or expected outputs (e.g. one per enum variant, one per "good/bad" input pair) — parameterize them with `rstest` cases instead of copy-pasting per-case test functions.
---

# Parameterize Repeated Tests with `rstest`

## Rule

When you'd write two or more test functions that share their body and differ only by inputs/expected values, write a single `#[rstest]` function with one `#[case]` per input set:

```rust
#[rstest]
#[case::happy("abc", true)]
#[case::empty("", false)]
#[case::too_long(LONG_INPUT, false)]
fn validate_name(#[case] input: &str, #[case] expected: bool) {
    assert_eq!(validate(input), expected);
}
```

This applies especially to "one test per enum variant" patterns and "one test per error condition" patterns.

## Why

Copy-pasted test bodies drift: a fix in one variant doesn't propagate to the others. `rstest` cases keep the assertion logic in one place, name each case in test output, and make it obvious from the test file that the coverage is complete (one case per variant).

Tests parameterized this way are also cheaper to extend: adding a new variant or input is a single `#[case]` line instead of a copy of the whole function.

## Examples

```rust
// Good
#[rstest]
#[case::fungible(Asset::Fungible(make_fungible()), AssetKind::Fungible)]
#[case::nft(Asset::Nft(make_nft()), AssetKind::Nft)]
fn asset_kind(#[case] asset: Asset, #[case] expected: AssetKind) {
    assert_eq!(asset.kind(), expected);
}

// Bad: two test functions duplicating the body
#[test]
fn asset_kind_fungible() { assert_eq!(Asset::Fungible(make_fungible()).kind(), AssetKind::Fungible); }
#[test]
fn asset_kind_nft() { assert_eq!(Asset::Nft(make_nft()).kind(), AssetKind::Nft); }
```

## Evidence

- PR #2849 (PhilippGackstatter): "Parametrize tests across all variants of an enum family rather than duplicating per-variant test boilerplate."
- PR #2439 (PhilippGackstatter): "Use rstest to dedupe these test functions."
- PR #2741 (bobbinth): "Could be expressed as rstest cases."
- PR #2390 (PhilippGackstatter): "These tests differ only by input — rstest case form."
- PR #2123 (PhilippGackstatter): "Fold into a single parameterized test."
