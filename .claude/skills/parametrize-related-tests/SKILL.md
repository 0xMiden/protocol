---
name: parametrize-related-tests
description: Use when writing two or more tests that differ only by inputs or expected outputs — collapse the duplication into parameterized cases.
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

Copy-pasted test bodies drift — a fix in one case doesn't reach the others. Parameterized cases keep the assertion in one place, name each case in the output, and make a missing case obvious; adding one is a single line.

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
