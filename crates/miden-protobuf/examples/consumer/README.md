# Protobuf Consumer

A standalone `no_std` consumer showing build configuration, generated decoding, and error paths.

- `build.rs` defines a small schema and configures decoding before generating Prost types.
- `src/lib.rs` uses those types and demonstrates record, oneof, and payload decoding in tests.

Decoded collections retain named `OptionalField`, `RepeatedField`, and `MapField` wrappers.
Borrow their contents with `as_ref()` or `as_slice()`, call `verify()` when their elements
implement `Verify`, or use `into_inner()` for custom processing. Decoding does not verify them.

Maps retain their collection type and keys. Message and enum values are decoded, with errors such
as `values["rpc"].values["limits"].leaf`. The example uses Prost's `btree_map` setting for `no_std`;
the default `HashMap` representation requires the `std` feature. Synthetic map-entry descriptors
can be included in the selected messages and are skipped automatically.

Optional oneofs use a manual `#[proto_decode(optional)]` field attribute. The build script omits
the leading dot from that attribute's path to avoid applying it to the oneof variants.

Run from the protocol workspace root:

```sh
cargo test --manifest-path crates/miden-protobuf/examples/consumer/Cargo.toml
```

The `miden-protobuf` test suite also runs this example when its `build` feature is enabled.
