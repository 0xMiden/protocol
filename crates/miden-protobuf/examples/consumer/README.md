# Protobuf Consumer

A standalone `no_std` consumer showing build configuration, generated decoding, and error paths.

- `build.rs` defines a small schema and configures decoding before generating Prost types.
- `src/lib.rs` uses those types and demonstrates record, oneof, and payload decoding in tests.

Run from the protocol workspace root:

```sh
cargo test --manifest-path crates/miden-protobuf/examples/consumer/Cargo.toml
```

The `miden-protobuf` test suite also runs this example when its `build` feature is enabled.
