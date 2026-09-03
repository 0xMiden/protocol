# Miden Objects

Canonical Protobuf representations for values exchanged between Miden clients and nodes.

This crate owns the transport representation and conversions for protocol objects. It does not
define protocol commitments, replace the protocol's native serialization, or define RPC services.
Generated messages are exposed under `miden_objects::proto`.

The crate supports `no_std` consumers when default features are disabled.

RPC crates can use `FILE_DESCRIPTOR_SET` as the import descriptor and apply every entry in
`EXTERN_PATHS` with `prost_build::Config::extern_path`. This makes imported object messages resolve
to the canonical generated types from this crate instead of generating duplicate Rust types in the
RPC crate.

## License

This project is [MIT licensed](../../LICENSE).
