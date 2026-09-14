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

## Decoded Objects

The experimental `ProtoDecodeFields` derive generates schema-shaped records, required/optional/
repeated message conversion, and nested field/index error paths. Atomic messages can implement
`DecodeMessage` using their existing representation decoder. Enum fields use Prost's named enum
types, preserving optional/repeated cardinality and rejecting unknown discriminants with generated
paths. Known variants such as `Unspecified` remain available for domain verification. Oneofs
generate matching decoded enums, with exact wire variant names supplied by descriptors.
An absent oneof is rejected by default; an explicitly configured optional oneof retains its Option.
Maps and boxed messages are not yet supported and are not used by these schemas.

The three single-payload atoms use `ProtoDecodeValue` to generate `decode_value(&self, parser)`.
Their parsers return representation errors; the helper supplies the payload field path and
preserves the source. Neither targets nor constructors are configured in attributes.

Canonical bytes can opt into a local representation type using
`#[proto_decode(bytes = Adapter)]`. The adapter implements ordinary `TryFrom`; generated
code supplies field, variant, and index paths. It does not run domain verification.

Domain construction is opt-in and handwritten: `Verify::verify()` needs no external context,
`VerifyWith<C>::verify_with(context)` accepts borrowed or owned context, and
`BuildUnchecked::build_unchecked()` uses a supported unchecked constructor. Unchecked construction
can still fail and must document the invariants the caller must ensure. None of these operations
is invoked automatically by field decoding, and verification errors do not get generated wire
paths. Direct protobuf-to-domain `TryFrom`/`From` conversions are intentionally unavailable for
generated records; only atomic representation adapters retain their `TryFrom` implementations.

Import `DecodeMessageExt` to combine field decoding with an explicit construction choice:

```rust
use miden_objects::{ConversionError, DecodeMessageExt, proto};
use miden_protocol::block::BlockNumber;

fn decode_block_number(message: proto::blockchain::BlockNumber) -> Result<BlockNumber, ConversionError> {
    message.decode_and_verify()
}
```

`decode_and_verify_with(context)` and `decode_and_build_unchecked()` select the other capabilities.
Each helper is available only when the decoded type implements the corresponding trait. They
consume parsed Protobuf messages and return `ConversionError` with a `failed to decode`,
`failed to verify`, or `failed to build unchecked` prefix. The original error, including structural
field paths and domain error sources, is preserved in the source chain. Call `decode_fields()` and
the construction method separately when the intermediate record or typed domain error is needed.

## License

This project is [MIT licensed](../../LICENSE).
