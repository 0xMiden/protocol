use miden_protobuf::{ConversionError, DecodeRepeated, ProtoDecode, RepeatedField};

#[derive(Clone, PartialEq, prost::Message, ProtoDecode)]
#[proto_decode(target(DownstreamValue), constructor(DownstreamValue::new(value)))]
struct DownstreamMessage {
    #[prost(uint32, tag = "1")]
    value: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct DownstreamValue(u16);

impl DownstreamValue {
    const fn new(value: u16) -> Self {
        Self(value)
    }
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecode)]
#[proto_decode(target(DownstreamCollection), constructor(DownstreamCollection::new(values)))]
struct DownstreamRepeatedMessage {
    #[prost(uint32, repeated, tag = "1")]
    values: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq)]
struct CheckedValues(Vec<u16>);

impl DecodeRepeated<u32> for CheckedValues {
    fn decode_repeated(field: RepeatedField<u32>) -> Result<Self, ConversionError> {
        field.decode_items().map(CheckedValues)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DownstreamCollection(CheckedValues);

impl DownstreamCollection {
    const fn new(values: CheckedValues) -> Self {
        Self(values)
    }
}

#[test]
fn reexported_derive_expands_in_a_downstream_crate() {
    assert_eq!(
        DownstreamValue::try_from(DownstreamMessage { value: 7 }).unwrap(),
        DownstreamValue(7)
    );
}

#[test]
fn downstream_conversion_uses_shared_error_paths() {
    let error: ConversionError =
        DownstreamValue::try_from(DownstreamMessage { value: u32::MAX }).unwrap_err();

    assert!(error.to_string().starts_with("value:"));
}

#[test]
fn downstream_crate_can_supply_a_repeated_field_adapter() {
    let value =
        DownstreamCollection::try_from(DownstreamRepeatedMessage { values: vec![1, 2] }).unwrap();

    assert_eq!(value, DownstreamCollection(CheckedValues(vec![1, 2])));
}
