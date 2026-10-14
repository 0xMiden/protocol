#![cfg(all(feature = "derive", feature = "std"))]

use std::collections::{BTreeMap, HashMap};
use std::error::Error;

use miden_protobuf::{DecodeMessage, ProtoDecodeFields, Verify};
use prost::Message;

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct Leaf {
    #[prost(uint32, tag = "1")]
    value: u32,
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct Child {
    #[prost(message, optional, tag = "1")]
    leaf: Option<Leaf>,
}

impl Verify for DecodedChild {
    type Verified = u8;
    type Error = core::num::TryFromIntError;

    fn verify(self) -> Result<u8, Self::Error> {
        self.leaf.value.try_into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum Kind {
    Unspecified = 0,
    Active = 1,
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct Maps {
    #[prost(map = "string, message", tag = "1")]
    messages: HashMap<String, Child>,
    #[prost(btree_map = "int32, message", tag = "2")]
    ordered_messages: BTreeMap<i32, Child>,
    #[prost(map = "string, enumeration(Kind)", tag = "3")]
    enums: HashMap<String, i32>,
    #[prost(btree_map = "int64, enumeration(Kind)", tag = "4")]
    ordered_enums: BTreeMap<i64, i32>,
    #[prost(map = "uint64, sint32", tag = "5")]
    scalars: HashMap<u64, i32>,
    #[prost(btree_map = "bool, bytes", tag = "6")]
    bytes: BTreeMap<bool, Vec<u8>>,
    #[prost(map = "string, message", tag = "7")]
    empty: HashMap<String, ()>,
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct Parent {
    #[prost(message, repeated, tag = "1")]
    children: Vec<Maps>,
}

#[test]
fn map_values_decode_while_preserving_keys_and_collection_types() {
    let wire = Maps {
        messages: [("rpc".into(), Child { leaf: Some(Leaf { value: 7 }) })].into(),
        ordered_messages: [(-3, Child { leaf: Some(Leaf { value: 8 }) })].into(),
        enums: [("active".into(), 1)].into(),
        ordered_enums: [(i64::MIN, 0)].into(),
        scalars: [(u64::MAX, -1), (0, 2)].into(),
        bytes: [(false, vec![]), (true, vec![1, 2])].into(),
        empty: [("empty".into(), ())].into(),
    };
    let decoded = Maps::decode(wire.encode_to_vec().as_slice()).unwrap().decode_fields().unwrap();
    let _: &HashMap<String, DecodedChild> = decoded.messages.as_ref();
    let _: &BTreeMap<i32, DecodedChild> = decoded.ordered_messages.as_ref();
    let _: &HashMap<String, Kind> = decoded.enums.as_ref();
    let _: &BTreeMap<i64, Kind> = decoded.ordered_enums.as_ref();
    assert_eq!(decoded.messages.as_ref()["rpc"].leaf.value, 7);
    assert_eq!(decoded.ordered_messages.as_ref()[&-3].leaf.value, 8);
    assert_eq!(decoded.enums.as_ref()["active"], Kind::Active);
    assert_eq!(decoded.ordered_enums.as_ref()[&i64::MIN], Kind::Unspecified);
    assert_eq!(decoded.scalars.into_inner(), wire.scalars);
    assert_eq!(decoded.bytes.into_inner(), wire.bytes);
    assert_eq!(decoded.empty.into_inner(), wire.empty);

    let empty = Maps::default().decode_fields().unwrap();
    assert!(empty.messages.as_ref().is_empty());
    assert!(empty.ordered_messages.as_ref().is_empty());
    assert!(empty.enums.as_ref().is_empty());
    assert!(empty.ordered_enums.as_ref().is_empty());
}

#[test]
fn map_message_errors_preserve_escaped_keys_and_nested_paths() {
    let key = "rpc.\"[limits]\n";
    for (maps, path) in [
        (
            Maps {
                messages: [(key.into(), Child::default())].into(),
                ..Default::default()
            },
            format!("messages[{key:?}].leaf"),
        ),
        (
            Maps {
                ordered_messages: [(-3, Child::default())].into(),
                ..Default::default()
            },
            "ordered_messages[-3].leaf".into(),
        ),
    ] {
        let error = Parent { children: vec![Maps::default(), maps] }.decode_fields().unwrap_err();
        assert!(error.to_string().starts_with(&format!("children[1].{path}:")), "{error}");
    }
}

#[test]
fn generated_maps_retain_keys_for_later_verification() {
    let key = "rpc.\"[limits]\n";
    let decoded = Maps {
        messages: [(key.into(), Child { leaf: Some(Leaf { value: 256 }) })].into(),
        ordered_messages: [(-3, Child { leaf: Some(Leaf { value: 256 }) })].into(),
        ..Default::default()
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.messages.as_ref()[key].leaf.value, 256);
    for (error, path) in [
        (decoded.messages.verify().unwrap_err(), format!("messages[{key:?}]")),
        (decoded.ordered_messages.verify().unwrap_err(), "ordered_messages[-3]".into()),
    ] {
        assert!(error.to_string().starts_with(&format!("{path}:")), "{error}");
        assert!(error.source().unwrap().is::<core::num::TryFromIntError>());
    }
}

#[test]
fn enum_map_errors_preserve_keys_and_typed_sources() {
    for (maps, path) in [
        (
            Maps {
                enums: [("rpc".into(), 99)].into(),
                ..Default::default()
            },
            "enums[\"rpc\"]",
        ),
        (
            Maps {
                ordered_enums: [(i64::MIN, 99)].into(),
                ..Default::default()
            },
            "ordered_enums[-9223372036854775808]",
        ),
    ] {
        let error = maps.decode_fields().unwrap_err();
        assert!(error.to_string().starts_with(&format!("{path}:")), "{error}");
        assert_eq!(
            error.source().unwrap().downcast_ref::<prost::UnknownEnumValue>().unwrap().0,
            99
        );
    }
}

#[derive(Debug, PartialEq)]
struct ByteValue(u8);

impl TryFrom<Vec<u8>> for ByteValue {
    type Error = core::array::TryFromSliceError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let [value] = <[u8; 1]>::try_from(bytes.as_slice())?;
        Ok(Self(value))
    }
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct AdaptedMap {
    #[prost(btree_map = "bool, bytes", tag = "1")]
    #[proto_decode(bytes = ByteValue)]
    values: BTreeMap<bool, Vec<u8>>,
}

#[test]
fn map_value_adapters_preserve_key_context_and_sources() {
    let decoded = AdaptedMap { values: [(true, vec![7])].into() }.decode_fields().unwrap();
    assert_eq!(decoded.values.as_ref()[&true], ByteValue(7));
    let error = AdaptedMap { values: [(false, vec![])].into() }.decode_fields().unwrap_err();
    assert!(error.to_string().starts_with("values[false]:"), "{error}");
    assert!(error.source().unwrap().is::<core::array::TryFromSliceError>());
}
