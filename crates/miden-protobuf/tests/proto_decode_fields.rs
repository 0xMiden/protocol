#![cfg(feature = "derive")]

use core::convert::Infallible;

use miden_protobuf::{
    BuildUnchecked,
    DecodeMessage,
    DecodeMessageExt,
    ProtoDecodeFields,
    VerifyWith,
};

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
#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct Container {
    #[prost(message, optional, tag = "1")]
    required: Option<Child>,
    #[prost(message, optional, tag = "2")]
    #[proto_decode(optional)]
    optional: Option<Child>,
    #[prost(message, repeated, tag = "3")]
    repeated: Vec<Child>,
}
fn child() -> Child {
    Child { leaf: Some(Leaf { value: 7 }) }
}
#[test]
fn generated_records_preserve_presence_and_nested_fields() {
    let decoded = Container {
        required: Some(child()),
        optional: None,
        repeated: vec![child()],
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.required.leaf.value, 7);
    assert!(decoded.optional.is_none());
    assert_eq!(decoded.repeated[0].leaf.value, 7);
}
#[test]
fn generated_records_report_complete_paths() {
    let error = Container {
        required: Some(child()),
        optional: None,
        repeated: vec![child(), Child { leaf: None }],
    }
    .decode_fields()
    .unwrap_err();
    assert!(error.to_string().starts_with("repeated[1].leaf:"), "{error}");
    let error = Container::default().decode_fields().unwrap_err();
    assert!(error.to_string().starts_with("required:"), "{error}");
}
#[derive(Debug)]
struct LimitExceeded;

impl core::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("value exceeds permitted limit")
    }
}
impl core::error::Error for LimitExceeded {}

impl VerifyWith<&u32> for DecodedLeaf {
    type Verified = u32;
    type Error = LimitExceeded;
    fn verify_with(self, max: &u32) -> Result<u32, Self::Error> {
        if self.value > *max {
            return Err(LimitExceeded);
        }
        Ok(self.value)
    }
}
impl BuildUnchecked for DecodedLeaf {
    type Output = u32;
    type Error = Infallible;
    // This fixture retains the decoded scalar without applying the contextual cap.
    fn build_unchecked(self) -> Result<u32, Infallible> {
        Ok(self.value)
    }
}
#[test]
fn construction_capabilities_are_independent_and_opt_in() {
    assert_eq!(Leaf { value: 7 }.decode_and_verify_with(&10).unwrap(), 7);
    assert!(Leaf { value: u32::MAX }.decode_and_verify_with(&5).is_err());
    assert_eq!(Leaf { value: u32::MAX }.decode_and_build_unchecked().unwrap(), u32::MAX);
}

mod kinds {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Unspecified = 0,
        Active = 1,
        Negative = -1,
    }
}

#[derive(Clone, PartialEq, prost::Oneof, ProtoDecodeFields)]
enum Choice {
    #[prost(message, tag = "1")]
    #[proto_decode(name = "nested_child")]
    NestedChild(Child),
    #[prost(uint64, tag = "2")]
    #[proto_decode(name = "index")]
    Index(u64),
    #[prost(enumeration = "kinds::Kind", tag = "3")]
    #[proto_decode(name = "type")]
    Type(i32),
    #[prost(message, tag = "4")]
    #[proto_decode(name = "empty")]
    Empty(()),
}
#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct ChoiceMessage {
    #[prost(oneof = "Choice", tags = "1, 2, 3, 4")]
    choice: Option<Choice>,
}
#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct ChoiceContainer {
    #[prost(message, repeated, tag = "1")]
    children: Vec<ChoiceMessage>,
}
#[test]
fn oneof_payloads_decode_without_domain_mapping() {
    use prost::Message;
    for choice in [
        Choice::NestedChild(child()),
        Choice::Index(0),
        Choice::Type(1),
        Choice::Empty(()),
    ] {
        let wire = ChoiceMessage { choice: Some(choice.clone()) };
        let decoded = ChoiceMessage::decode(wire.encode_to_vec().as_slice())
            .unwrap()
            .decode_fields()
            .unwrap();
        match (choice, decoded.choice) {
            (Choice::NestedChild(_), DecodedChoice::NestedChild(value)) => {
                assert_eq!(value.leaf.value, 7)
            },
            (Choice::Index(value), DecodedChoice::Index(decoded)) => assert_eq!(value, decoded),
            (Choice::Type(_), DecodedChoice::Type(kinds::Kind::Active))
            | (Choice::Empty(()), DecodedChoice::Empty(())) => {},
            _ => panic!("variant changed"),
        }
    }
}
#[test]
fn oneof_errors_include_variant_and_repeated_parent_paths() {
    use core::error::Error;
    let error = ChoiceContainer {
        children: vec![ChoiceMessage {
            choice: Some(Choice::NestedChild(Child { leaf: None })),
        }],
    }
    .decode_fields()
    .unwrap_err();
    assert!(
        error.to_string().starts_with("children[0].choice.nested_child.leaf:"),
        "{error}"
    );
    let error = ChoiceMessage { choice: Some(Choice::Type(99)) }.decode_fields().unwrap_err();
    assert!(error.to_string().starts_with("choice.type:"), "{error}");
    assert_eq!(error.source().unwrap().downcast_ref::<prost::UnknownEnumValue>().unwrap().0, 99);
    let error = ChoiceMessage::default().decode_fields().unwrap_err();
    assert!(error.to_string().starts_with("choice: field"), "{error}");
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct EnumFields {
    #[prost(enumeration = "kinds::Kind", tag = "1")]
    r#type: i32,
    #[prost(enumeration = "kinds::Kind", optional, tag = "2")]
    optional: Option<i32>,
    #[prost(enumeration = "kinds::Kind", repeated, tag = "3")]
    repeated: Vec<i32>,
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct EnumContainer {
    #[prost(message, repeated, tag = "1")]
    children: Vec<EnumFields>,
}

#[test]
fn enum_fields_use_named_prost_types_and_preserve_presence() {
    use kinds::Kind;
    use prost::Message;

    let wire = EnumFields {
        r#type: Kind::Active as i32,
        optional: Some(Kind::Unspecified as i32),
        repeated: vec![Kind::Negative as i32, Kind::Active as i32],
    };
    let decoded = EnumFields::decode(wire.encode_to_vec().as_slice())
        .unwrap()
        .decode_fields()
        .unwrap();
    let _: Kind = decoded.r#type;
    let _: Option<Kind> = decoded.optional;
    let _: Vec<Kind> = decoded.repeated;
    assert_eq!(decoded.r#type, Kind::Active);
    assert_eq!(decoded.optional, Some(Kind::Unspecified));
    assert_eq!(decoded.repeated, [Kind::Negative, Kind::Active]);

    let decoded = EnumFields::default().decode_fields().unwrap();
    assert_eq!(decoded.r#type, Kind::Unspecified);
    assert_eq!(decoded.optional, None);
    assert!(decoded.repeated.is_empty());
}

#[test]
fn unknown_enums_report_full_paths_and_preserve_prost_errors() {
    use core::error::Error;

    for unknown in [i32::MIN, 2, i32::MAX] {
        for (wire, path) in [
            (EnumFields { r#type: unknown, ..Default::default() }, "type"),
            (
                EnumFields {
                    optional: Some(unknown),
                    ..Default::default()
                },
                "optional",
            ),
            (
                EnumFields {
                    repeated: vec![0, unknown],
                    ..Default::default()
                },
                "repeated[1]",
            ),
        ] {
            let error = EnumContainer {
                children: vec![EnumFields::default(), wire],
            }
            .decode_fields()
            .unwrap_err();
            assert!(error.to_string().starts_with(&format!("children[1].{path}: ")), "{error}");
            assert_eq!(
                error.source().unwrap().downcast_ref::<prost::UnknownEnumValue>().unwrap().0,
                unknown,
            );
        }
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
struct BytesMessage {
    #[prost(bytes = "vec", tag = "1")]
    #[proto_decode(bytes = ByteValue)]
    value: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "2")]
    #[proto_decode(bytes = ByteValue)]
    optional: Option<Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    #[proto_decode(bytes = ByteValue)]
    repeated: Vec<Vec<u8>>,
}
#[derive(Clone, PartialEq, prost::Oneof, ProtoDecodeFields)]
enum BytesChoice {
    #[prost(bytes = "vec", tag = "1")]
    #[proto_decode(name = "encoded", bytes = ByteValue)]
    Encoded(Vec<u8>),
}
#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct BytesChoiceMessage {
    #[prost(oneof = "BytesChoice", tags = "1")]
    choice: Option<BytesChoice>,
}
#[test]
fn bytes_adapters_keep_generated_paths_and_sources() {
    use core::error::Error;
    let decoded = BytesChoiceMessage {
        choice: Some(BytesChoice::Encoded(vec![7])),
    }
    .decode_fields()
    .unwrap();
    let DecodedBytesChoice::Encoded(value) = decoded.choice;
    assert_eq!(value, ByteValue(7));
    let decoded = BytesMessage {
        value: vec![1],
        optional: Some(vec![2]),
        repeated: vec![vec![3]],
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.value, ByteValue(1));
    assert_eq!(decoded.optional, Some(ByteValue(2)));
    assert_eq!(decoded.repeated, [ByteValue(3)]);
    for (optional, repeated, path) in
        [(Some(vec![]), vec![], "optional"), (None, vec![vec![1], vec![]], "repeated[1]")]
    {
        let error =
            BytesMessage { value: vec![1], optional, repeated }.decode_fields().unwrap_err();
        assert!(error.to_string().starts_with(&format!("{path}:")), "{error}");
        assert!(error.source().unwrap().is::<core::array::TryFromSliceError>());
    }
    let error = BytesChoiceMessage {
        choice: Some(BytesChoice::Encoded(vec![])),
    }
    .decode_fields()
    .unwrap_err();
    assert!(error.to_string().starts_with("choice.encoded:"), "{error}");
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct OptionalChoice {
    #[prost(oneof = "Choice", tags = "1, 2, 3, 4")]
    #[proto_decode(optional)]
    choice: Option<Choice>,
}
#[test]
fn optional_oneofs_preserve_absence_and_validate_present_payloads() {
    assert!(OptionalChoice::default().decode_fields().unwrap().choice.is_none());
    let decoded = OptionalChoice { choice: Some(Choice::Index(0)) }.decode_fields().unwrap();
    assert!(matches!(decoded.choice, Some(DecodedChoice::Index(0))));
    let error = OptionalChoice {
        choice: Some(Choice::NestedChild(Child { leaf: None })),
    }
    .decode_fields()
    .unwrap_err();
    assert!(error.to_string().starts_with("choice.nested_child.leaf:"), "{error}");
}
