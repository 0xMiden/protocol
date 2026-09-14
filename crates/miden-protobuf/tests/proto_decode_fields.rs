#![cfg(feature = "derive")]

use core::convert::Infallible;

use miden_protobuf::{
    BuildUnchecked,
    DecodeMessage,
    DecodeMessageExt,
    DuplicatePolicy,
    ProtoDecodeFields,
    Verify,
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
    assert!(decoded.optional.as_ref().is_none());
    assert_eq!(decoded.repeated.as_slice()[0].leaf.value, 7);
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

impl Verify for DecodedChild {
    type Verified = u8;
    type Error = core::num::TryFromIntError;

    fn verify(self) -> Result<u8, Self::Error> {
        self.leaf.value.try_into()
    }
}

impl VerifyWith<&u32> for DecodedChild {
    type Verified = u32;
    type Error = LimitExceeded;

    fn verify_with(self, max: &u32) -> Result<u32, Self::Error> {
        self.leaf.verify_with(max)
    }
}

#[test]
fn generated_collections_retain_context_until_explicit_verification() {
    use core::error::Error;

    let wire = Container {
        required: Some(child()),
        optional: Some(Child { leaf: Some(Leaf { value: 256 }) }),
        repeated: vec![child(), Child { leaf: Some(Leaf { value: 256 }) }],
    };
    // Both malformed domain values survive structural decoding and can be inspected.
    let decoded = wire.clone().decode_fields().unwrap();
    assert_eq!(decoded.optional.as_ref().unwrap().leaf.value, 256);
    assert_eq!(decoded.repeated.as_slice()[1].leaf.value, 256);
    let optional = decoded.optional.verify().unwrap_err();
    assert!(optional.to_string().starts_with("optional:"), "{optional}");
    assert!(optional.source().unwrap().is::<core::num::TryFromIntError>());
    let repeated = decoded.repeated.verify().unwrap_err();
    assert!(repeated.to_string().starts_with("repeated[1]:"), "{repeated}");
    assert!(repeated.source().unwrap().is::<core::num::TryFromIntError>());

    let decoded = wire.decode_fields().unwrap();
    let optional = decoded.optional.verify_with(&255).unwrap_err();
    assert!(optional.to_string().starts_with("optional:"), "{optional}");
    assert!(optional.source().unwrap().is::<LimitExceeded>());
    let repeated = decoded.repeated.verify_with(&255).unwrap_err();
    assert!(repeated.to_string().starts_with("repeated[1]:"), "{repeated}");
    assert!(repeated.source().unwrap().is::<LimitExceeded>());
}

#[test]
fn generated_collections_require_an_explicit_set_duplicate_policy() {
    let wire = Container {
        required: Some(child()),
        optional: None,
        repeated: vec![child(), child()],
    };
    let decoded = wire.clone().decode_fields().unwrap();
    assert_eq!(decoded.optional.verify().unwrap(), None);
    let error = decoded.repeated.verify_into_btree_set(DuplicatePolicy::Reject).unwrap_err();
    assert!(error.to_string().starts_with("repeated[1]: duplicate"), "{error}");
    let decoded = wire.decode_fields().unwrap();
    let values = decoded.repeated.verify_into_btree_set(DuplicatePolicy::KeepFirst).unwrap();
    assert_eq!(values, [7].into());
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct ScalarCollections {
    #[prost(uint32, repeated, tag = "1")]
    numbers: Vec<u32>,
    #[prost(uint32, optional, tag = "2")]
    number: Option<u32>,
    #[prost(bytes = "vec", tag = "3")]
    bytes: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "4")]
    buffers: Vec<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    buffer: Option<Vec<u8>>,
}

#[test]
fn wrappers_follow_protobuf_cardinality_and_allow_explicit_extraction() {
    let wire = ScalarCollections {
        numbers: vec![2, 1, 2],
        number: Some(0),
        bytes: vec![1, 2],
        buffers: vec![vec![3], vec![]],
        buffer: Some(vec![]),
    };
    let decoded = wire.clone().decode_fields().unwrap();
    let _: &Vec<u8> = &decoded.bytes;
    assert_eq!(decoded.bytes, wire.bytes);
    assert_eq!(decoded.numbers.as_slice(), wire.numbers);
    assert_eq!(decoded.numbers.into_inner(), wire.numbers);
    assert_eq!(decoded.number.as_ref(), Some(&0));
    assert_eq!(decoded.number.into_inner(), wire.number);
    assert_eq!(decoded.buffers.as_slice(), wire.buffers);
    assert_eq!(decoded.buffers.into_inner(), wire.buffers);
    assert_eq!(decoded.buffer.as_ref(), Some(&vec![]));
    assert_eq!(decoded.buffer.into_inner(), wire.buffer);
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
    let _: &miden_protobuf::OptionalField<Kind> = &decoded.optional;
    let _: &miden_protobuf::RepeatedField<Kind> = &decoded.repeated;
    assert_eq!(decoded.r#type, Kind::Active);
    assert_eq!(decoded.optional.into_inner(), Some(Kind::Unspecified));
    assert_eq!(decoded.repeated.into_inner(), [Kind::Negative, Kind::Active]);

    let decoded = EnumFields::default().decode_fields().unwrap();
    assert_eq!(decoded.r#type, Kind::Unspecified);
    assert_eq!(decoded.optional.into_inner(), None);
    assert!(decoded.repeated.as_slice().is_empty());
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
    assert_eq!(decoded.optional.into_inner(), Some(ByteValue(2)));
    assert_eq!(decoded.repeated.into_inner(), [ByteValue(3)]);
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
    assert!(OptionalChoice::default().decode_fields().unwrap().choice.as_ref().is_none());
    let decoded = OptionalChoice { choice: Some(Choice::Index(0)) }.decode_fields().unwrap();
    assert!(matches!(decoded.choice.into_inner(), Some(DecodedChoice::Index(0))));
    let error = OptionalChoice {
        choice: Some(Choice::NestedChild(Child { leaf: None })),
    }
    .decode_fields()
    .unwrap_err();
    assert!(error.to_string().starts_with("choice.nested_child.leaf:"), "{error}");
}

#[test]
fn wire_and_decoded_oneof_accessors_return_payloads_without_verification() {
    let wire = Choice::NestedChild(Child { leaf: Some(Leaf { value: 256 }) });
    let decoded: DecodedChild = wire.clone().into_nested_child().unwrap();
    assert_eq!(decoded.leaf.value, 256);
    // Extraction succeeded even though the domain verifier rejects this value.
    assert!(decoded.verify().is_err());
    let decoded: DecodedChild = wire.decode_fields().unwrap().into_nested_child().unwrap();
    assert_eq!(decoded.leaf.value, 256);
    assert!(decoded.verify().is_err());

    assert_eq!(Choice::Index(7).into_index().unwrap(), 7);
    assert_eq!(Choice::Index(7).decode_fields().unwrap().into_index().unwrap(), 7);
    assert_eq!(Choice::Type(1).into_type().unwrap(), kinds::Kind::Active);
    assert_eq!(
        Choice::Type(1).decode_fields().unwrap().into_type().unwrap(),
        kinds::Kind::Active
    );
    let _: () = Choice::Empty(()).into_empty().unwrap();
    let _: () = Choice::Empty(()).decode_fields().unwrap().into_empty().unwrap();
}

#[test]
fn mismatched_oneof_accessors_report_the_expected_and_actual_wire_variants() {
    for wire in [Choice::Index(7), Choice::Type(1), Choice::Empty(())] {
        let actual = match &wire {
            Choice::Index(_) => "index",
            Choice::Type(_) => "type",
            Choice::Empty(_) => "empty",
            _ => unreachable!(),
        };
        let expected = format!("{actual}: expected oneof variant `nested_child`, got `{actual}`");
        let error = wire.clone().into_nested_child().unwrap_err();
        assert_eq!(error.to_string(), expected);
        let error = wire.decode_fields().unwrap().into_nested_child().unwrap_err();
        assert_eq!(error.to_string(), expected);
    }
    for error in [
        Choice::NestedChild(child()).into_index().unwrap_err(),
        Choice::NestedChild(child()).decode_fields().unwrap().into_index().unwrap_err(),
    ] {
        assert_eq!(
            error.to_string(),
            "nested_child: expected oneof variant `index`, got `nested_child`"
        );
    }
}

#[test]
fn wire_accessors_check_the_variant_before_decoding_its_payload() {
    let wire = Choice::NestedChild(Child::default());
    let error = wire.clone().into_index().unwrap_err();
    assert_eq!(
        error.to_string(),
        "nested_child: expected oneof variant `index`, got `nested_child`"
    );
    let error = wire.into_nested_child().unwrap_err();
    assert!(error.to_string().starts_with("nested_child.leaf:"), "{error}");

    let error = Choice::Type(99).into_index().unwrap_err();
    assert_eq!(error.to_string(), "type: expected oneof variant `index`, got `type`");
}

#[test]
fn oneof_accessors_preserve_conversion_sources_and_collection_context() {
    use core::error::Error;

    use miden_protobuf::RepeatedField;

    let error = Choice::Type(99).into_type().unwrap_err();
    assert!(error.to_string().starts_with("type:"), "{error}");
    assert_eq!(error.source().unwrap().downcast_ref::<prost::UnknownEnumValue>().unwrap().0, 99);

    let error = RepeatedField::new("choices", vec![Choice::Index(0), Choice::Type(99)])
        .try_map(Choice::into_index)
        .unwrap_err();
    assert_eq!(error.to_string(), "choices[1].type: expected oneof variant `index`, got `type`");
    let error = RepeatedField::new("choices", vec![Choice::NestedChild(Child::default())])
        .try_map(Choice::into_nested_child)
        .unwrap_err();
    assert!(error.to_string().starts_with("choices[0].nested_child.leaf:"), "{error}");
}

#[test]
fn single_variant_accessors_apply_bytes_adapters_and_preserve_sources() {
    use core::error::Error;

    assert_eq!(BytesChoice::Encoded(vec![7]).into_encoded().unwrap(), ByteValue(7));
    assert_eq!(
        BytesChoice::Encoded(vec![7]).decode_fields().unwrap().into_encoded().unwrap(),
        ByteValue(7)
    );
    let error = BytesChoice::Encoded(vec![]).into_encoded().unwrap_err();
    assert!(error.to_string().starts_with("encoded:"), "{error}");
    assert!(error.source().unwrap().is::<core::array::TryFromSliceError>());
}

#[derive(Clone, PartialEq, prost::Oneof, ProtoDecodeFields)]
enum WireNames {
    #[prost(uint32, tag = "1")]
    #[proto_decode(name = "HTTPResponse")]
    DifferentRustName(u32),
    #[prost(uint32, tag = "2")]
    #[proto_decode(name = "type")]
    Type(u32),
}

#[test]
fn accessor_names_use_snake_case_but_errors_keep_exact_wire_names() {
    assert_eq!(WireNames::Type(7).into_type().unwrap(), 7);
    assert_eq!(WireNames::Type(7).decode_fields().unwrap().into_type().unwrap(), 7);
    assert_eq!(WireNames::DifferentRustName(7).into_http_response().unwrap(), 7);
    assert_eq!(
        WireNames::DifferentRustName(7)
            .decode_fields()
            .unwrap()
            .into_http_response()
            .unwrap(),
        7
    );
    let error = WireNames::DifferentRustName(7).into_type().unwrap_err();
    assert_eq!(
        error.to_string(),
        "HTTPResponse: expected oneof variant `type`, got `HTTPResponse`"
    );
    let error = WireNames::Type(7).decode_fields().unwrap().into_http_response().unwrap_err();
    assert_eq!(error.to_string(), "type: expected oneof variant `HTTPResponse`, got `type`");
}
