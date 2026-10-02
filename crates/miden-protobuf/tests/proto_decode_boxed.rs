#![cfg(feature = "derive")]

use core::num::TryFromIntError;

use miden_protobuf::{BuildUnchecked, DecodeMessage, ProtoDecodeFields, Verify, VerifyWith};
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

fn child(value: u32) -> Box<Child> {
    Box::new(Child { leaf: Some(Leaf { value }) })
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct BoxedFields {
    #[prost(message, optional, boxed, tag = "1")]
    required: Option<Box<Child>>,
    #[prost(message, optional, boxed, tag = "2")]
    #[proto_decode(optional)]
    optional: Option<Box<Child>>,
    #[prost(message, required, boxed, tag = "3")]
    direct: Box<Child>,
    #[prost(message, repeated, boxed, tag = "4")]
    #[allow(clippy::vec_box)]
    repeated: Vec<Box<Child>>,
}

fn fields() -> BoxedFields {
    BoxedFields {
        required: Some(child(1)),
        optional: Some(child(2)),
        direct: child(3),
        repeated: vec![child(4), child(5)],
    }
}

#[test]
fn boxed_fields_preserve_boxes_and_cardinality() {
    let wire = fields();
    let decoded = BoxedFields::decode(wire.encode_to_vec().as_slice())
        .unwrap()
        .decode_fields()
        .unwrap();
    let required: Box<DecodedChild> = decoded.required;
    let direct: Box<DecodedChild> = decoded.direct;
    assert_eq!(required.leaf.value, 1);
    assert_eq!(decoded.optional.as_ref().unwrap().leaf.value, 2);
    assert_eq!(direct.leaf.value, 3);
    assert_eq!(decoded.repeated.as_slice()[1].leaf.value, 5);
    let absent = BoxedFields { optional: None, ..fields() }.decode_fields().unwrap();
    assert!(absent.optional.as_ref().is_none());
}

#[test]
fn boxed_fields_retain_required_checks_and_nested_error_paths() {
    for (wire, path) in [
        (BoxedFields { required: None, ..fields() }, "required:"),
        (
            BoxedFields {
                required: Some(Box::default()),
                ..fields()
            },
            "required.leaf:",
        ),
        (
            BoxedFields {
                optional: Some(Box::default()),
                ..fields()
            },
            "optional.leaf:",
        ),
        (BoxedFields { direct: Box::default(), ..fields() }, "direct.leaf:"),
        (
            BoxedFields {
                repeated: vec![child(1), Box::default()],
                ..fields()
            },
            "repeated[1].leaf:",
        ),
    ] {
        let error = wire.decode_fields().unwrap_err();
        assert!(error.to_string().starts_with(path), "{error}");
    }
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct BoxedEmpty {
    #[prost(message, optional, boxed, tag = "1")]
    required: Option<Box<()>>,
    #[prost(message, optional, boxed, tag = "2")]
    #[proto_decode(optional)]
    optional: Option<Box<()>>,
}

#[test]
fn boxed_google_protobuf_empty_preserves_presence_without_a_message_adapter() {
    let decoded = BoxedEmpty {
        required: Some(Box::default()),
        optional: None,
    }
    .decode_fields()
    .unwrap();
    let _: Box<()> = decoded.required;
    assert!(decoded.optional.as_ref().is_none());
    let decoded = BoxedEmpty {
        required: Some(Box::default()),
        optional: Some(Box::default()),
    }
    .decode_fields()
    .unwrap();
    assert!(decoded.optional.as_ref().is_some());
    let error = BoxedEmpty::default().decode_fields().unwrap_err();
    assert!(error.to_string().starts_with("required: field"), "{error}");
}

impl Verify for DecodedChild {
    type Verified = u8;
    type Error = TryFromIntError;

    fn verify(self) -> Result<u8, Self::Error> {
        self.leaf.value.try_into()
    }
}

// Owned and non-Clone to ensure the box forwards context without additional bounds.
struct Context(u32);

impl VerifyWith<Context> for DecodedChild {
    type Verified = u8;
    type Error = TryFromIntError;

    fn verify_with(self, context: Context) -> Result<u8, Self::Error> {
        (self.leaf.value + context.0).try_into()
    }
}

impl BuildUnchecked for DecodedChild {
    type Output = u32;
    type Error = core::convert::Infallible;

    fn build_unchecked(self) -> Result<u32, Self::Error> {
        Ok(self.leaf.value)
    }
}

#[test]
fn boxed_values_forward_each_construction_capability_independently() {
    use core::error::Error;

    let decoded = fields().decode_fields().unwrap();
    let verified: Box<u8> = decoded.required.verify().unwrap();
    assert_eq!(*verified, 1);
    let contextual: Box<u8> = decoded.direct.verify_with(Context(1)).unwrap();
    assert_eq!(*contextual, 4);
    let values: Vec<Box<u8>> = decoded.repeated.verify().unwrap();
    assert_eq!(values, [Box::new(4), Box::new(5)]);

    let wire = BoxedFields { optional: Some(child(256)), ..fields() };
    let decoded = wire.clone().decode_fields().unwrap();
    let error = decoded.optional.verify().unwrap_err();
    assert!(error.to_string().starts_with("optional:"), "{error}");
    assert!(error.source().unwrap().is::<TryFromIntError>());
    let decoded = wire.decode_fields().unwrap();
    let unchecked: Option<Box<u32>> = decoded.optional.build_unchecked().unwrap();
    assert_eq!(unchecked, Some(Box::new(256)));
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct Recursive {
    #[prost(message, optional, tag = "1")]
    leaf: Option<Leaf>,
    #[prost(message, optional, boxed, tag = "2")]
    #[proto_decode(optional)]
    next: Option<Box<Recursive>>,
}

#[test]
fn recursive_messages_decode_finite_values_and_retain_deep_error_paths() {
    let mut wire = Recursive {
        leaf: Some(Leaf { value: 1 }),
        next: None,
    };
    for value in 2..5 {
        wire = Recursive {
            leaf: Some(Leaf { value }),
            next: Some(Box::new(wire)),
        };
    }
    let decoded = Recursive::decode(wire.encode_to_vec().as_slice())
        .unwrap()
        .decode_fields()
        .unwrap();
    assert_eq!(decoded.leaf.value, 4);
    assert_eq!(decoded.next.as_ref().unwrap().leaf.value, 3);

    wire.next.as_mut().unwrap().next.as_mut().unwrap().leaf = None;
    let error = wire.decode_fields().unwrap_err();
    assert!(error.to_string().starts_with("next.next.leaf:"), "{error}");
}

#[derive(Clone, PartialEq, prost::Oneof, ProtoDecodeFields)]
enum Choice {
    #[prost(message, tag = "1")]
    #[proto_decode(name = "recurse")]
    Recurse(Box<ChoiceMessage>),
    #[prost(message, boxed, tag = "2")]
    #[proto_decode(name = "child")]
    Child(Box<Child>),
    #[prost(message, tag = "3")]
    #[proto_decode(name = "end")]
    End(()),
}

#[derive(Clone, PartialEq, prost::Message, ProtoDecodeFields)]
struct ChoiceMessage {
    #[prost(oneof = "Choice", tags = "1, 2, 3")]
    choice: Option<Choice>,
}

#[test]
fn recursive_oneofs_preserve_boxed_payloads_and_variant_paths() {
    let wire = ChoiceMessage {
        choice: Some(Choice::Recurse(Box::new(ChoiceMessage {
            choice: Some(Choice::Child(child(7))),
        }))),
    };
    let decoded = ChoiceMessage::decode(wire.encode_to_vec().as_slice())
        .unwrap()
        .decode_fields()
        .unwrap();
    let DecodedChoice::Recurse(recurse) = decoded.choice else {
        panic!("wrong variant")
    };
    let nested: Box<DecodedChoiceMessage> = recurse;
    let DecodedChoice::Child(child) = nested.choice else {
        panic!("wrong variant")
    };
    let payload: Box<DecodedChild> = child;
    assert_eq!(payload.leaf.value, 7);
    let error = ChoiceMessage {
        choice: Some(Choice::Recurse(Box::new(ChoiceMessage {
            choice: Some(Choice::Child(Box::default())),
        }))),
    }
    .decode_fields()
    .unwrap_err();
    assert!(error.to_string().starts_with("choice.recurse.choice.child.leaf:"), "{error}");
}

#[test]
fn recursive_oneof_accessors_preserve_decoded_boxes_and_error_paths() {
    let wire = Choice::Recurse(Box::new(ChoiceMessage { choice: Some(Choice::Child(child(256))) }));
    let nested: Box<DecodedChoiceMessage> = wire.into_recurse().unwrap();
    let payload: Box<DecodedChild> = nested.choice.into_child().unwrap();
    assert_eq!(payload.leaf.value, 256);
    assert!(payload.verify().is_err());

    let wire = Choice::Recurse(Box::new(ChoiceMessage {
        choice: Some(Choice::Child(Box::default())),
    }));
    let error = wire.clone().into_child().unwrap_err();
    assert_eq!(error.to_string(), "recurse: expected oneof variant `child`, got `recurse`");
    let error = wire.into_recurse().unwrap_err();
    assert!(error.to_string().starts_with("recurse.choice.child.leaf:"), "{error}");
}
