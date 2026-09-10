use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{
    DescriptorProto,
    FieldDescriptorProto,
    FileDescriptorProto,
    FileDescriptorSet,
    OneofDescriptorProto,
};

fn field(name: &str, number: i32, type_name: &str) -> FieldDescriptorProto {
    FieldDescriptorProto {
        name: Some(name.into()),
        number: Some(number),
        r#type: Some(Type::Message as i32),
        label: Some(Label::Optional as i32),
        type_name: Some(type_name.into()),
        ..Default::default()
    }
}

fn main() {
    let descriptors = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("consumer.proto".into()),
            package: Some("example".into()),
            syntax: Some("proto3".into()),
            message_type: vec![
                DescriptorProto {
                    name: Some("Leaf".into()),
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("Child".into()),
                    field: vec![field("leaf", 1, ".example.Leaf")],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("Container".into()),
                    field: vec![
                        field("implicit", 1, ".example.Child"),
                        FieldDescriptorProto {
                            proto3_optional: Some(true),
                            oneof_index: Some(1),
                            ..field("explicit", 2, ".example.Child")
                        },
                        FieldDescriptorProto {
                            oneof_index: Some(0),
                            ..field("choice_value", 3, ".example.Child")
                        },
                        FieldDescriptorProto {
                            label: Some(Label::Repeated as i32),
                            ..field("children", 4, ".example.Child")
                        },
                    ],
                    oneof_decl: vec![
                        OneofDescriptorProto {
                            name: Some("selection".into()),
                            ..Default::default()
                        },
                        OneofDescriptorProto {
                            name: Some("_explicit".into()),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
    };
    let mut prost = prost_build::Config::new();
    wire_codec::build::configure_proto_decode_fields(
        &mut prost,
        &descriptors,
        [".example.Leaf", ".example.Child", ".example.Container"],
    )
    .unwrap();
    prost.compile_fds(descriptors).unwrap();
}
