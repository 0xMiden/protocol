use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{
    DescriptorProto,
    EnumDescriptorProto,
    EnumValueDescriptorProto,
    FieldDescriptorProto,
    FileDescriptorProto,
    FileDescriptorSet,
    MessageOptions,
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

fn map_message(name: &str, value_type: Type, value_type_name: Option<&str>) -> DescriptorProto {
    DescriptorProto {
        name: Some(name.into()),
        field: vec![FieldDescriptorProto {
            label: Some(Label::Repeated as i32),
            ..field("values", 1, &format!(".example.{name}.ValuesEntry"))
        }],
        nested_type: vec![DescriptorProto {
            name: Some("ValuesEntry".into()),
            options: Some(MessageOptions {
                map_entry: Some(true),
                ..Default::default()
            }),
            field: vec![
                FieldDescriptorProto {
                    name: Some("key".into()),
                    number: Some(1),
                    r#type: Some(Type::String as i32),
                    label: Some(Label::Optional as i32),
                    ..Default::default()
                },
                FieldDescriptorProto {
                    name: Some("value".into()),
                    number: Some(2),
                    r#type: Some(value_type as i32),
                    type_name: value_type_name.map(str::to_owned),
                    label: Some(Label::Optional as i32),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn main() {
    let descriptors = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("consumer.proto".into()),
            package: Some("example".into()),
            syntax: Some("proto3".into()),
            enum_type: vec![EnumDescriptorProto {
                name: Some("Kind".into()),
                value: vec![EnumValueDescriptorProto {
                    name: Some("UNSPECIFIED".into()),
                    number: Some(0),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            message_type: vec![
                map_message("MappedChildren", Type::Message, Some(".example.Child")),
                map_message("MappedGroups", Type::Message, Some(".example.MappedChildren")),
                map_message("MappedScalars", Type::Uint32, None),
                map_message("MappedEnums", Type::Enum, Some(".example.Kind")),
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
                    nested_type: vec![DescriptorProto {
                        name: Some("DetailRequest".into()),
                        field: vec![
                            FieldDescriptorProto {
                                oneof_index: Some(0),
                                ..field("all", 1, ".example.Child")
                            },
                            FieldDescriptorProto {
                                name: Some("slot".into()),
                                number: Some(2),
                                r#type: Some(Type::Uint32 as i32),
                                label: Some(Label::Optional as i32),
                                oneof_index: Some(0),
                                ..Default::default()
                            },
                        ],
                        oneof_decl: vec![OneofDescriptorProto {
                            name: Some("storage_request".into()),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
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
    // BTreeMap keeps generated map fields usable without std.
    prost.btree_map(["."]);
    wire_codec::build::configure_proto_decode_fields(
        &mut prost,
        &descriptors,
        [
            ".example.Leaf",
            ".example.Child",
            ".example.Container",
            ".example.Container.DetailRequest",
            ".example.MappedChildren",
            ".example.MappedGroups",
            ".example.MappedScalars",
            ".example.MappedEnums",
            // A recursive descriptor walk also visits these synthetic messages.
            ".example.MappedChildren.ValuesEntry",
            ".example.MappedGroups.ValuesEntry",
            ".example.MappedScalars.ValuesEntry",
            ".example.MappedEnums.ValuesEntry",
        ],
    )
    .unwrap();
    // Omit the leading dot so Prost does not apply the presence override to oneof variants.
    prost.field_attribute(
        "example.Container.DetailRequest.storage_request",
        "#[proto_decode(optional)]",
    );
    prost.compile_fds(descriptors).unwrap();
}
