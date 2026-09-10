use std::borrow::ToOwned;
use std::collections::BTreeSet;
use std::string::String;
use std::vec::Vec;
use std::{format, io};

use proc_macro_crate::{FoundCrate, crate_name};
use prost_types::field_descriptor_proto::Type;
use prost_types::{DescriptorProto, FileDescriptorSet};

const OPTIONAL_ATTRIBUTE: &str = "#[proto_decode(optional)]";

/// Generates schema-shaped decoded records without any domain constructor configuration.
///
/// Each selected message derives `ProtoDecodeFields`. Explicitly optional message fields are
/// preserved using the descriptor metadata that Prost's attributes omit. Nested message types
/// must also derive `ProtoDecodeFields` or implement `DecodeMessage` as an atomic adapter.
/// Real oneofs also derive decoded enums; their exact wire variant names are injected from the
/// descriptors. Synthetic oneofs used for explicit optional fields are not configured as enums.
/// The derive path is resolved from the consumer's Cargo dependencies, including renamed and
/// workspace-inherited dependencies. The runtime dependency must enable its `derive` feature.
pub fn configure_proto_decode_fields<'a>(
    prost: &mut prost_build::Config,
    descriptors: &FileDescriptorSet,
    messages: impl IntoIterator<Item = &'a str>,
) -> Result<(), io::Error> {
    let runtime = match crate_name("miden-protobuf").map_err(io::Error::other)? {
        FoundCrate::Itself => "crate".to_owned(),
        FoundCrate::Name(name) => format!("::{name}"),
    };
    let derive = format!("#[derive({runtime}::ProtoDecodeFields)]");
    let mut configured = BTreeSet::new();
    for message in messages {
        let canonical_name = message.strip_prefix('.').unwrap_or(message);
        if !configured.insert(canonical_name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("duplicate ProtoDecodeFields message `{canonical_name}`"),
            ));
        }
        let optional_fields = explicit_optional_message_fields(descriptors, message)?;
        let descriptor = lookup_message(descriptors, canonical_name)
            .expect("optional field lookup already validated the message");
        for (index, oneof) in descriptor.oneof_decl.iter().enumerate() {
            let variants: Vec<_> = descriptor
                .field
                .iter()
                .filter(|field| field.oneof_index == Some(index as i32) && !field.proto3_optional())
                .collect();
            if variants.is_empty() {
                continue;
            }
            let path = format!("{canonical_name}.{}", oneof.name());
            prost.enum_attribute(&path, &derive);
            for variant in variants {
                prost.field_attribute(
                    format!(".{path}.{}", variant.name()),
                    format!("#[proto_decode(name = {:?})]", variant.name()),
                );
            }
        }
        // A leading dot would also apply the derive to nested message declarations.
        prost.message_attribute(canonical_name, &derive);
        for field in optional_fields {
            prost.field_attribute(field, OPTIONAL_ATTRIBUTE);
        }
    }
    Ok(())
}

fn lookup_message<'a>(
    descriptors: &'a FileDescriptorSet,
    name: &str,
) -> Option<&'a DescriptorProto> {
    fn find<'a>(
        message: &'a DescriptorProto,
        parent: &str,
        target: &str,
    ) -> Option<&'a DescriptorProto> {
        let path = if parent.is_empty() {
            message.name().to_owned()
        } else {
            format!("{parent}.{}", message.name())
        };
        if path == target {
            return Some(message);
        }
        message.nested_type.iter().find_map(|nested| find(nested, &path, target))
    }
    descriptors.file.iter().find_map(|file| {
        file.message_type.iter().find_map(|message| find(message, file.package(), name))
    })
}

fn explicit_optional_message_fields(
    descriptors: &FileDescriptorSet,
    message_name: &str,
) -> Result<Vec<String>, io::Error> {
    let message_name = message_name.strip_prefix('.').unwrap_or(message_name);

    for file in &descriptors.file {
        let package = file.package.as_deref().unwrap_or_default();
        for message in &file.message_type {
            if let Some(fields) = find_message(message, package, message_name) {
                return Ok(fields);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("ProtoDecode message `{message_name}` is missing from the descriptor set"),
    ))
}

fn find_message(
    message: &DescriptorProto,
    parent_name: &str,
    target_name: &str,
) -> Option<Vec<String>> {
    let name = message.name.as_deref()?;
    let message_name = if parent_name.is_empty() {
        name.to_owned()
    } else {
        format!("{parent_name}.{name}")
    };

    if message_name == target_name {
        let fields = message
            .field
            .iter()
            .filter(|field| {
                field.proto3_optional == Some(true) && field.r#type == Some(Type::Message as i32)
            })
            .filter_map(|field| field.name.as_deref())
            .map(|field_name| format!(".{message_name}.{field_name}"))
            .collect();
        return Some(fields);
    }

    message
        .nested_type
        .iter()
        .find_map(|nested| find_message(nested, &message_name, target_name))
}

#[cfg(test)]
mod tests {
    use std::vec;

    use prost_types::field_descriptor_proto::Label;
    use prost_types::{FieldDescriptorProto, FileDescriptorProto, OneofDescriptorProto};

    use super::*;
    #[test]
    fn finds_only_explicitly_optional_message_fields() {
        let descriptors = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                package: Some("example".to_owned()),
                message_type: vec![DescriptorProto {
                    name: Some("Container".to_owned()),
                    field: vec![
                        field("implicit_message", Type::Message, false),
                        field("explicit_message", Type::Message, true),
                        field("explicit_scalar", Type::Uint32, true),
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        assert_eq!(
            explicit_optional_message_fields(&descriptors, ".example.Container").unwrap(),
            [".example.Container.explicit_message"]
        );
    }

    #[test]
    fn finds_nested_messages_by_fully_qualified_name() {
        let descriptors = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                package: Some("example".to_owned()),
                message_type: vec![DescriptorProto {
                    name: Some("Outer".to_owned()),
                    nested_type: vec![DescriptorProto {
                        name: Some("Inner".to_owned()),
                        field: vec![field("value", Type::Message, true)],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        assert_eq!(
            explicit_optional_message_fields(&descriptors, ".example.Outer.Inner").unwrap(),
            [".example.Outer.Inner.value"]
        );
    }

    #[test]
    fn decoded_records_preserve_optional_metadata_without_domain_configuration() {
        let descriptors = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("optional.proto".to_owned()),
                package: Some("example".to_owned()),
                syntax: Some("proto3".to_owned()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("Value".to_owned()),
                        ..Default::default()
                    },
                    message_with_explicit_optional_field("Selected"),
                    message_with_explicit_optional_field("Unselected"),
                ],
                ..Default::default()
            }],
        };
        let out_dir =
            std::env::temp_dir().join(format!("miden-protobuf-fields-test-{}", std::process::id()));
        std::fs::create_dir_all(&out_dir).unwrap();
        let mut prost = prost_build::Config::new();
        prost.out_dir(&out_dir);
        configure_proto_decode_fields(&mut prost, &descriptors, [".example.Selected"]).unwrap();
        prost.compile_fds(descriptors.clone()).unwrap();

        let generated = std::fs::read_to_string(out_dir.join("example.rs")).unwrap();
        let selected = generated.find("pub struct Selected").unwrap();
        let unselected = generated.find("pub struct Unselected").unwrap();
        let marker = generated.find(OPTIONAL_ATTRIBUTE).unwrap();
        assert!(selected < marker && marker < unselected);
        assert_eq!(generated.matches(OPTIONAL_ATTRIBUTE).count(), 1);
        assert_eq!(generated.matches("crate::ProtoDecodeFields").count(), 2);
        assert_eq!(generated.matches("#[proto_decode(name = \"choice\")]").count(), 1);
        assert!(!generated.contains("constructor"));

        let duplicate = configure_proto_decode_fields(
            &mut prost_build::Config::new(),
            &descriptors,
            ["example.Selected", ".example.Selected"],
        )
        .unwrap_err();
        assert_eq!(duplicate.kind(), io::ErrorKind::InvalidInput);
        let missing = configure_proto_decode_fields(
            &mut prost_build::Config::new(),
            &descriptors,
            [".example.Missing"],
        )
        .unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::InvalidInput);
        std::fs::remove_dir_all(out_dir).unwrap();
    }

    fn field(name: &str, field_type: Type, proto3_optional: bool) -> FieldDescriptorProto {
        FieldDescriptorProto {
            name: Some(name.to_owned()),
            r#type: Some(field_type as i32),
            proto3_optional: Some(proto3_optional),
            ..Default::default()
        }
    }

    fn message_with_explicit_optional_field(name: &str) -> DescriptorProto {
        DescriptorProto {
            name: Some(name.to_owned()),
            nested_type: vec![DescriptorProto {
                name: Some("Nested".to_owned()),
                ..Default::default()
            }],
            field: vec![
                FieldDescriptorProto {
                    name: Some("value".to_owned()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Message as i32),
                    type_name: Some(".example.Value".to_owned()),
                    oneof_index: Some(0),
                    proto3_optional: Some(true),
                    ..Default::default()
                },
                FieldDescriptorProto {
                    name: Some("choice".to_owned()),
                    number: Some(2),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Uint32 as i32),
                    oneof_index: Some(1),
                    ..Default::default()
                },
            ],
            oneof_decl: vec![
                OneofDescriptorProto {
                    name: Some("_value".to_owned()),
                    ..Default::default()
                },
                OneofDescriptorProto {
                    name: Some("choice".to_owned()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }
}
