use std::borrow::ToOwned;
use std::collections::BTreeSet;
use std::string::String;
use std::vec::Vec;
use std::{format, io};

use prost_types::field_descriptor_proto::Type;
use prost_types::{DescriptorProto, FileDescriptorSet};

const OPTIONAL_ATTRIBUTE: &str = "#[proto_decode(optional)]";

/// Structured configuration for a generated `ProtoDecode` implementation.
#[doc(hidden)]
pub struct ProtoDecodeConfig {
    message_name: &'static str,
    target: &'static str,
    constructor: &'static str,
    constructor_kind: ConstructorKind,
}

impl ProtoDecodeConfig {
    #[doc(hidden)]
    pub const fn constructor(
        message_name: &'static str,
        target: &'static str,
        constructor: &'static str,
    ) -> Self {
        Self {
            message_name,
            target,
            constructor,
            constructor_kind: ConstructorKind::Infallible,
        }
    }

    #[doc(hidden)]
    pub const fn try_constructor(
        message_name: &'static str,
        target: &'static str,
        constructor: &'static str,
    ) -> Self {
        Self {
            message_name,
            target,
            constructor,
            constructor_kind: ConstructorKind::Fallible,
        }
    }

    fn derive_attribute(&self) -> String {
        let constructor = match self.constructor_kind {
            ConstructorKind::Infallible => "constructor",
            ConstructorKind::Fallible => "try_constructor",
        };

        format!(
            "#[derive(::miden_protobuf::ProtoDecode)]\n\
             #[proto_decode(target({}), {}({}))]",
            self.target, constructor, self.constructor
        )
    }
}

enum ConstructorKind {
    Infallible,
    Fallible,
}

/// Configures generated messages for `ProtoDecode` and preserves explicitly optional message
/// fields that Prost's Rust attributes cannot distinguish from unlabelled message fields.
pub fn configure_proto_decodes(
    prost: &mut prost_build::Config,
    descriptors: &FileDescriptorSet,
    configs: impl IntoIterator<Item = ProtoDecodeConfig>,
) -> Result<(), io::Error> {
    let mut configured = BTreeSet::new();
    for config in configs {
        let canonical_name = config.message_name.strip_prefix('.').unwrap_or(config.message_name);
        if !configured.insert(canonical_name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("duplicate ProtoDecode message `{canonical_name}`"),
            ));
        }

        prost.type_attribute(config.message_name, config.derive_attribute());

        for field_name in explicit_optional_message_fields(descriptors, config.message_name)? {
            prost.field_attribute(field_name, OPTIONAL_ATTRIBUTE);
        }
    }

    Ok(())
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
    use alloc::string::ToString;
    use std::{format, vec};

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
    fn configure_proto_decodes_injects_the_marker_only_into_the_selected_message() {
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
            std::env::temp_dir().join(format!("miden-protobuf-build-test-{}", std::process::id()));
        std::fs::create_dir_all(&out_dir).unwrap();

        let mut prost = prost_build::Config::new();
        prost.out_dir(&out_dir);
        crate::configure_proto_decodes! {
            prost: &mut prost,
            descriptors: &descriptors,
            ".example.Selected" => {
                target: SelectedTarget,
                constructor: SelectedTarget::new(value),
            },
        }
        .unwrap();
        prost.compile_fds(descriptors).unwrap();

        let generated = std::fs::read_to_string(out_dir.join("example.rs")).unwrap();
        let selected = generated.find("pub struct Selected").unwrap();
        let unselected = generated.find("pub struct Unselected").unwrap();
        let marker = generated.find(OPTIONAL_ATTRIBUTE).unwrap();
        assert!(selected < marker && marker < unselected);
        assert_eq!(generated.matches(OPTIONAL_ATTRIBUTE).count(), 1);

        std::fs::remove_dir_all(out_dir).unwrap();
    }

    #[test]
    fn configure_proto_decodes_rejects_duplicate_messages() {
        let descriptors = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                package: Some("example".to_owned()),
                message_type: vec![DescriptorProto {
                    name: Some("Selected".to_owned()),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let mut prost = prost_build::Config::new();

        let error = crate::configure_proto_decodes! {
            prost: &mut prost,
            descriptors: &descriptors,
            ".example.Selected" => {
                target: SelectedTarget,
                constructor: SelectedTarget::new(),
            },
            "example.Selected" => {
                target: SelectedTarget,
                constructor: SelectedTarget::new(),
            },
        }
        .unwrap_err();

        assert_eq!(error.to_string(), "duplicate ProtoDecode message `example.Selected`");
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
            field: vec![FieldDescriptorProto {
                name: Some("value".to_owned()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".example.Value".to_owned()),
                oneof_index: Some(0),
                proto3_optional: Some(true),
                ..Default::default()
            }],
            oneof_decl: vec![OneofDescriptorProto {
                name: Some("_value".to_owned()),
                ..Default::default()
            }],
            ..Default::default()
        }
    }
}
