use std::collections::BTreeSet;

use miden_objects::{EXTERN_PATHS, FILE_DESCRIPTOR_SET};
use prost::Message;
use prost_types::field_descriptor_proto::Type;
use prost_types::{DescriptorProto, EnumDescriptorProto, FileDescriptorSet};

fn assert_enum_is_dense(scope: &str, enumeration: &EnumDescriptorProto) {
    assert!(
        enumeration.reserved_range.is_empty() && enumeration.reserved_name.is_empty(),
        "{scope}.{} contains reserved enum values",
        enumeration.name()
    );

    let mut numbers = enumeration.value.iter().map(|value| value.number()).collect::<Vec<_>>();
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(
        numbers,
        (0..i32::try_from(numbers.len()).unwrap()).collect::<Vec<_>>(),
        "{scope}.{} does not use dense enum values",
        enumeration.name()
    );
}

fn assert_message_is_dense(scope: &str, message: &DescriptorProto) {
    let name = format!("{scope}.{}", message.name());
    assert!(
        message.reserved_range.is_empty() && message.reserved_name.is_empty(),
        "{name} contains reserved fields"
    );

    let mut numbers = message.field.iter().map(|field| field.number()).collect::<Vec<_>>();
    numbers.sort_unstable();
    assert_eq!(
        numbers,
        (1..=i32::try_from(numbers.len()).unwrap()).collect::<Vec<_>>(),
        "{name} does not use dense field numbers"
    );

    for nested in &message.nested_type {
        assert_message_is_dense(&name, nested);
    }
    for enumeration in &message.enum_type {
        assert_enum_is_dense(&name, enumeration);
    }
}

#[test]
fn descriptor_has_no_reservations_and_uses_dense_numbering() {
    let descriptor = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    for file in descriptor.file {
        let package = file.package();
        for message in &file.message_type {
            assert_message_is_dense(package, message);
        }
        for enumeration in &file.enum_type {
            assert_enum_is_dense(package, enumeration);
        }
    }
}

#[test]
fn every_schema_package_has_an_external_path() {
    let descriptor = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    let packages = descriptor
        .file
        .iter()
        .map(|file| format!(".{}", file.package()))
        .collect::<BTreeSet<_>>();
    let external_packages = EXTERN_PATHS
        .iter()
        .map(|(package, _)| (*package).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(packages, external_packages);
}

#[test]
fn canonical_scalar_wire_types_are_pinned() {
    let descriptor = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    let expected = [
        ("primitives", "Felt", "encoded", 1, Type::Bytes),
        ("primitives", "Word", "encoded", 1, Type::Bytes),
        ("primitives", "ExecutionProof", "encoded", 1, Type::Bytes),
        ("primitives", "MastForest", "encoded", 1, Type::Bytes),
        ("primitives", "MmrDelta", "forest", 1, Type::Uint64),
        ("primitives", "SmtLeaf", "empty_leaf_index", 1, Type::Uint64),
        ("account", "AccountHeader", "nonce", 5, Type::Uint64),
        ("account", "AccountCode", "mast", 1, Type::Message),
        ("note", "NoteAttachment", "scheme", 1, Type::Uint32),
        ("note", "NoteScript", "entrypoint", 1, Type::Uint32),
        ("note", "NoteScript", "mast", 2, Type::Message),
        ("blockchain", "BlockHeader", "version", 1, Type::Uint32),
        ("blockchain", "BlockBody", "contents", 1, Type::Message),
        ("blockchain", "IndexedOutputNote", "note_index_in_batch", 1, Type::Uint32),
        ("transaction", "ProvenTransactionData", "proof", 7, Type::Message),
        ("transaction", "ProvenBatch", "proof", 8, Type::Message),
    ];

    for (package, message_name, field_name, number, field_type) in expected {
        let message = descriptor
            .file
            .iter()
            .filter(|file| file.package() == package)
            .flat_map(|file| &file.message_type)
            .find(|message| message.name() == message_name)
            .unwrap_or_else(|| panic!("missing {package}.{message_name}"));
        let field = message
            .field
            .iter()
            .find(|field| field.name() == field_name)
            .unwrap_or_else(|| panic!("missing {package}.{message_name}.{field_name}"));
        assert_eq!(
            field.number(),
            number,
            "wrong number for {package}.{message_name}.{field_name}"
        );
        assert_eq!(
            field.r#type(),
            field_type,
            "wrong wire type for {package}.{message_name}.{field_name}"
        );
    }
}
