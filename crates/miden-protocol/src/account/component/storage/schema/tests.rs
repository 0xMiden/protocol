use alloc::collections::BTreeMap;

use super::super::{InitStorageData, SchemaType};
use super::{FeltSchema, MapSlotSchema, ValueSlotSchema, WordSchema};
use crate::account::{StorageMap, StorageMapKey, StorageSlotName};
use crate::{Felt, Word};

#[test]
fn map_slot_schema_default_values_returns_map() {
    let word_schema = WordSchema::new_simple(SchemaType::native_word());
    let mut default_values = BTreeMap::new();
    default_values.insert(
        Word::from([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]),
        Word::from([Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13)]),
    );
    let slot = MapSlotSchema::new(
        Some("static map".into()),
        Some(default_values),
        word_schema.clone(),
        word_schema,
    );

    let mut expected = BTreeMap::new();
    expected.insert(
        Word::from([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]),
        Word::from([Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13)]),
    );

    assert_eq!(slot.default_values(), Some(expected));
}

#[test]
fn value_slot_schema_exposes_felt_schema_types() {
    let felt_values = [
        FeltSchema::u8("a"),
        FeltSchema::u16("b"),
        FeltSchema::u32("c"),
        FeltSchema::new_typed(SchemaType::new("felt").unwrap(), "d"),
    ];

    let slot = ValueSlotSchema::new(None, WordSchema::new_value(felt_values));
    let WordSchema::Composite { value } = slot.word() else {
        panic!("expected composite word schema");
    };

    assert_eq!(value[0].felt_type(), SchemaType::u8());
    assert_eq!(value[1].felt_type(), SchemaType::u16());
    assert_eq!(value[2].felt_type(), SchemaType::u32());
    assert_eq!(value[3].felt_type(), SchemaType::new("felt").unwrap());
}

#[test]
fn map_slot_schema_key_and_value_types() {
    let key_schema = WordSchema::new_simple(SchemaType::new("sampling::Key").unwrap());

    let value_schema = WordSchema::new_value([
        FeltSchema::felt("a"),
        FeltSchema::felt("b"),
        FeltSchema::felt("c"),
        FeltSchema::felt("d"),
    ]);

    let slot = MapSlotSchema::new(None, None, key_schema, value_schema);

    assert_eq!(
        slot.key_schema(),
        &WordSchema::new_simple(SchemaType::new("sampling::Key").unwrap())
    );

    let WordSchema::Composite { value } = slot.value_schema() else {
        panic!("expected composite word schema for map values");
    };
    for felt in value.iter() {
        assert_eq!(felt.felt_type(), SchemaType::native_felt());
    }
}

#[test]
fn value_slot_schema_accepts_typed_word_init_value() {
    let slot = ValueSlotSchema::new(None, WordSchema::new_simple(SchemaType::native_word()));
    let slot_name: StorageSlotName = "demo::slot".parse().unwrap();

    let mut init_data = InitStorageData::default();
    init_data.set_value("demo::slot", [1u32, 2, 3, 4]).unwrap();

    let built = slot.try_build_word(&init_data, &slot_name).unwrap();
    let expected = Word::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    assert_eq!(built, expected);
}

#[test]
fn value_slot_schema_accepts_felt_typed_word_init_value() {
    let slot = ValueSlotSchema::new(None, WordSchema::new_simple(SchemaType::u8()));
    let slot_name: StorageSlotName = "demo::u8_word".parse().unwrap();

    let mut init_data = InitStorageData::default();
    init_data.set_value("demo::u8_word", 6u8).unwrap();

    let built = slot.try_build_word(&init_data, &slot_name).unwrap();
    assert_eq!(built, Word::from([Felt::new(6), Felt::new(0), Felt::new(0), Felt::new(0)]));
}

#[test]
fn value_slot_schema_accepts_typed_felt_init_value_in_composed_word() {
    let word = WordSchema::new_value([
        FeltSchema::u8("a"),
        FeltSchema::felt("b").with_default(Felt::new(2)),
        FeltSchema::felt("c").with_default(Felt::new(3)),
        FeltSchema::felt("d").with_default(Felt::new(4)),
    ]);
    let slot = ValueSlotSchema::new(None, word);
    let slot_name: StorageSlotName = "demo::slot".parse().unwrap();

    let mut init_data = InitStorageData::default();
    init_data.set_value("demo::slot.a", 1u8).unwrap();

    let built = slot.try_build_word(&init_data, &slot_name).unwrap();
    assert_eq!(built, Word::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]));
}

#[test]
fn map_slot_schema_accepts_typed_map_init_value() {
    let word_schema = WordSchema::new_simple(SchemaType::native_word());
    let slot = MapSlotSchema::new(None, None, word_schema.clone(), word_schema);
    let slot_name: StorageSlotName = "demo::map".parse().unwrap();

    let mut init_data = InitStorageData::default();
    init_data
        .insert_map_entry("demo::map", [1u32, 0, 0, 0], [10u32, 11, 12, 13])
        .unwrap();

    let built = slot.try_build_map(&init_data, &slot_name).unwrap();
    let expected = StorageMap::with_entries([(
        StorageMapKey::from_array([1, 0, 0, 0]),
        Word::from([Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13)]),
    )])
    .unwrap();
    assert_eq!(built, expected);
}

#[test]
fn map_slot_schema_missing_init_value_defaults_to_empty_map() {
    let word_schema = WordSchema::new_simple(SchemaType::native_word());
    let slot = MapSlotSchema::new(None, None, word_schema.clone(), word_schema);
    let built = slot
        .try_build_map(&InitStorageData::default(), &"demo::map".parse().unwrap())
        .unwrap();
    assert_eq!(built, StorageMap::new());
}
