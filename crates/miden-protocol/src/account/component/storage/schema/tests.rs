use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::super::{InitStorageData, SchemaType};
use super::{
    ArraySlotSchema,
    FeltSchema,
    MapSlotSchema,
    StorageSchema,
    StorageSlotSchema,
    ValueSlotSchema,
    WordSchema,
};
#[cfg(feature = "std")]
use crate::account::StorageSlotContent;
#[cfg(feature = "std")]
use crate::account::component::{AccountComponentMetadata, StorageValueName};
use crate::account::{StorageArrayLength, StorageMap, StorageMapKey, StorageSlotName};
use crate::asset::TokenSymbol;
use crate::utils::serde::{Deserializable, Serializable};
use crate::{Felt, Word};

#[test]
fn map_slot_schema_default_values_returns_map() {
    let word_schema = WordSchema::new_simple(SchemaType::native_word());
    let mut default_values = BTreeMap::new();
    default_values.insert(
        Word::from([Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        Word::from([10_u32, 11_u32, 12_u32, 13_u32]),
    );
    let slot = MapSlotSchema::new(
        Some("static map".into()),
        Some(default_values),
        word_schema.clone(),
        word_schema,
    );

    let mut expected = BTreeMap::new();
    expected.insert(
        Word::from([Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        Word::from([10_u32, 11_u32, 12_u32, 13_u32]),
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
    let expected = Word::from([Felt::ONE, Felt::from(2_u32), Felt::from(3_u32), Felt::from(4_u32)]);
    assert_eq!(built, expected);
}

#[test]
fn value_slot_schema_accepts_felt_typed_word_init_value() {
    let slot = ValueSlotSchema::new(None, WordSchema::new_simple(SchemaType::u8()));
    let slot_name: StorageSlotName = "demo::u8_word".parse().unwrap();

    let mut init_data = InitStorageData::default();
    init_data.set_value("demo::u8_word", 6u8).unwrap();

    let built = slot.try_build_word(&init_data, &slot_name).unwrap();
    assert_eq!(built, Word::from([Felt::new_unchecked(6), Felt::ZERO, Felt::ZERO, Felt::ZERO]));
}

#[test]
fn value_slot_schema_accepts_typed_felt_init_value_in_composed_word() {
    let word = WordSchema::new_value([
        FeltSchema::u8("a"),
        FeltSchema::felt("b").with_default(Felt::from(2_u32)),
        FeltSchema::felt("c").with_default(Felt::from(3_u32)),
        FeltSchema::felt("d").with_default(Felt::from(4_u32)),
    ]);
    let slot = ValueSlotSchema::new(None, word);
    let slot_name: StorageSlotName = "demo::slot".parse().unwrap();

    let mut init_data = InitStorageData::default();
    init_data.set_value("demo::slot.a", 1u8).unwrap();

    let built = slot.try_build_word(&init_data, &slot_name).unwrap();
    assert_eq!(
        built,
        Word::from([Felt::ONE, Felt::from(2_u32), Felt::from(3_u32), Felt::from(4_u32)])
    );
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
        Word::from([10_u32, 11_u32, 12_u32, 13_u32]),
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

#[test]
fn word_schema_displays_simple_felt_type() {
    let schema = WordSchema::new_simple(SchemaType::u8());
    let word = Word::from([Felt::new_unchecked(6), Felt::ZERO, Felt::ZERO, Felt::ZERO]);

    assert_eq!(schema.display_word(word), "6");
}

#[test]
fn word_schema_displays_composite_felt_types() {
    let schema = WordSchema::new_value([
        FeltSchema::u8("a"),
        FeltSchema::bool("b"),
        FeltSchema::new_typed(SchemaType::token_symbol(), "c"),
        FeltSchema::felt("d"),
    ]);
    let word = Word::from([
        Felt::new_unchecked(6),
        Felt::ONE,
        Felt::from(TokenSymbol::new("TST").unwrap()),
        Felt::new_unchecked(9),
    ]);

    assert_eq!(schema.display_word(word), "[6, true, TST, 0x9]");
}

#[test]
fn word_schema_displays_hex_for_unregistered_type() {
    let schema = WordSchema::new_simple(SchemaType::new("custom::unknown").unwrap());
    let word = Word::from([1_u32, 2, 3, 4]);

    assert_eq!(schema.display_word(word), word.to_hex());
}

#[test]
fn array_schema_binds_length_and_type_but_not_defaults() -> anyhow::Result<()> {
    let name = StorageSlotName::new("test::array")?;
    let make_schema = |length: usize,
                       word: WordSchema,
                       defaults: Option<Vec<Word>>|
     -> anyhow::Result<StorageSchema> {
        Ok(StorageSchema::new([(
            name.clone(),
            StorageSlotSchema::Array(ArraySlotSchema::new(
                None,
                StorageArrayLength::try_from(length)?,
                word,
                defaults,
            )?),
        )])?)
    };
    let schema = make_schema(
        3,
        WordSchema::new_simple(SchemaType::native_word()),
        Some(vec![Word::empty(); 3]),
    )?;
    let different_defaults = make_schema(
        3,
        WordSchema::new_simple(SchemaType::native_word()),
        Some(vec![Word::from([1u32; 4]); 3]),
    )?;
    assert_eq!(schema.commitment(), different_defaults.commitment());
    assert_ne!(
        schema.commitment(),
        make_schema(2, WordSchema::new_simple(SchemaType::native_word()), None)?.commitment()
    );
    assert_ne!(
        schema.commitment(),
        make_schema(3, WordSchema::new_simple(SchemaType::pub_key()), None)?.commitment()
    );
    assert_eq!(StorageSchema::read_from_bytes(&schema.to_bytes())?, schema);
    Ok(())
}

#[test]
#[cfg(feature = "std")]
fn array_schema_toml_roundtrip_and_initialization() -> anyhow::Result<()> {
    let schema = StorageSchema::new([(
        StorageSlotName::new("test::array")?,
        StorageSlotSchema::Array(ArraySlotSchema::new(
            None,
            StorageArrayLength::try_from(3)?,
            WordSchema::new_simple(SchemaType::native_word()),
            Some(vec![Word::empty(); 3]),
        )?),
    )])?;
    let metadata =
        AccountComponentMetadata::new("test::arrays").with_storage_schema(schema.clone());
    let decoded = AccountComponentMetadata::from_toml(&metadata.to_toml()?)?;
    assert_eq!(decoded.storage_schema(), &schema);
    let init = InitStorageData::from_toml(
        r#""test::array" = { array = [["1", "2", "3", "4"], ["0", "0", "0", "0"], ["5", "6", "7", "8"]] }"#,
    )?;
    let slots = schema.build_storage_slots(&init)?;
    let StorageSlotContent::Array(array) = slots[0].content() else {
        panic!("expected array");
    };
    assert_eq!(array.values()[1], Word::empty());
    let invalid_init =
        InitStorageData::from_toml(r#""test::array" = { array = [["0", "0", "0", "0"]] }"#)?;
    assert!(schema.build_storage_slots(&invalid_init).is_err());
    Ok(())
}

#[test]
fn array_schema_validates_complete_typed_defaults() -> anyhow::Result<()> {
    let length = StorageArrayLength::try_from(2)?;
    let element = WordSchema::new_value([
        FeltSchema::bool("enabled"),
        FeltSchema::u8("count"),
        FeltSchema::new_void(),
        FeltSchema::new_void(),
    ]);
    let valid = Word::from([1u32, 255, 0, 0]);
    let schema = ArraySlotSchema::new(None, length, element.clone(), Some(vec![valid; 2]))?;
    let name = StorageSlotName::new("test::array")?;
    assert_eq!(
        schema.try_build_array(&InitStorageData::default(), &name)?.values(),
        &[valid; 2]
    );
    assert!(ArraySlotSchema::new(None, length, element.clone(), Some(vec![valid])).is_err());
    for invalid in [Word::from([2u32, 0, 0, 0]), Word::from([1u32, 256, 0, 0])] {
        assert!(
            ArraySlotSchema::new(None, length, element.clone(), Some(vec![invalid; 2])).is_err()
        );
    }
    assert!(
        ArraySlotSchema::new(
            None,
            length,
            WordSchema::new_simple_with_default(SchemaType::native_word(), Word::empty()),
            None
        )
        .is_err()
    );
    let mut init = InitStorageData::default();
    init.set_array_values(name.clone(), vec![valid.into(); 2])?;
    assert!(init.insert_value(&name, valid).is_err());
    assert!(init.insert_map_entry(name.clone(), valid, valid).is_err());
    let mut value_init = InitStorageData::default();
    value_init.insert_value(&name, valid)?;
    assert!(schema.try_build_array(&value_init, &name).is_err());
    assert!(value_init.set_array_values(name, vec![valid.into(); 2]).is_err());
    Ok(())
}

#[test]
#[cfg(feature = "std")]
fn array_init_syntax_preserves_a_field_named_array() -> anyhow::Result<()> {
    let init = InitStorageData::from_toml(r#""test::value" = { array = "7" }"#)?;
    let name = StorageSlotName::new("test::value")?;
    assert!(init.array_values(&name).is_none());
    assert!(
        init.value_entry(&StorageValueName::from_slot_name_with_suffix(&name, "array")?)
            .is_some()
    );
    Ok(())
}
