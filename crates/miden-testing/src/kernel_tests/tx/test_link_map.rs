use alloc::vec::Vec;
use std::collections::BTreeMap;
use std::string::String;

use anyhow::Context;
use miden_processor::{ONE, ZERO};
use miden_protocol::{EMPTY_WORD, LexicographicWord, Word};
use miden_tx::{LinkMap, MemoryViewer};
use rand::seq::IteratorRandom;
use winter_rand_utils::rand_value;

use crate::TransactionContextBuilder;

/// Tests the following properties:
/// - Insertion into an empty map.
/// - Insertion after an existing entry.
/// - Insertion in between two existing entries.
/// - Insertion before an existing head.
#[tokio::test]
async fn insertion() -> anyhow::Result<()> {
    let map_ptr = 8u32;
    // check that using an empty word as key is fine
    let entry0_key = Word::from([0, 0, 0, 0u32]);
    let entry0_value = Word::from([1, 2, 3, 4u32]);
    let entry1_key = Word::from([1, 2, 1, 1u32]);
    let entry1_value = Word::from([3, 4, 5, 6u32]);
    let entry2_key = Word::from([1, 3, 1, 1u32]);
    // check that using an empty word as value is fine
    let entry2_value = Word::from([0, 0, 0, 0u32]);
    let entry3_key = Word::from([1, 4, 1, 1u32]);
    let entry3_value = Word::from([5, 6, 7, 8u32]);

    let code = format!(
        r#"
      use $kernel::link_map

      const MAP_PTR={map_ptr}

      begin
          # Insert key {entry1_key} into an empty map.
          # ---------------------------------------------------------------------------------------

          # value
          padw push.{entry1_value}
          # key
          push.{entry1_key}
          push.MAP_PTR
          # => [map_ptr, KEY, VALUE]

          exec.link_map::set
          # => [is_new_key]
          assert.err="{entry1_key} should be a new key in the map"
          # => []

          # Insert key {entry3_key} after the previous one.
          # ---------------------------------------------------------------------------------------

          # value
          padw push.{entry3_value}
          # key
          push.{entry3_key}
          push.MAP_PTR
          # => [map_ptr, KEY, VALUE]

          exec.link_map::set
          # => [is_new_key]
          assert.err="{entry3_key} should be a new key in the map"
          # => []

          # Insert key {entry2_key} in between the first two.
          # ---------------------------------------------------------------------------------------

          # value
          padw push.{entry2_value}
          # key
          push.{entry2_key}
          push.MAP_PTR
          # => [map_ptr, KEY, VALUE]

          exec.link_map::set
          # => [is_new_key]
          assert.err="{entry2_key} should be a new key in the map"
          # => []

          # Insert key {entry0_key} at the head of the map.
          # ---------------------------------------------------------------------------------------

          # value
          padw push.{entry0_value}
          # key
          push.{entry0_key}
          push.MAP_PTR
          # => [map_ptr, KEY, VALUE]

          exec.link_map::set
          # => [is_new_key]
          assert.err="{entry0_key} should be a new key in the map"
          # => []

          # Fetch value at key {entry0_key}.
          # ---------------------------------------------------------------------------------------

          # key
          push.{entry0_key}
          push.MAP_PTR
          # => [map_ptr, KEY]

          exec.link_map::get
          # => [contains_key, VALUE0, VALUE1]
          assert.err="value for key {entry0_key} should exist"

          push.{entry0_value}
          assert_eqw.err="retrieved value0 for key {entry0_key} should be the previously inserted value"
          padw
          assert_eqw.err="retrieved value1 for key {entry0_key} should be an empty word"
          # => []

          # Fetch value at key {entry1_key}.
          # ---------------------------------------------------------------------------------------

          # key
          push.{entry1_key}
          push.MAP_PTR
          # => [map_ptr, KEY]

          exec.link_map::get
          # => [contains_key, VALUE0, VALUE1]
          assert.err="value for key {entry1_key} should exist"

          push.{entry1_value}
          assert_eqw.err="retrieved value0 for key {entry1_key} should be the previously inserted value"
          padw
          assert_eqw.err="retrieved value1 for key {entry1_key} should be an empty word"
          # => []

          # Fetch value at key {entry2_key}.
          # ---------------------------------------------------------------------------------------

          # key
          push.{entry2_key}
          push.MAP_PTR
          # => [map_ptr, KEY]

          exec.link_map::get
          # => [contains_key, VALUE0, VALUE1]
          assert.err="value for key {entry2_key} should exist"

          push.{entry2_value}
          assert_eqw.err="retrieved value0 for key {entry2_key} should be the previously inserted value"
          padw
          assert_eqw.err="retrieved value1 for key {entry2_key} should be an empty word"
          # => []

          # Fetch value at key {entry3_key}.
          # ---------------------------------------------------------------------------------------

          # key
          push.{entry3_key}
          push.MAP_PTR
          # => [map_ptr, KEY]

          exec.link_map::get
          # => [contains_key, VALUE0, VALUE1]
          assert.err="value for key {entry3_key} should exist"

          push.{entry3_value}
          assert_eqw.err="retrieved value0 for key {entry3_key} should be the previously inserted value"
          padw
          assert_eqw.err="retrieved value1 for key {entry3_key} should be an empty word"
          # => []
      end
    "#
    );

    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let exec_output = tx_context.execute_code(&code).await.context("failed to execute code")?;
    let mem_viewer = MemoryViewer::ExecutionOutputs(&exec_output);

    let map = LinkMap::new(map_ptr.into(), &mem_viewer);
    let mut map_iter = map.iter();

    let entry0 = map_iter.next().expect("map should have four entries");
    let entry1 = map_iter.next().expect("map should have four entries");
    let entry2 = map_iter.next().expect("map should have four entries");
    let entry3 = map_iter.next().expect("map should have four entries");
    assert!(map_iter.next().is_none(), "map should only have four entries");

    assert_eq!(entry0.metadata.map_ptr, map_ptr);
    assert_eq!(entry0.metadata.prev_entry_ptr, 0);
    assert_eq!(entry0.metadata.next_entry_ptr, entry1.ptr);
    assert_eq!(Word::from(entry0.key), entry0_key);
    assert_eq!(entry0.value0, entry0_value);
    assert_eq!(entry0.value1, EMPTY_WORD);

    assert_eq!(entry1.metadata.map_ptr, map_ptr);
    assert_eq!(entry1.metadata.prev_entry_ptr, entry0.ptr);
    assert_eq!(entry1.metadata.next_entry_ptr, entry2.ptr);
    assert_eq!(Word::from(entry1.key), entry1_key);
    assert_eq!(entry1.value0, entry1_value);
    assert_eq!(entry1.value1, EMPTY_WORD);

    assert_eq!(entry2.metadata.map_ptr, map_ptr);
    assert_eq!(entry2.metadata.prev_entry_ptr, entry1.ptr);
    assert_eq!(entry2.metadata.next_entry_ptr, entry3.ptr);
    assert_eq!(Word::from(entry2.key), entry2_key);
    assert_eq!(entry2.value0, entry2_value);
    assert_eq!(entry2.value1, EMPTY_WORD);

    assert_eq!(entry3.metadata.map_ptr, map_ptr);
    assert_eq!(entry3.metadata.prev_entry_ptr, entry2.ptr);
    assert_eq!(entry3.metadata.next_entry_ptr, 0);
    assert_eq!(Word::from(entry3.key), entry3_key);
    assert_eq!(entry3.value0, entry3_value);
    assert_eq!(entry3.value1, EMPTY_WORD);

    Ok(())
}

#[tokio::test]
async fn insert_and_update() -> anyhow::Result<()> {
    const MAP_PTR: u32 = 8;

    let value0 = Word::from([1, 2, 3, 4u32]);
    let value1 = Word::from([2, 3, 4, 5u32]);
    let value2 = Word::from([3, 4, 5, 6u32]);

    let operations = vec![
        TestOperation::set(MAP_PTR, link_map_key([1, 0, 0, 0]), (value0, value1)),
        TestOperation::set(MAP_PTR, link_map_key([3, 0, 0, 0]), (value1, value2)),
        TestOperation::set(MAP_PTR, link_map_key([2, 0, 0, 0]), (value2, value1)),
        // This key is updated.
        TestOperation::set(MAP_PTR, link_map_key([1, 0, 0, 0]), (value1, value1)),
        // This key is updated (even though its value is the same).
        TestOperation::set(MAP_PTR, link_map_key([3, 0, 0, 0]), (value1, value2)),
    ];

    execute_link_map_test(operations).await
}

#[tokio::test]
async fn insert_at_head() -> anyhow::Result<()> {
    const MAP_PTR: u32 = 8;

    let key3 = link_map_key([3, 0, 0, 0]);
    let key2 = link_map_key([2, 0, 0, 0]);
    let key1 = link_map_key([1, 0, 0, 0]);
    let value0 = Word::from([1, 2, 3, 4u32]);
    let value1 = Word::from([2, 3, 4, 5u32]);
    let value2 = Word::from([3, 4, 5, 6u32]);

    let operations = vec![
        TestOperation::set(MAP_PTR, key3, (value1, value0)),
        // These keys are smaller than the existing one, so the head of the map is updated.
        TestOperation::set(MAP_PTR, key2, (value2, value0)),
        TestOperation::set(MAP_PTR, key1, (value1, value2)),
        TestOperation::get(MAP_PTR, key1),
        TestOperation::get(MAP_PTR, key2),
        TestOperation::get(MAP_PTR, key3),
    ];

    execute_link_map_test(operations).await
}

/// Tests that a get before a set results in the expected returned values and behavior.
#[tokio::test]
async fn get_before_set() -> anyhow::Result<()> {
    const MAP_PTR: u32 = 8;

    let key0 = link_map_key([3, 0, 0, 0]);
    let value0 = Word::from([1, 2, 3, 4u32]);
    let value1 = Word::from([2, 3, 4, 5u32]);

    let operations = vec![
        TestOperation::get(MAP_PTR, key0),
        TestOperation::set(MAP_PTR, key0, (value1, value0)),
        TestOperation::get(MAP_PTR, key0),
    ];

    execute_link_map_test(operations).await
}

#[tokio::test]
async fn multiple_link_maps() -> anyhow::Result<()> {
    const MAP_PTR0: u32 = 8;
    const MAP_PTR1: u32 = 12;

    let key3 = link_map_key([3, 0, 0, 0]);
    let key2 = link_map_key([2, 0, 0, 0]);
    let key1 = link_map_key([1, 0, 0, 0]);
    let value0 = Word::from([1, 2, 3, 4u32]);
    let value1 = Word::from([2, 3, 4, 5u32]);
    let value2 = Word::from([3, 4, 5, 6u32]);

    let operations = vec![
        TestOperation::set(MAP_PTR0, key3, (value0, value2)),
        TestOperation::set(MAP_PTR0, key2, (value1, value2)),
        TestOperation::set(MAP_PTR1, key1, (value2, value2)),
        TestOperation::set(MAP_PTR1, key3, (value0, value2)),
        // Note that not all keys that we fetch have been inserted, but that is intentional.
        TestOperation::get(MAP_PTR0, key1),
        TestOperation::get(MAP_PTR0, key2),
        TestOperation::get(MAP_PTR0, key3),
        TestOperation::get(MAP_PTR1, key1),
        TestOperation::get(MAP_PTR1, key2),
        TestOperation::get(MAP_PTR1, key3),
    ];

    execute_link_map_test(operations).await
}

#[tokio::test]
async fn iteration() -> anyhow::Result<()> {
    const MAP_PTR: u32 = 12;

    let entries = generate_entries(100);

    // Insert all entries into the map.
    let set_ops = generate_set_ops(MAP_PTR, &entries);
    // Fetch all values and ensure they are as expected.
    let get_ops = generate_get_ops(MAP_PTR, &entries);

    let mut test_operations = set_ops;
    test_operations.extend(get_ops);
    // Iterate the map.
    test_operations.push(TestOperation::iter(MAP_PTR));

    execute_link_map_test(test_operations).await
}

#[tokio::test]
async fn set_update_get_random_entries() -> anyhow::Result<()> {
    const MAP_PTR: u32 = 12;

    let entries = generate_entries(1000);
    let absent_entries = generate_entries(500);
    let update_ops = generate_updates(&entries, 200);

    // Insert all entries into the map.
    let set_ops = generate_set_ops(MAP_PTR, &entries);
    // Fetch all values and ensure they are as expected.
    let get_ops = generate_get_ops(MAP_PTR, &entries);
    // Update a few of the existing keys.
    let set_update_ops = generate_set_ops(MAP_PTR, &update_ops);
    // Fetch all values and ensure they are as expected, in particular the updated ones.
    let get_ops2 = generate_get_ops(MAP_PTR, &entries);

    // Fetch values for entries that are (most likely) absent.
    // Note that the link map test will simply assert that the link map returns whatever the
    // BTreeMap returns, so whether they actually exist or not does not matter for the correctness
    // of the test.
    let get_ops3 = generate_get_ops(MAP_PTR, &absent_entries);

    let mut test_operations = set_ops;
    test_operations.extend(get_ops);
    test_operations.extend(set_update_ops);
    test_operations.extend(get_ops2);
    test_operations.extend(get_ops3);

    execute_link_map_test(test_operations).await
}

// TEST HELPERS
// ================================================================================================

fn link_map_key(elements: [u32; 4]) -> LexicographicWord {
    LexicographicWord::from(Word::from(elements))
}

enum TestOperation {
    Set {
        map_ptr: u32,
        key: LexicographicWord,
        value0: Word,
        value1: Word,
    },
    Get {
        map_ptr: u32,
        key: LexicographicWord,
    },
    Iter {
        map_ptr: u32,
    },
}

impl TestOperation {
    pub fn set(map_ptr: u32, key: LexicographicWord, values: (Word, Word)) -> Self {
        Self::Set {
            map_ptr,
            key,
            value0: values.0,
            value1: values.1,
        }
    }
    pub fn get(map_ptr: u32, key: LexicographicWord) -> Self {
        Self::Get { map_ptr, key }
    }
    pub fn iter(map_ptr: u32) -> Self {
        Self::Iter { map_ptr }
    }
}

async fn execute_link_map_test(operations: Vec<TestOperation>) -> anyhow::Result<()> {
    let mut test_code = String::new();
    let mut control_maps: BTreeMap<u32, BTreeMap<LexicographicWord, (Word, Word)>> =
        BTreeMap::new();

    for operation in operations {
        match operation {
            TestOperation::Set { map_ptr, key, value0, value1 } => {
                let control_map: &mut BTreeMap<_, _> = control_maps.entry(map_ptr).or_default();
                let is_new_key = control_map.insert(key, (value0, value1)).is_none();

                let set_code = format!(
                    r#"
                  push.{value1} push.{value0} push.{key} push.{map_ptr}
                  # => [map_ptr, KEY, VALUE]
                  exec.link_map::set
                  # => [is_new_key]
                  push.{expected_is_new_key}
                  assert_eq.err="is_new_key returned by link_map::set for {key} did not match expected value {expected_is_new_key}"
                "#,
                    key = Word::from(key),
                    value0 = value0,
                    value1 = value1,
                    expected_is_new_key = is_new_key as u8,
                );

                test_code.push_str(&set_code);
            },
            TestOperation::Get { map_ptr, key } => {
                let control_map: &mut BTreeMap<_, _> = control_maps.entry(map_ptr).or_default();
                let control_value = control_map.get(&key);

                let (expected_contains_key, (expected_value0, expected_value1)) =
                    match control_value {
                        Some(value) => (true, (value.0, value.1)),
                        None => (false, (Word::empty(), Word::empty())),
                    };

                let get_code = format!(
                    r#"
                  push.{key} push.{map_ptr}
                  # => [map_ptr, KEY]
                  exec.link_map::get
                  # => [contains_key, VALUE0, VALUE1]
                  push.{expected_contains_key}
                  assert_eq.err="contains_key did not match the expected value: {expected_contains_key}"
                  push.{expected_value0}
                  assert_eqw.err="value0 returned from get is not the expected value: {expected_value0}"
                  push.{expected_value1}
                  assert_eqw.err="value1 returned from get is not the expected value: {expected_value1}"
                "#,
                    key = Word::from(key),
                    expected_value0 = expected_value0,
                    expected_value1 = expected_value1,
                    expected_contains_key = expected_contains_key as u8
                );

                test_code.push_str(&get_code);
            },
            TestOperation::Iter { map_ptr } => {
                let control_map: &mut BTreeMap<_, _> = control_maps.entry(map_ptr).or_default();
                let mut control_iter = control_map.iter().peekable();

                // Initialize iteration.
                let mut iter_code = format!(
                    r#"
                push.{map_ptr}
                # => [map_ptr]
                exec.link_map::iter
                # => [has_next, iter]
                push.{control_has_next} assert_eq.err="has_next returned by iter did not match control"
                # => [iter]
              "#,
                    control_has_next = if control_iter.peek().is_some() { ONE } else { ZERO },
                );

                while let Some((control_key, (control_value0, control_value1))) =
                    control_iter.next()
                {
                    iter_code.push_str(&format!(
                        r#"
                      # ======== TEST next_key_double_value ========
                      dup exec.link_map::next_key_double_value
                      # => [KEY, VALUE0, VALUE1, has_next, next_iter0, prev_iter]
                      push.{control_key} assert_eqw.err="next_key_double_value: returned key did not match {control_key}"
                      # => [VALUE0, VALUE1, has_next, next_iter0, prev_iter]
                      push.{control_value0} assert_eqw.err="next_key_double_value: returned value0 did not match {control_value0}"
                      # => [VALUE1, has_next, next_iter0, prev_iter]
                      push.{control_value1} assert_eqw.err="next_key_double_value: returned value0 did not match {control_value1}"
                      # => [has_next, next_iter0, prev_iter]
                      push.{control_has_next} assert_eq.err="next_key_double_value: returned has_next did not match {control_has_next}"
                      # => [next_iter0, prev_iter]

                      # ======== TEST next_key_value ========
                      dup.1 exec.link_map::next_key_value
                      # => [KEY, VALUE0, has_next, next_iter1, next_iter0, prev_iter]
                      push.{control_key} assert_eqw.err="next_key_value: returned key did not match {control_key}"
                      # => [VALUE0, has_next, next_iter1, next_iter0, prev_iter]
                      push.{control_value0} assert_eqw.err="next_key_value: returned value0 did not match {control_value0}"
                      # => [has_next, next_iter1, next_iter0, prev_iter]
                      push.{control_has_next} assert_eq.err="next_key_value: returned has_next did not match {control_has_next}"
                      # => [next_iter1, next_iter0, prev_iter]

                      # ======== TEST next_key ========
                      movup.2 exec.link_map::next_key
                      # => [KEY, has_next, next_iter2, next_iter1, next_iter0]
                      push.{control_key} assert_eqw.err="next_key: returned key did not match {control_key}"
                      push.{control_has_next} assert_eq.err="next_key: returned has_next did not match {control_has_next}"

                      # All next procedures should return the same next iterator.
                      # => [next_iter2, next_iter1, next_iter0]
                      # assert that next_iter2 == next_iter1
                      dup.1 assert_eq.err="next_iter2 and next_iter1 did not match"
                      # => [next_iter1, next_iter0]
                      dup.1 assert_eq.err="next_iter1 and next_iter0 did not match"

                      # => [next_iter]
                  "#,
                        control_key = Word::from(*control_key),
                        control_value0 = *control_value0,
                        control_value1 = *control_value1,
                        control_has_next = if control_iter.peek().is_some() { ONE } else { ZERO },
                    ));
                }

                // Drop the iterator.
                iter_code.push_str("drop");

                test_code.push_str(&iter_code);
            },
        }
    }

    let code = format!(
        r#"
      use $kernel::link_map
      begin
          {test_code}
      end
    "#
    );

    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let exec_output = tx_context.execute_code(&code).await.context("failed to execute code")?;
    let mem_viewer = MemoryViewer::ExecutionOutputs(&exec_output);

    for (map_ptr, control_map) in control_maps {
        let map = LinkMap::new(map_ptr.into(), &mem_viewer);
        let actual_map_len = map.iter().count();
        assert_eq!(
            actual_map_len,
            control_map.len(),
            "size of link map {map_ptr} is different from control map"
        );

        for (
            idx,
            (
                (control_key, (control_value0, control_value1)),
                (actual_key, (actual_value0, actual_value1)),
            ),
        ) in control_map
            .iter()
            .zip(map.iter().map(|entry| (entry.key, (entry.value0, entry.value1))))
            .enumerate()
        {
            assert_eq!(
                actual_key, *control_key,
                "link map {map_ptr}'s key is different from control map's key at index {idx}"
            );
            assert_eq!(
                actual_value0, *control_value0,
                "link map {map_ptr}'s value0 is different from control map's value0 at index {idx}"
            );
            assert_eq!(
                actual_value1, *control_value1,
                "link map {map_ptr}'s value1 is different from control map's value1 at index {idx}"
            );
        }
    }

    Ok(())
}

fn generate_set_ops(
    map_ptr: u32,
    entries: &[(LexicographicWord, (Word, Word))],
) -> Vec<TestOperation> {
    entries
        .iter()
        .map(|(key, values)| TestOperation::set(map_ptr, *key, *values))
        .collect()
}

fn generate_get_ops(
    map_ptr: u32,
    entries: &[(LexicographicWord, (Word, Word))],
) -> Vec<TestOperation> {
    entries.iter().map(|(key, _)| TestOperation::get(map_ptr, *key)).collect()
}

fn generate_entries(count: u64) -> Vec<(LexicographicWord, (Word, Word))> {
    (0..count)
        .map(|_| {
            let key = rand_link_map_key();
            let value0 = rand_value::<Word>();
            let value1 = rand_value::<Word>();
            (key, (value0, value1))
        })
        .collect()
}

fn generate_updates(
    entries: &[(LexicographicWord, (Word, Word))],
    num_updates: usize,
) -> Vec<(LexicographicWord, (Word, Word))> {
    let mut rng = rand::rng();

    entries
        .iter()
        .choose_multiple(&mut rng, num_updates)
        .into_iter()
        .map(|(key, _)| (*key, (rand_value::<Word>(), rand_value::<Word>())))
        .collect()
}

fn rand_link_map_key() -> LexicographicWord {
    LexicographicWord::new(rand_value())
}
