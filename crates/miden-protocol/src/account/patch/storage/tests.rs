use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use std::string::ToString;
use std::sync::LazyLock;

use anyhow::Context;
use assert_matches::assert_matches;

use crate::account::{
    Account,
    AccountCode,
    AccountId,
    AccountPatch,
    AccountStorage,
    AccountStoragePatch,
    AccountVaultPatch,
    StorageMapKey,
    StorageMapPatch,
    StorageMapPatchEntries,
    StorageSlot,
    StorageSlotName,
    StorageSlotPatch,
    StorageValuePatch,
};
use crate::asset::AssetVault;
use crate::errors::AccountPatchError;
use crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
use crate::utils::serde::{ByteWriter, Deserializable, DeserializationError, Serializable};
use crate::{Felt, ONE, Word};

static TEST_MAP_ENTRIES: LazyLock<StorageMapPatchEntries> = LazyLock::new(|| {
    StorageMapPatchEntries::from_iters(
        [StorageMapKey::from_array([1, 2, 3, 4])],
        [(StorageMapKey::from_array([5, 6, 7, 8]), Word::from([3, 4, 5, 6u32]))],
    )
});

#[test]
fn account_storage_patch_accessors() {
    let value_slot = StorageSlotName::mock(1);
    let map_slot = StorageSlotName::mock(2);
    let absent_slot = StorageSlotName::mock(3);

    let value = Word::from([1u32, 2, 3, 4]);
    let map_key = StorageMapKey::from_array([10, 11, 12, 13]);
    let map_value = Word::from([5u32, 6, 7, 8]);
    let absent_key = StorageMapKey::from_array([99, 99, 99, 99]);

    let patch = AccountStoragePatch::from_iters(
        [],
        [(value_slot.clone(), value)],
        [(map_slot.clone(), StorageMapPatch::from_iters([], [(map_key, map_value)]))],
    );

    assert_eq!(patch.get_value(&value_slot), Some(value));
    assert_eq!(patch.get_value(&absent_slot), None);

    let map_patch = patch.get_map(&map_slot).unwrap();
    assert_eq!(map_patch.entries().unwrap().as_map().get(&map_key), Some(&map_value));
    assert_eq!(patch.get_map(&absent_slot), None);

    assert_eq!(patch.get_map_value(&map_slot, &map_key), Some(map_value));
    assert_eq!(patch.get_map_value(&map_slot, &absent_key), None);
    assert_eq!(patch.get_map_value(&absent_slot, &map_key), None);
}

#[test]
fn test_is_empty() {
    let storage_patch = AccountStoragePatch::new();
    assert!(storage_patch.is_empty());

    let storage_patch = AccountStoragePatch::from_iters([StorageSlotName::mock(1)], [], []);
    assert!(!storage_patch.is_empty());

    let storage_patch = AccountStoragePatch::from_iters(
        [],
        [(StorageSlotName::mock(2), Word::from([ONE, ONE, ONE, ONE]))],
        [],
    );
    assert!(!storage_patch.is_empty());

    let storage_patch = AccountStoragePatch::from_iters(
        [],
        [],
        [(StorageSlotName::mock(3), StorageMapPatch::from_iters([], []))],
    );
    assert!(!storage_patch.is_empty());
}

#[test]
fn account_storage_patch_deserialize_rejects_duplicate_slot() {
    let slot_name = StorageSlotName::mock(1);
    // Two value slot patches for the same slot name, length-prefixed with a count of 2.
    let mut bytes = Vec::new();
    bytes.push(2u8);
    let value_patch = StorageSlotPatch::Value(StorageValuePatch::Update { value: Word::empty() });
    for _ in 0..2 {
        slot_name.write_into(&mut bytes);
        value_patch.write_into(&mut bytes);
    }

    let err = AccountStoragePatch::read_from_bytes(&bytes).unwrap_err();
    assert_matches!(err, DeserializationError::InvalidValue(err) => {
        assert!(err.contains("assigned to more than one slot patch"))
    });
}

#[test]
fn storage_map_patch_entries_deserialize_rejects_duplicate_key() {
    let key = StorageMapKey::from_array([1, 2, 3, 4]);
    let value = Word::from([5u32, 6, 7, 8]);

    // One cleared entry and one updated entry sharing the same key, each section
    // length-prefixed with a count of 1.
    let mut bytes = Vec::new();
    bytes.write_usize(1);
    key.write_into(&mut bytes);
    bytes.write_usize(1);
    (key, value).write_into(&mut bytes);

    let err = StorageMapPatchEntries::read_from_bytes(&bytes).unwrap_err();
    assert_matches!(err, DeserializationError::InvalidValue(err) => {
        assert!(err.contains("duplicate key"))
    });
}

#[test]
fn from_entries_rejects_duplicate_slot() {
    let slot_name = StorageSlotName::mock(1);
    let err = AccountStoragePatch::from_entries([
        (
            slot_name.clone(),
            StorageSlotPatch::Value(StorageValuePatch::Update { value: Word::empty() }),
        ),
        (
            slot_name.clone(),
            StorageSlotPatch::Value(StorageValuePatch::Update { value: Word::empty() }),
        ),
    ])
    .unwrap_err();
    assert_matches!(err, AccountPatchError::DuplicateStorageSlotName(name) => {
        assert_eq!(name, slot_name)
    });
}

#[test]
fn test_serde_account_storage_patch() -> anyhow::Result<()> {
    for storage_patch in [
        AccountStoragePatch::new(),
        AccountStoragePatch::from_iters([StorageSlotName::mock(1)], [], []),
        AccountStoragePatch::from_iters(
            [],
            [(StorageSlotName::mock(2), Word::from([ONE, ONE, ONE, ONE]))],
            [],
        ),
        AccountStoragePatch::from_iters(
            [],
            [],
            [(StorageSlotName::mock(3), StorageMapPatch::from_iters([], []))],
        ),
    ] {
        let serialized = storage_patch.to_bytes();
        let deserialized = AccountStoragePatch::read_from_bytes(&serialized)?;
        assert_eq!(deserialized, storage_patch);
        assert_eq!(storage_patch.get_size_hint(), serialized.len());
    }

    Ok(())
}

#[rstest::rstest]
#[case::value_create(StorageSlotPatch::Value(StorageValuePatch::Create { value: Word::from([1, 2, 3, 4u32])}))]
#[case::value_update(StorageSlotPatch::Value(StorageValuePatch::Update { value: Word::from([1, 2, 3, 4u32])}))]
#[case::value_remove(StorageSlotPatch::Value(StorageValuePatch::Remove))]
#[case::map_create(StorageSlotPatch::Map(StorageMapPatch::Create { entries: TEST_MAP_ENTRIES.clone() }))]
#[case::map_update(StorageSlotPatch::Map(StorageMapPatch::Update { entries: TEST_MAP_ENTRIES.clone() }))]
#[case::map_remove(StorageSlotPatch::Map(StorageMapPatch::Remove))]
fn test_serde_storage_patch(#[case] slot_patch: StorageSlotPatch) -> anyhow::Result<()> {
    let serialized = slot_patch.to_bytes();
    let deserialized = StorageSlotPatch::read_from_bytes(&serialized)?;
    assert_eq!(deserialized, slot_patch);
    assert_eq!(slot_patch.get_size_hint(), serialized.len());

    Ok(())
}

// MERGE
// --------------------------------------------------------------------------------------------
//
// The merge logic is duplicated verbatim between value slots ([`StorageValuePatch::merge`]) and
// map slots ([`StorageMapPatch::merge`]): the same 3x3 operation matrix and the same errors.
// The tests below deduplicate along both axes:
// - the delta-operation axis via the `#[case]` table (the nine current/incoming transitions),
// - the slot-type axis via `#[values]` (every case is run against both value and map slots).

static TEST_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| StorageSlotName::mock(7));

/// The seed used to build the patch that is merged into. Distinct from [`INCOMING_SEED`] so
/// that assertions can tell which patch's value won.
const CURRENT_SEED: u32 = 1;

/// The seed used to build the patch that is merged in. On every successful merge the incoming
/// value wins, so the expected result is always built from this seed.
const INCOMING_SEED: u32 = 2;

/// A delta operation, abstracting over value and map slots which share the same set.
#[derive(Clone, Copy, Debug)]
enum Op {
    Create,
    Update,
    Remove,
}

/// The kind of slot a patch operates on.
#[derive(Clone, Copy, Debug)]
enum SlotType {
    Value,
    Map,
}

/// The expected outcome of merging two slot patches.
enum Expected {
    /// The merge succeeds, leaving a slot patch with the given operation and the incoming
    /// value.
    Ok(Op),
    /// The merge fails with the error produced by the given variant constructor.
    Err(AccountPatchError),
}

/// Builds map entries holding a single value derived from `seed`.
///
/// The key is fixed so that merging current and incoming entries collides on it, letting the
/// incoming value win - this mirrors how a value slot replaces its value on merge and keeps the
/// expected result identical across slot types.
fn build_map_entries(seed: u32) -> StorageMapPatchEntries {
    StorageMapPatchEntries::from_iter([(
        StorageMapKey::from_array([1, 0, 0, 0]),
        Word::from([seed, 0, 0, 0]),
    )])
}

/// Builds a slot patch of the given type and operation, carrying a value derived from `seed`.
fn build_slot_patch(slot_type: SlotType, op: Op, seed: u32) -> StorageSlotPatch {
    match slot_type {
        SlotType::Value => {
            let value = Word::from([seed, 0, 0, 0]);
            StorageSlotPatch::Value(match op {
                Op::Create => StorageValuePatch::Create { value },
                Op::Update => StorageValuePatch::Update { value },
                Op::Remove => StorageValuePatch::Remove,
            })
        },
        SlotType::Map => StorageSlotPatch::Map(match op {
            Op::Create => StorageMapPatch::Create { entries: build_map_entries(seed) },
            Op::Update => StorageMapPatch::Update { entries: build_map_entries(seed) },
            Op::Remove => StorageMapPatch::Remove,
        }),
    }
}

/// Wraps a single slot patch in an [`AccountStoragePatch`].
fn single_slot_patch(slot_name: StorageSlotName, patch: StorageSlotPatch) -> AccountStoragePatch {
    AccountStoragePatch::from_raw(BTreeMap::from([(slot_name, patch)]))
        .expect("single slot patch is within limits")
}

#[rstest::rstest]
#[case::create_create(
    Op::Create,
    Op::Create,
    Expected::Err(AccountPatchError::StoragePatchMergeDoubleCreate(TEST_SLOT_NAME.clone()))
)]
#[case::create_update(Op::Create, Op::Update, Expected::Ok(Op::Create))]
#[case::create_remove(Op::Create, Op::Remove, Expected::Ok(Op::Remove))]
#[case::update_create(
    Op::Update,
    Op::Create,
    Expected::Err(AccountPatchError::StoragePatchMergeCreateAfterUpdate(TEST_SLOT_NAME.clone()))
)]
#[case::update_update(Op::Update, Op::Update, Expected::Ok(Op::Update))]
#[case::update_remove(Op::Update, Op::Remove, Expected::Ok(Op::Remove))]
#[case::remove_create(Op::Remove, Op::Create, Expected::Ok(Op::Create))]
#[case::remove_update(
    Op::Remove,
    Op::Update,
    Expected::Err(AccountPatchError::StoragePatchMergeUpdateAfterRemove(TEST_SLOT_NAME.clone()))
)]
#[case::remove_remove(
    Op::Remove,
    Op::Remove,
    Expected::Err(AccountPatchError::StoragePatchMergeDoubleRemove(TEST_SLOT_NAME.clone()))
)]
#[test]
fn merge_slot_patch(
    #[case] current: Op,
    #[case] incoming: Op,
    #[case] expected: Expected,
    #[values(SlotType::Value, SlotType::Map)] slot_type: SlotType,
) -> anyhow::Result<()> {
    let slot_name = TEST_SLOT_NAME.clone();

    let mut current_patch =
        single_slot_patch(slot_name.clone(), build_slot_patch(slot_type, current, CURRENT_SEED));
    let incoming_patch =
        single_slot_patch(slot_name.clone(), build_slot_patch(slot_type, incoming, INCOMING_SEED));

    let result = current_patch.merge(incoming_patch);

    match expected {
        Expected::Ok(resulting_op) => {
            result.context("merge should succeed")?;
            let expected_patch = build_slot_patch(slot_type, resulting_op, INCOMING_SEED);
            assert_eq!(current_patch.get(&slot_name), Some(&expected_patch));
        },
        Expected::Err(expected_err) => {
            let err = result.err().context("merge should fail")?;
            // `AccountPatchError` is not `PartialEq`, so compare the stringified error.
            assert_eq!(err.to_string(), expected_err.to_string());
        },
    }

    Ok(())
}

#[rstest::rstest]
#[case::value_then_map(SlotType::Value, SlotType::Map)]
#[case::map_then_value(SlotType::Map, SlotType::Value)]
#[test]
fn merge_slot_patch_rejects_type_mismatch(
    #[case] current: SlotType,
    #[case] incoming: SlotType,
) -> anyhow::Result<()> {
    let slot_name = TEST_SLOT_NAME.clone();

    let mut current_patch =
        single_slot_patch(slot_name.clone(), build_slot_patch(current, Op::Create, CURRENT_SEED));
    let incoming_patch =
        single_slot_patch(slot_name.clone(), build_slot_patch(incoming, Op::Create, INCOMING_SEED));

    let err = current_patch.merge(incoming_patch).err().context("merge should fail")?;
    assert_matches!(
        err,
        AccountPatchError::StorageSlotUsedAsDifferentTypes(name) => assert_eq!(name, slot_name)
    );

    Ok(())
}

#[test]
fn merge_inserts_disjoint_slots() -> anyhow::Result<()> {
    let value_slot = StorageSlotName::mock(1);
    let map_slot = StorageSlotName::mock(2);

    let value_patch = build_slot_patch(SlotType::Value, Op::Create, CURRENT_SEED);
    let map_patch = build_slot_patch(SlotType::Map, Op::Create, INCOMING_SEED);

    let mut current_patch = single_slot_patch(value_slot.clone(), value_patch.clone());
    current_patch.merge(single_slot_patch(map_slot.clone(), map_patch.clone()))?;

    assert_eq!(current_patch.num_slots(), 2);
    assert_eq!(current_patch.get(&value_slot), Some(&value_patch));
    assert_eq!(current_patch.get(&map_slot), Some(&map_patch));

    Ok(())
}

#[test]
fn merge_map_accumulates_entries() -> anyhow::Result<()> {
    let slot_name = StorageSlotName::mock(3);
    let shared_key = StorageMapKey::from_array([1, 0, 0, 0]);
    let current_only_key = StorageMapKey::from_array([2, 0, 0, 0]);
    let incoming_only_key = StorageMapKey::from_array([3, 0, 0, 0]);

    let incoming_shared_value = Word::from([20u32, 0, 0, 0]);
    let current_only_value = Word::from([11u32, 0, 0, 0]);
    let incoming_only_value = Word::from([21u32, 0, 0, 0]);

    let current_entries = StorageMapPatchEntries::from_iter([
        (shared_key, Word::from([10u32, 0, 0, 0])),
        (current_only_key, current_only_value),
    ]);
    let incoming_entries = StorageMapPatchEntries::from_iter([
        (shared_key, incoming_shared_value),
        (incoming_only_key, incoming_only_value),
    ]);

    let mut current_patch = single_slot_patch(
        slot_name.clone(),
        StorageSlotPatch::Map(StorageMapPatch::Update { entries: current_entries }),
    );
    let incoming_patch = single_slot_patch(
        slot_name.clone(),
        StorageSlotPatch::Map(StorageMapPatch::Update { entries: incoming_entries }),
    );

    current_patch.merge(incoming_patch)?;

    let merged = match current_patch.get(&slot_name) {
        Some(StorageSlotPatch::Map(StorageMapPatch::Update { entries })) => entries.as_map(),
        other => anyhow::bail!("expected an updated map slot, got {other:?}"),
    };

    assert_eq!(merged.len(), 3);
    // The incoming value wins on the shared key, disjoint keys from both sides are kept.
    assert_eq!(merged.get(&shared_key), Some(&incoming_shared_value));
    assert_eq!(merged.get(&current_only_key), Some(&current_only_value));
    assert_eq!(merged.get(&incoming_only_key), Some(&incoming_only_value));

    Ok(())
}

// MERGE-VS-APPLY EQUIVALENCE
// --------------------------------------------------------------------------------------------

/// The slot that the re-creation scenario churns. Already present in the initial account.
static RECREATED_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| StorageSlotName::mock(5));
static ACCOUNT_ID: LazyLock<AccountId> = LazyLock::new(|| {
    AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap()
});

/// Builds an account that already contains [`RECREATED_SLOT`] as a value slot, with nonce 1.
fn initial_account_with_slot() -> anyhow::Result<Account> {
    let storage = AccountStorage::new(Vec::from([StorageSlot::with_value(
        RECREATED_SLOT.clone(),
        Word::from([1, 2, 3, 4u32]),
    )]))?;

    Ok(Account::new_existing(
        *ACCOUNT_ID,
        AssetVault::default(),
        storage,
        AccountCode::mock(),
        ONE,
    ))
}

/// Builds an account that does not contain [`RECREATED_SLOT`], with nonce 1.
fn initial_account_without_slot() -> anyhow::Result<Account> {
    Ok(Account::new_existing(
        *ACCOUNT_ID,
        AssetVault::default(),
        AccountStorage::new(Vec::new())?,
        AccountCode::mock(),
        ONE,
    ))
}

/// Wraps a single value-slot patch in an [`AccountPatch`] carrying the given final nonce.
fn value_slot_account_patch(
    value_patch: StorageValuePatch,
    final_nonce: u32,
) -> anyhow::Result<AccountPatch> {
    let storage = single_slot_patch(RECREATED_SLOT.clone(), StorageSlotPatch::Value(value_patch));

    Ok(AccountPatch::new(
        *ACCOUNT_ID,
        storage,
        AccountVaultPatch::default(),
        None,
        Some(Felt::from(final_nonce)),
    )?)
}

/// Applying remove / create individually must yield the same account as applying their merge in one
/// shot.
///
/// The slot already exists in the initial account, so the first `Create` re-creates an existing
/// slot. This should be allowed and behave as removal followed by creation; otherwise the two paths
/// diverge (or error) instead of converging on the same account.
#[test]
fn merge_then_apply_equals_apply_individually_for_recreated_slot() -> anyhow::Result<()> {
    let patches = [
        value_slot_account_patch(StorageValuePatch::Remove, 3)?,
        value_slot_account_patch(
            StorageValuePatch::Create { value: Word::from([30u32, 0, 0, 0]) },
            4,
        )?,
    ];

    // Path A: apply each patch to the initial account in order.
    let mut account_a = initial_account_with_slot()?;
    for patch in patches.clone() {
        account_a.apply_patch(&patch)?;
    }

    // Path B: merge patches first, then apply the single merged patch.
    let [mut merged, second] = patches;
    merged.merge(second)?;

    let mut account_b = initial_account_with_slot()?;
    account_b.apply_patch(&merged)?;

    assert_eq!(account_a, account_b);

    Ok(())
}

/// Applying create / remove individually must yield the same account as applying their merge in one
/// shot.
///
/// The slot is absent from the initial account, so `(Create, Remove)` merges to a single `Remove`
/// that is applied to a base state which never had the slot. This relies on removing an absent slot
/// being a no-op.
#[test]
fn merge_then_apply_equals_apply_individually_for_created_then_removed_slot() -> anyhow::Result<()>
{
    let patches = [
        value_slot_account_patch(
            StorageValuePatch::Create { value: Word::from([30u32, 0, 0, 0]) },
            2,
        )?,
        value_slot_account_patch(StorageValuePatch::Remove, 3)?,
    ];

    // Path A: apply each patch to the initial account in order.
    let mut account_a = initial_account_without_slot()?;
    for patch in patches.clone() {
        account_a.apply_patch(&patch)?;
    }

    // Path B: merge patches first, then apply the single merged patch.
    let [mut merged, second] = patches;
    merged.merge(second)?;

    let mut account_b = initial_account_without_slot()?;
    account_b.apply_patch(&merged)?;

    assert_eq!(account_a, account_b);

    Ok(())
}

/// Builds a map of `num_slots` distinct value slot patches.
fn distinct_value_patches(num_slots: usize) -> BTreeMap<StorageSlotName, StorageSlotPatch> {
    (0..num_slots)
        .map(|index| {
            (
                StorageSlotName::mock(index),
                StorageSlotPatch::Value(StorageValuePatch::Create { value: Word::empty() }),
            )
        })
        .collect()
}

#[test]
fn from_raw_rejects_too_many_patches() -> anyhow::Result<()> {
    let num_slots = AccountStorage::MAX_NUM_STORAGE_SLOTS + 1;
    let patches = distinct_value_patches(num_slots);

    let err = AccountStoragePatch::from_raw(patches)
        .err()
        .context("from_raw should reject too many patches")?;
    assert_matches!(
        err,
        AccountPatchError::TooManyStorageSlotPatches(count) => assert_eq!(count, num_slots)
    );

    Ok(())
}

#[test]
fn merge_rejects_exceeding_max_patches() -> anyhow::Result<()> {
    // A patch with the maximum number of slots is still valid.
    let mut current_patch = AccountStoragePatch::from_raw(distinct_value_patches(
        AccountStorage::MAX_NUM_STORAGE_SLOTS,
    ))?;

    // Merging a single, disjoint slot pushes the total over the limit.
    let incoming_patch = single_slot_patch(
        StorageSlotName::mock(AccountStorage::MAX_NUM_STORAGE_SLOTS),
        StorageSlotPatch::Value(StorageValuePatch::Create { value: Word::empty() }),
    );

    let err = current_patch.merge(incoming_patch).err().context("merge should fail")?;
    assert_matches!(
        err,
        AccountPatchError::TooManyStorageSlotPatches(count) => {
            assert_eq!(count, AccountStorage::MAX_NUM_STORAGE_SLOTS + 1)
        }
    );

    Ok(())
}
