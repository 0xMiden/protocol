use super::*;

#[test]
fn array_commitment_and_serialization() -> anyhow::Result<()> {
    // Odd lengths exercise hash padding; the upper bound must not truncate to a u8.
    for length in [1, 3, 256] {
        let words = (0..length).map(|i| Word::from([i as u32, 0, 0, 0])).collect();
        let array = StorageArray::new(words)?;
        assert_eq!(array.commitment(), Hasher::hash_elements(&array.to_elements()));
        assert_eq!(StorageArray::read_from_bytes(&array.to_bytes())?, array);
    }
    Ok(())
}

#[test]
fn invalid_lengths_are_rejected_before_reading_payload() {
    for length in [0u16, 257, u16::MAX] {
        assert!(StorageArray::new(vec![Word::empty(); usize::from(length)]).is_err());
        assert!(StorageArray::read_from_bytes(&length.to_le_bytes()).is_err());
    }
}

#[test]
fn arrays_survive_full_partial_and_compact_storage_roundtrips() -> anyhow::Result<()> {
    use alloc::collections::BTreeMap;

    use crate::account::{
        AccountStorage,
        AccountStorageHeader,
        PartialStorage,
        StorageSlot,
        StorageSlotName,
        StorageSlotType,
    };
    let name = StorageSlotName::new("test::array")?;
    let array = StorageArray::new(vec![Word::empty(), Word::from([1u32, 2, 3, 4]), Word::empty()])?;
    let storage = AccountStorage::new(vec![StorageSlot::with_array(name.clone(), array.clone())])?;
    assert_eq!(AccountStorage::read_from_bytes(&storage.to_bytes())?, storage);
    let header = storage.to_header();
    assert_eq!(AccountStorageHeader::read_from_bytes(&header.to_bytes())?, header);
    assert_eq!(PartialStorage::new_minimal(&storage).header(), &header);
    let names = BTreeMap::from([(name.id(), name)]);
    assert!(
        AccountStorageHeader::try_from_elements(&header.to_elements(), &names, &BTreeMap::new())
            .is_err()
    );
    let arrays = BTreeMap::from([(array.commitment(), array)]);
    assert_eq!(
        AccountStorageHeader::try_from_elements(&header.to_elements(), &names, &arrays)?,
        header
    );
    for length in [1, 3, 256] {
        let slot_type = StorageSlotType::Array(StorageArrayLength::try_from(length)?);
        assert_eq!(StorageSlotType::try_from(slot_type.as_felt())?, slot_type);
        assert_eq!(StorageSlotType::read_from_bytes(&slot_type.to_bytes())?, slot_type);
    }
    for invalid in [2, 2 + (257 << 32), 1 + (1 << 32), 3 + (1 << 32)] {
        assert!(StorageSlotType::try_from(Felt::new_unchecked(invalid)).is_err());
    }
    Ok(())
}

#[test]
fn array_patches_preserve_zeroes_and_reject_invalid_indices() -> anyhow::Result<()> {
    use crate::account::{StorageArrayPatch, StorageArrayPatchEntries};
    let initial = StorageArray::new(vec![Word::from([1u32; 4]); 3])?;
    let final_array =
        StorageArray::new(vec![Word::empty(), initial.values()[1], Word::from([2u32; 4])])?;
    let entries = StorageArrayPatchEntries::between(&initial, &final_array)?;
    assert_eq!(entries.as_map().keys().copied().collect::<Vec<_>>(), vec![0, 2]);
    assert_eq!(entries.apply(&initial)?, final_array);
    assert!(StorageArrayPatchEntries::new(initial.length(), [(3, Word::empty())]).is_err());
    assert!(StorageArrayPatchEntries::new(initial.length(), [(0, Word::empty()); 2]).is_err());
    assert!(entries.apply(&StorageArray::new(vec![Word::empty()])?).is_err());
    for patch in [
        StorageArrayPatch::Create { array: initial.clone() },
        StorageArrayPatch::Update { entries },
        StorageArrayPatch::Remove { length: initial.length() },
    ] {
        assert_eq!(StorageArrayPatch::read_from_bytes(&patch.to_bytes())?, patch);
    }
    Ok(())
}

#[test]
fn storage_payload_budget_applies_to_final_state_atomically() -> anyhow::Result<()> {
    use crate::account::{
        AccountStorage,
        AccountStoragePatch,
        StorageArrayPatch,
        StorageSlot,
        StorageSlotName,
        StorageSlotPatch,
        StorageValuePatch,
    };
    let name = StorageSlotName::new("test::array")?;
    let other = StorageSlotName::new("test::other")?;
    let array = StorageArray::empty(StorageArrayLength::try_from(256)?);
    let original = AccountStorage::new(vec![StorageSlot::with_array(name.clone(), array.clone())])?;
    assert!(
        AccountStorage::new(vec![
            StorageSlot::with_array(name.clone(), array.clone()),
            StorageSlot::with_empty_value(other.clone())
        ])
        .is_err()
    );
    let mut storage = original.clone();
    let overflowing = AccountStoragePatch::from_entries([(
        other.clone(),
        StorageSlotPatch::Value(StorageValuePatch::Create { value: Word::empty() }),
    )])?;
    assert!(storage.apply_patch(&overflowing).is_err());
    assert_eq!(storage, original);
    let replacement = AccountStoragePatch::from_entries([
        (
            name.clone(),
            StorageSlotPatch::Array(StorageArrayPatch::Remove { length: array.length() }),
        ),
        (
            other.clone(),
            StorageSlotPatch::Array(StorageArrayPatch::Create { array: array.clone() }),
        ),
    ])?;
    storage.apply_patch(&replacement)?;
    assert_eq!(storage.get_array(&other)?, &array);
    assert!(storage.get(&name).is_none());
    // Reverse the slot order, so both possible create/remove traversal orders are covered.
    storage.apply_patch(&AccountStoragePatch::from_entries([
        (
            other,
            StorageSlotPatch::Array(StorageArrayPatch::Remove { length: array.length() }),
        ),
        (name.clone(), StorageSlotPatch::Array(StorageArrayPatch::Create { array })),
    ])?)?;
    assert_eq!(storage, original);
    let before = storage.clone();
    assert!(storage.set_array(&name, StorageArray::new(vec![Word::empty()])?).is_err());
    assert_eq!(storage, before);
    Ok(())
}

#[test]
fn array_patch_merge_matches_sequential_application() -> anyhow::Result<()> {
    use crate::account::{
        AccountStorage,
        AccountStoragePatch,
        StorageArrayPatch,
        StorageArrayPatchEntries,
        StorageSlot,
        StorageSlotName,
        StorageSlotPatch,
    };
    let name = StorageSlotName::new("test::array")?;
    let array = StorageArray::new(vec![Word::from([1u32; 4]); 3])?;
    let create = AccountStoragePatch::from_entries([(
        name.clone(),
        StorageSlotPatch::Array(StorageArrayPatch::Create { array: array.clone() }),
    )])?;
    let update = AccountStoragePatch::from_entries([(
        name.clone(),
        StorageSlotPatch::Array(StorageArrayPatch::Update {
            entries: StorageArrayPatchEntries::new(array.length(), [(1, Word::empty())])?,
        }),
    )])?;
    let remove = AccountStoragePatch::from_entries([(
        name.clone(),
        StorageSlotPatch::Array(StorageArrayPatch::Remove { length: array.length() }),
    )])?;
    let recreate = AccountStoragePatch::from_entries([(
        name.clone(),
        StorageSlotPatch::Array(StorageArrayPatch::Create {
            array: StorageArray::new(vec![Word::empty()])?,
        }),
    )])?;
    let second_update = AccountStoragePatch::from_entries([(
        name.clone(),
        StorageSlotPatch::Array(StorageArrayPatch::Update {
            entries: StorageArrayPatchEntries::new(
                array.length(),
                [(1, Word::from([2u32; 4])), (2, Word::empty())],
            )?,
        }),
    )])?;
    let existing = AccountStorage::new(vec![StorageSlot::with_array(name, array)])?;
    for (initial, patches) in [
        (
            AccountStorage::default(),
            vec![create.clone(), update.clone(), remove.clone(), recreate.clone()],
        ),
        (existing.clone(), vec![update.clone(), second_update, remove.clone()]),
        (existing, vec![remove.clone(), recreate]),
    ] {
        let mut sequential = initial.clone();
        let mut merged = AccountStoragePatch::new();
        for patch in patches {
            sequential.apply_patch(&patch)?;
            merged.merge(patch)?;
            let mut combined = initial.clone();
            combined.apply_patch(&merged)?;
            assert_eq!(combined, sequential);
        }
    }
    for (mut first, second) in [
        (create.clone(), create.clone()),
        (update.clone(), create),
        (remove.clone(), update),
        (remove.clone(), remove),
    ] {
        assert!(first.merge(second).is_err());
    }
    Ok(())
}
