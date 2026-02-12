use alloc::string::ToString;
use alloc::vec;
use std::collections::BTreeMap;
use std::vec::Vec;

use miden_core::utils::{Deserializable, Serializable};

use crate::account::{
    AccountCode,
    AccountHeader,
    AccountId,
    AccountStorageHeader,
    PartialAccount,
    PartialStorage,
    StorageSlotHeader,
    StorageSlotName,
    StorageSlotType,
};
use crate::asset::PartialVault;
use crate::errors::TransactionInputsExtractionError;
use crate::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
};
use crate::transaction::TransactionInputs;
use crate::{Felt, Word};

#[test]
fn test_read_foreign_account_inputs_missing_data() {
    let native_account_id =
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let foreign_account_id =
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2).unwrap();

    // Create minimal transaction inputs with empty advice map.
    let code = AccountCode::mock();
    let storage_header = AccountStorageHeader::new(vec![]).unwrap();
    let partial_storage = PartialStorage::new(storage_header, []).unwrap();
    let partial_vault = PartialVault::new(Word::default());
    let partial_account = PartialAccount::new(
        native_account_id,
        Felt::new(10),
        code,
        partial_storage,
        partial_vault,
        None,
    )
    .unwrap();

    let tx_inputs = TransactionInputs {
        account: partial_account,
        block_header: crate::block::BlockHeader::mock(0, None, None, &[], Word::default()),
        blockchain: crate::transaction::PartialBlockchain::default(),
        input_notes: crate::transaction::InputNotes::new(vec![]).unwrap(),
        tx_args: crate::transaction::TransactionArgs::default(),
        advice_inputs: crate::vm::AdviceInputs::default(),
        foreign_account_code: Vec::new(),
        foreign_account_slot_names: BTreeMap::new(),
    };

    // Try to read foreign account that doesn't exist in advice map.
    let result = tx_inputs.read_foreign_account_inputs(foreign_account_id);

    assert!(
        matches!(result, Err(TransactionInputsExtractionError::ForeignAccountNotFound(id)) if id == foreign_account_id)
    );
}

#[test]
fn test_read_foreign_account_inputs_with_storage_data() {
    use crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2;

    let native_account_id =
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let foreign_account_id =
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2).unwrap();

    // Create minimal transaction inputs with proper advice map.
    let code = AccountCode::mock();
    let storage_header = AccountStorageHeader::new(vec![]).unwrap();
    let partial_storage = PartialStorage::new(storage_header, []).unwrap();
    let partial_vault = PartialVault::new(Word::default());
    let partial_account = PartialAccount::new(
        native_account_id,
        Felt::new(10),
        code.clone(),
        partial_storage,
        partial_vault,
        None,
    )
    .unwrap();

    // Create foreign account header and storage data.
    let foreign_header = AccountHeader::new(
        foreign_account_id,
        Felt::new(5),
        Word::default(),
        Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]),
        code.commitment(),
    );

    // Create storage slots with test data.
    let slot_name1 = StorageSlotName::new("test::slot1::value".to_string()).unwrap();
    let slot_name2 = StorageSlotName::new("test::slot2::value".to_string()).unwrap();
    let slot1 = StorageSlotHeader::new(
        slot_name1,
        StorageSlotType::Value,
        Word::new([Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]),
    );
    let slot2 = StorageSlotHeader::new(
        slot_name2,
        StorageSlotType::Map,
        Word::new([Felt::new(50), Felt::new(60), Felt::new(70), Felt::new(80)]),
    );

    let mut slots = vec![slot1, slot2];
    slots.sort_by_key(|slot| slot.id());
    let foreign_storage_header = AccountStorageHeader::new(slots.clone()).unwrap();

    // Create advice inputs with both account header and storage header.
    let mut advice_inputs = crate::vm::AdviceInputs::default();
    let account_id_key =
        crate::transaction::TransactionAdviceInputs::account_id_map_key(foreign_account_id);
    advice_inputs.map.insert(account_id_key, foreign_header.as_elements().to_vec());
    advice_inputs
        .map
        .insert(foreign_header.storage_commitment(), foreign_storage_header.to_elements());

    let foreign_account_slot_names = BTreeMap::from([
        (slots[0].id(), slots[0].name().clone()),
        (slots[1].id(), slots[1].name().clone()),
    ]);
    let tx_inputs = TransactionInputs {
        account: partial_account,
        block_header: crate::block::BlockHeader::mock(0, None, None, &[], Word::default()),
        blockchain: crate::transaction::PartialBlockchain::default(),
        input_notes: crate::transaction::InputNotes::new(vec![]).unwrap(),
        tx_args: crate::transaction::TransactionArgs::default(),
        advice_inputs,
        foreign_account_code: vec![code],
        foreign_account_slot_names,
    };

    // Try to read foreign account with storage data.
    // Should succeed and create partial account with proper storage.
    let account_inputs = tx_inputs.read_foreign_account_inputs(foreign_account_id).unwrap();
    assert_eq!(account_inputs.id(), foreign_account_id);
    assert_eq!(account_inputs.account().nonce(), Felt::new(5));

    // Verify storage was properly reconstructed.
    let storage = account_inputs.account().storage();
    assert_eq!(storage.header().slots().count(), 2);

    // Verify witness data is valid.
    let witness = account_inputs.witness();
    assert_eq!(witness.id(), foreign_account_id);

    // Verify the witness can compute a valid account root.
    let computed_root = account_inputs.compute_account_root();
    assert!(
        computed_root.is_ok(),
        "Failed to compute account root from witness: {:?}",
        computed_root.err()
    );

    // Test that the witness path has the expected depth for SMT.
    assert_eq!(witness.path().depth(), 64, "Witness path should have SMT depth of 64");
}

#[test]
fn test_read_foreign_account_inputs_with_proper_witness() {
    use crate::block::account_tree::AccountTree;
    use crate::crypto::merkle::smt::Smt;
    use crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2;

    let native_account_id =
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let foreign_account_id =
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2).unwrap();

    // Create a native account.
    let code = AccountCode::mock();
    let storage_header = AccountStorageHeader::new(vec![]).unwrap();
    let partial_storage = PartialStorage::new(storage_header, []).unwrap();
    let partial_vault = PartialVault::new(Word::default());
    let native_account = PartialAccount::new(
        native_account_id,
        Felt::new(10),
        code.clone(),
        partial_storage,
        partial_vault,
        None,
    )
    .unwrap();

    // Create a foreign account with proper commitment.
    let foreign_header = AccountHeader::new(
        foreign_account_id,
        Felt::new(5),
        Word::default(),
        Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]),
        code.commitment(),
    );

    // Create storage header for the foreign account.
    let foreign_storage_header = AccountStorageHeader::new(vec![]).unwrap();

    // Create an account tree and insert both accounts to get proper Merkle paths.
    let mut account_tree = AccountTree::<Smt>::default();

    // Insert native account.
    let native_commitment = AccountHeader::from(&native_account).commitment();
    account_tree.insert(native_account_id, native_commitment).unwrap();

    // Insert foreign account.
    let _foreign_partial_account = PartialAccount::new(
        foreign_account_id,
        Felt::new(5),
        code.clone(),
        PartialStorage::new(foreign_storage_header.clone(), []).unwrap(),
        PartialVault::new(Word::default()),
        None,
    )
    .unwrap();
    account_tree.insert(foreign_account_id, foreign_header.commitment()).unwrap();

    // Get the account tree root and create witness.
    let account_tree_root = account_tree.root();
    let foreign_witness = account_tree.open(foreign_account_id);

    // Create advice inputs with proper Merkle store data.
    let mut advice_inputs = crate::vm::AdviceInputs::default();

    // Add account header to advice map.
    let account_id_key =
        crate::transaction::TransactionAdviceInputs::account_id_map_key(foreign_account_id);
    advice_inputs.map.insert(account_id_key, foreign_header.as_elements().to_vec());

    // Add storage header to advice map.
    advice_inputs
        .map
        .insert(foreign_header.storage_commitment(), foreign_storage_header.to_elements());

    // Add authenticated nodes from the witness to the Merkle store.
    advice_inputs.store.extend(foreign_witness.authenticated_nodes());

    // Add the account leaf to the advice map (needed for witness verification).
    let leaf = foreign_witness.leaf();
    advice_inputs.map.insert(leaf.hash(), leaf.to_elements());

    // Create block header with the account tree root.
    let block_header = crate::block::BlockHeader::mock(0, None, None, &[], account_tree_root);

    let tx_inputs = TransactionInputs {
        account: native_account,
        block_header,
        blockchain: crate::transaction::PartialBlockchain::default(),
        input_notes: crate::transaction::InputNotes::new(vec![]).unwrap(),
        tx_args: crate::transaction::TransactionArgs::default(),
        advice_inputs,
        foreign_account_code: vec![code],
        foreign_account_slot_names: BTreeMap::new(),
    };

    // Test reading foreign account inputs.
    // Should succeed and create proper witness.
    let account_inputs = tx_inputs.read_foreign_account_inputs(foreign_account_id).unwrap();
    assert_eq!(account_inputs.id(), foreign_account_id);
    assert_eq!(account_inputs.account().nonce(), Felt::new(5));

    // Verify witness data.
    let witness = account_inputs.witness();
    assert_eq!(witness.id(), foreign_account_id);

    // Verify the witness contains the expected account ID and can compute a root.
    let computed_root = account_inputs.compute_account_root();
    assert!(
        computed_root.is_ok(),
        "Failed to compute account root from witness: {:?}",
        computed_root.err()
    );

    // The computed root should be consistent - we're mainly testing that
    // the witness was properly reconstructed from the Merkle store data.
    let _computed_root_value = computed_root.unwrap();

    // Test that the witness path has the expected depth (64 for SMT).
    assert_eq!(witness.path().depth(), 64, "Witness path should have SMT depth of 64");
}

#[test]
fn test_transaction_inputs_serialization_with_foreign_slot_names() {
    use miden_core::Felt;

    use crate::account::{
        AccountCode,
        AccountId,
        AccountStorageHeader,
        PartialAccount,
        PartialStorage,
        StorageSlotName,
    };
    use crate::asset::PartialVault;
    use crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;

    // Create test account IDs
    let native_account_id =
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();

    // Create some slot names and IDs.
    let slot_name_1 = StorageSlotName::new("test::slot1::value".to_string()).unwrap();
    let slot_name_2 = StorageSlotName::new("test::slot2::map".to_string()).unwrap();
    let slot_name_3 = StorageSlotName::new("another::slot::value".to_string()).unwrap();

    let slot_id_1 = slot_name_1.id();
    let slot_id_2 = slot_name_2.id();
    let slot_id_3 = slot_name_3.id();

    // Create foreign account slot names map.
    let mut foreign_account_slot_names = BTreeMap::new();
    foreign_account_slot_names.insert(slot_id_1, slot_name_1.clone());
    foreign_account_slot_names.insert(slot_id_2, slot_name_2.clone());
    foreign_account_slot_names.insert(slot_id_3, slot_name_3.clone());

    // Create a basic TransactionInputs with foreign slot names.
    let code = AccountCode::mock();
    let storage_header = AccountStorageHeader::new(vec![]).unwrap();
    let partial_storage = PartialStorage::new(storage_header, []).unwrap();
    let partial_vault = PartialVault::new(Word::default());
    let partial_account = PartialAccount::new(
        native_account_id,
        Felt::new(10),
        code,
        partial_storage,
        partial_vault,
        None,
    )
    .unwrap();

    let original_tx_inputs = TransactionInputs {
        account: partial_account,
        block_header: crate::block::BlockHeader::mock(0, None, None, &[], Word::default()),
        blockchain: crate::transaction::PartialBlockchain::default(),
        input_notes: crate::transaction::InputNotes::new(vec![]).unwrap(),
        tx_args: crate::transaction::TransactionArgs::default(),
        advice_inputs: crate::vm::AdviceInputs::default(),
        foreign_account_code: Vec::new(),
        foreign_account_slot_names,
    };

    // Test serialization roundtrip.
    let serialized = original_tx_inputs.to_bytes();
    let deserialized = TransactionInputs::read_from_bytes(&serialized).unwrap();

    // Verify that foreign account slot names are preserved.
    assert_eq!(
        original_tx_inputs.foreign_account_slot_names(),
        deserialized.foreign_account_slot_names()
    );

    // Verify specific slot names.
    let deserialized_slots = deserialized.foreign_account_slot_names();

    // Check slots.
    assert_eq!(deserialized_slots.get(&slot_id_1).unwrap(), &slot_name_1);
    assert_eq!(deserialized_slots.get(&slot_id_2).unwrap(), &slot_name_2);
    assert_eq!(deserialized_slots.get(&slot_id_3).unwrap(), &slot_name_3);

    // Verify the entire structure is identical.
    assert_eq!(original_tx_inputs, deserialized);
}
