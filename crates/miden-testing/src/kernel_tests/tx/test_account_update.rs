use alloc::vec::Vec;
use std::collections::BTreeMap;
use std::string::String;
use std::sync::LazyLock;

use anyhow::Context;
use miden_crypto::rand::test_utils::rand_value;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountCode,
    AccountComponent,
    AccountComponentCode,
    AccountComponentMetadata,
    AccountDelta,
    AccountId,
    AccountPatch,
    AccountStorage,
    AccountStoragePatch,
    AccountType,
    AccountVaultDelta,
    AccountVaultPatch,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::testing::account_id::{ACCOUNT_ID_SENDER, AccountIdBuilder};
use miden_protocol::testing::storage::{MOCK_MAP_SLOT, MOCK_VALUE_SLOT0};
use miden_protocol::transaction::TransactionScript;
use miden_protocol::{EMPTY_WORD, Felt, Word, ZERO};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_tx::{LocalTransactionProver, TransactionExecutorError};
use rand::Rng;

use crate::{Auth, MockChain, TransactionContextBuilder};

// ACCOUNT DELTA TESTS
//
// For the approach to these tests, see `AccountUpdateTest::execute`.
// ================================================================================================

/// Tests that a noop transaction with [`Auth::Noop`] results in an empty nonce delta with an empty
/// word as its commitment.
///
/// In order to make the account delta empty but the transaction still legal, we consume a note
/// without assets.
#[tokio::test]
async fn empty_account_delta_commitment_is_empty_word() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::Noop)?;
    let p2any_note =
        builder.add_p2any_note(AccountId::try_from(ACCOUNT_ID_SENDER)?, NoteType::Public, [])?;
    let mock_chain = builder.build()?;

    let executed_tx = mock_chain
        .build_tx_context(account.id(), &[p2any_note.id()], &[])
        .expect("failed to build tx context")
        .build()?
        .execute()
        .await
        .context("failed to execute transaction")?;

    assert_eq!(executed_tx.account_delta().nonce_delta(), ZERO);
    assert!(executed_tx.account_delta().is_empty());
    assert_eq!(executed_tx.account_delta().to_commitment(), Word::empty());

    Ok(())
}

/// Tests that a noop transaction with a nonce-incrementing auth results in a nonce delta of 1
/// and a patch whose only change is the bumped final nonce.
#[tokio::test]
async fn delta_nonce() -> anyhow::Result<()> {
    AccountUpdateTest {
        initial_storage_slots: vec![],
        initial_vault_assets: vec![],
        input_notes_assets: vec![],
        tx_script: None,
        expected_storage_patch: AccountStoragePatch::new(),
        expected_vault_delta: AccountVaultDelta::default(),
        expected_vault_patch: AccountVaultPatch::default(),
        expected_code: None,
    }
    .execute()
    .await
}

/// Tests that setting new values for value storage slots results in the correct patch.
///
/// - Slot 0: [2,4,6,8]  -> [3,4,5,6] -> EMPTY_WORD -> Patch: EMPTY_WORD
/// - Slot 1: EMPTY_WORD -> [3,4,5,6]               -> Patch: [3,4,5,6]
/// - Slot 2: [1,3,5,7]  -> [1,3,5,7]               -> Patch: None
/// - Slot 3: [1,3,5,7]  -> [2,3,4,5] -> [1,3,5,7]  -> Patch: None
#[tokio::test]
async fn storage_patch_for_value_slots() -> anyhow::Result<()> {
    let slot_0_name = StorageSlotName::mock(0);
    let slot_0_init_value = Word::from([2, 4, 6, 8u32]);
    let slot_0_tmp_value = Word::from([3, 4, 5, 6u32]);
    let slot_0_final_value = EMPTY_WORD;

    let slot_1_name = StorageSlotName::mock(1);
    let slot_1_init_value = EMPTY_WORD;
    let slot_1_final_value = Word::from([3, 4, 5, 6u32]);

    let slot_2_name = StorageSlotName::mock(2);
    let slot_2_init_value = Word::from([1, 3, 5, 7u32]);
    let slot_2_final_value = slot_2_init_value;

    let slot_3_name = StorageSlotName::mock(3);
    let slot_3_init_value = Word::from([1, 3, 5, 7u32]);
    let slot_3_tmp_value = Word::from([2, 3, 4, 5u32]);
    let slot_3_final_value = slot_3_init_value;

    let tx_script = parse_tx_script(format!(
        r#"
      const SLOT_0_NAME = word("{slot_0_name}")
      const SLOT_1_NAME = word("{slot_1_name}")
      const SLOT_2_NAME = word("{slot_2_name}")
      const SLOT_3_NAME = word("{slot_3_name}")

      begin
          push.{slot_0_tmp_value}
          push.SLOT_0_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, VALUE]
          exec.set_item
          # => []

          push.{slot_0_final_value}
          push.SLOT_0_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, VALUE]
          exec.set_item
          # => []

          push.{slot_1_final_value}
          push.SLOT_1_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, VALUE]
          exec.set_item
          # => []

          push.{slot_2_final_value}
          push.SLOT_2_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, VALUE]
          exec.set_item
          # => []

          push.{slot_3_tmp_value}
          push.SLOT_3_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, VALUE]
          exec.set_item
          # => []

          push.{slot_3_final_value}
          push.SLOT_3_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, VALUE]
          exec.set_item
          # => []
      end
      "#
    ))?;

    // Slots 2 and 3 are absent because their values haven't effectively changed.
    let mut expected_storage_patch = AccountStoragePatch::new();
    expected_storage_patch.set_item(slot_0_name.clone(), slot_0_final_value)?;
    expected_storage_patch.set_item(slot_1_name.clone(), slot_1_final_value)?;

    AccountUpdateTest {
        initial_storage_slots: vec![
            StorageSlot::with_value(slot_0_name, slot_0_init_value),
            StorageSlot::with_value(slot_1_name, slot_1_init_value),
            StorageSlot::with_value(slot_2_name, slot_2_init_value),
            StorageSlot::with_value(slot_3_name, slot_3_init_value),
        ],
        initial_vault_assets: vec![],
        input_notes_assets: vec![],
        tx_script: Some(tx_script),
        expected_storage_patch,
        expected_vault_delta: AccountVaultDelta::default(),
        expected_vault_patch: AccountVaultPatch::default(),
        expected_code: None,
    }
    .execute()
    .await
}

/// Tests that setting new values for map storage slots results in the correct patch.
///
/// - Slot 0: key0: EMPTY_WORD -> [1,2,3,4]              -> Patch: [1,2,3,4]
/// - Slot 0: key1: EMPTY_WORD -> [1,2,3,4] -> [2,3,4,5] -> Patch: [2,3,4,5]
/// - Slot 1: key2: [1,2,3,4]  -> [1,2,3,4]              -> Patch: None
/// - Slot 1: key3: [1,2,3,4]  -> EMPTY_WORD             -> Patch: EMPTY_WORD
/// - Slot 1: key4: [1,2,3,4]  -> [2,3,4,5] -> [1,2,3,4] -> Patch: None
/// - Slot 2: key5: [1,2,3,4]  -> [2,3,4,5] -> [1,2,3,4] -> Patch: None
///   - key5 and key4 are the same scenario, but in different slots. In particular, slot 2's patch
///     map will be empty after normalization and so it shouldn't be present in the patch at all.
#[tokio::test]
async fn storage_patch_for_map_slots() -> anyhow::Result<()> {
    // Test with random keys to make sure the ordering in the MASM and Rust implementations
    // matches.
    let key0 = StorageMapKey::from_raw(rand_value::<Word>());
    let key1 = StorageMapKey::from_raw(rand_value::<Word>());
    let key2 = StorageMapKey::from_raw(rand_value::<Word>());
    let key3 = StorageMapKey::from_raw(rand_value::<Word>());
    let key4 = StorageMapKey::from_raw(rand_value::<Word>());
    let key5 = StorageMapKey::from_raw(rand_value::<Word>());

    let key0_init_value = EMPTY_WORD;
    let key1_init_value = EMPTY_WORD;
    let key2_init_value = Word::from([1, 2, 3, 4u32]);
    let key3_init_value = Word::from([1, 2, 3, 4u32]);
    let key4_init_value = Word::from([1, 2, 3, 4u32]);
    let key5_init_value = Word::from([1, 2, 3, 4u32]);

    let key0_final_value = Word::from([1, 2, 3, 4u32]);
    let key1_tmp_value = Word::from([1, 2, 3, 4u32]);
    let key1_final_value = Word::from([2, 3, 4, 5u32]);
    let key2_final_value = key2_init_value;
    let key3_final_value = EMPTY_WORD;
    let key4_tmp_value = Word::from([2, 3, 4, 5u32]);
    let key4_final_value = Word::from([1, 2, 3, 4u32]);
    let key5_tmp_value = Word::from([2, 3, 4, 5u32]);
    let key5_final_value = Word::from([1, 2, 3, 4u32]);

    let slot_0_name = StorageSlotName::mock(0);
    let mut map0 = StorageMap::new();
    map0.insert(key0, key0_init_value).unwrap();
    map0.insert(key1, key1_init_value).unwrap();

    let slot_1_name = StorageSlotName::mock(1);
    let mut map1 = StorageMap::new();
    map1.insert(key2, key2_init_value).unwrap();
    map1.insert(key3, key3_init_value).unwrap();
    map1.insert(key4, key4_init_value).unwrap();

    let slot_2_name = StorageSlotName::mock(2);
    let mut map2 = StorageMap::new();
    map2.insert(key5, key5_init_value).unwrap();

    let tx_script = parse_tx_script(format!(
        r#"
      const SLOT_0_NAME = word("{slot_0_name}")
      const SLOT_1_NAME = word("{slot_1_name}")
      const SLOT_2_NAME = word("{slot_2_name}")

      begin
          push.{key0_final_value} push.{key0}
          push.SLOT_0_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key1_tmp_value} push.{key1}
          push.SLOT_0_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key1_final_value} push.{key1}
          push.SLOT_0_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key2_final_value} push.{key2}
          push.SLOT_1_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key3_final_value} push.{key3}
          push.SLOT_1_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key4_tmp_value} push.{key4}
          push.SLOT_1_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key4_final_value} push.{key4}
          push.SLOT_1_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key5_tmp_value} push.{key5}
          push.SLOT_2_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key5_final_value} push.{key5}
          push.SLOT_2_NAME[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          exec.set_map_item
          # => []
      end
      "#
    ))?;

    // map2 should not appear in the patch since its only change normalized to a no-op.
    let mut expected_storage_patch = AccountStoragePatch::new();
    expected_storage_patch.set_map_item(slot_0_name.clone(), key0, key0_final_value)?;
    expected_storage_patch.set_map_item(slot_0_name.clone(), key1, key1_final_value)?;
    expected_storage_patch.set_map_item(slot_1_name.clone(), key3, key3_final_value)?;

    AccountUpdateTest {
        initial_storage_slots: vec![
            StorageSlot::with_map(slot_0_name, map0),
            StorageSlot::with_map(slot_1_name, map1),
            StorageSlot::with_map(slot_2_name, map2),
            // Include an empty map which does not receive any updates, to test that the "metadata
            // header" in the delta commitment is not appended if there are no updates to a map
            // slot.
            StorageSlot::with_map(StorageSlotName::mock(3), StorageMap::new()),
        ],
        initial_vault_assets: vec![],
        input_notes_assets: vec![],
        tx_script: Some(tx_script),
        expected_storage_patch,
        expected_vault_delta: AccountVaultDelta::default(),
        expected_vault_patch: AccountVaultPatch::default(),
        expected_code: None,
    }
    .execute()
    .await
}

/// Tests that increasing, decreasing the amount of a fungible asset results in the correct update.
///
/// - Asset0 starts at 300, is increased by 100 and decreased by 200 -> Delta: -100, Patch: 200.
/// - Asset1 starts at 200, is increased by 100 and decreased by 100 -> Delta: 0, Patch: None.
/// - Asset2 starts at 100, is increased by 200 and decreased by 100 -> Delta: 100, Patch: 200.
/// - Asset3 starts at MAX, is decreased by MAX -> Delta: -MAX, Patch: 0.
/// - Asset4 starts at 0, is increased by MAX -> Delta: MAX, Patch: MAX.
#[tokio::test]
async fn fungible_asset_update() -> anyhow::Result<()> {
    // Test with random IDs to make sure the ordering in the MASM and Rust implementations
    // matches.
    let faucet0: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::Private)
        .build_with_seed(rand::random());
    let faucet1: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_seed(rand::random());
    let faucet2: AccountId = AccountIdBuilder::new().build_with_seed(rand::random());
    let faucet3: AccountId = AccountIdBuilder::new().build_with_seed(rand::random());
    let faucet4: AccountId = AccountIdBuilder::new().build_with_seed(rand::random());

    let max_amount = FungibleAsset::MAX_AMOUNT.as_u64();

    let original_asset0 = FungibleAsset::new(faucet0, 300)?;
    let original_asset1 = FungibleAsset::new(faucet1, 200)?;
    let original_asset2 = FungibleAsset::new(faucet2, 100)?;
    let original_asset3 = FungibleAsset::new(faucet3, max_amount)?;

    let added_asset0 = FungibleAsset::new(faucet0, 100)?;
    let added_asset1 = FungibleAsset::new(faucet1, 100)?;
    let added_asset2 = FungibleAsset::new(faucet2, 200)?;
    let added_asset4 = FungibleAsset::new(faucet4, max_amount)?;

    let removed_asset0 = FungibleAsset::new(faucet0, 200)?;
    let removed_asset1 = FungibleAsset::new(faucet1, 100)?;
    let removed_asset2 = FungibleAsset::new(faucet2, 100)?;
    let removed_asset3 = FungibleAsset::new(faucet3, max_amount)?;

    let tx_script = parse_tx_script(format!(
        "
    begin
        push.{ASSET0_VALUE} push.{ASSET0_KEY}
        exec.util::create_default_note_with_moved_asset
        # => []

        push.{ASSET1_VALUE} push.{ASSET1_KEY}
        exec.util::create_default_note_with_moved_asset
        # => []

        push.{ASSET2_VALUE} push.{ASSET2_KEY}
        exec.util::create_default_note_with_moved_asset
        # => []

        push.{ASSET3_VALUE} push.{ASSET3_KEY}
        exec.util::create_default_note_with_moved_asset
        # => []
    end
    ",
        ASSET0_KEY = removed_asset0.to_key_word(),
        ASSET0_VALUE = removed_asset0.to_value_word(),
        ASSET1_KEY = removed_asset1.to_key_word(),
        ASSET1_VALUE = removed_asset1.to_value_word(),
        ASSET2_KEY = removed_asset2.to_key_word(),
        ASSET2_VALUE = removed_asset2.to_value_word(),
        ASSET3_KEY = removed_asset3.to_key_word(),
        ASSET3_VALUE = removed_asset3.to_value_word(),
    ))?;

    let expected_vault_delta = AccountVaultDelta::from_iters(
        [Asset::from(added_asset2.sub(removed_asset2)?), Asset::from(added_asset4)],
        [Asset::from(removed_asset0.sub(added_asset0)?), Asset::from(removed_asset3)],
    );

    let mut expected_vault_patch = AccountVaultPatch::default();
    expected_vault_patch
        .insert_asset(original_asset0.add(added_asset0)?.sub(removed_asset0)?.into());
    expected_vault_patch
        .insert_asset(original_asset2.add(added_asset2)?.sub(removed_asset2)?.into());
    expected_vault_patch.remove_asset(removed_asset3.vault_key());
    expected_vault_patch.insert_asset(added_asset4.into());

    AccountUpdateTest {
        initial_storage_slots: vec![],
        initial_vault_assets: vec![
            original_asset0.into(),
            original_asset1.into(),
            original_asset2.into(),
            original_asset3.into(),
        ],
        input_notes_assets: vec![
            added_asset0.into(),
            added_asset1.into(),
            added_asset2.into(),
            added_asset4.into(),
        ],
        tx_script: Some(tx_script),
        expected_storage_patch: AccountStoragePatch::new(),
        expected_vault_delta,
        expected_vault_patch,
        expected_code: None,
    }
    .execute()
    .await
}

/// Tests that adding, removing non-fungible assets results in the correct update.
///
/// - Asset0 is added to the vault -> Delta: Add, Patch: Asset0.
/// - Asset1 is removed from the vault -> Delta: Remove, Patch: EMPTY_WORD.
/// - Asset2 is added and removed -> Delta: No Change, Patch: None.
/// - Asset3 is removed and added -> Delta: No Change, Patch: None.
#[tokio::test]
async fn non_fungible_asset_delta() -> anyhow::Result<()> {
    let mut rng = rand::rng();
    // Test with random IDs to make sure the ordering in the MASM and Rust implementations
    // matches.
    let faucet0: AccountId = AccountIdBuilder::new().build_with_seed(rng.random());
    let faucet1: AccountId = AccountIdBuilder::new().build_with_seed(rng.random());
    let faucet2: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_seed(rng.random());
    let faucet3: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::Private)
        .build_with_seed(rng.random());

    let asset0 = NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        faucet0,
        rng.random::<[u8; 32]>().to_vec(),
    ));
    let asset1 = NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        faucet1,
        rng.random::<[u8; 32]>().to_vec(),
    ));
    let asset2 = NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        faucet2,
        rng.random::<[u8; 32]>().to_vec(),
    ));
    let asset3 = NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        faucet3,
        rng.random::<[u8; 32]>().to_vec(),
    ));

    let tx_script = parse_tx_script(format!(
        "
    begin
        push.{ASSET1_VALUE} push.{ASSET1_KEY}
        exec.util::create_default_note_with_moved_asset
        # => []

        push.{ASSET2_VALUE} push.{ASSET2_KEY}
        exec.util::create_default_note_with_moved_asset
        # => []

        # remove asset 3
        push.{ASSET3_VALUE}
        push.{ASSET3_KEY}
        exec.remove_asset
        # => [FINAL_ASSET_VALUE]
        dropw

        # re-add asset 3
        push.{ASSET3_VALUE}
        push.{ASSET3_KEY}
        # => [ASSET_KEY, ASSET_VALUE]
        exec.add_asset dropw
        # => []
    end
    ",
        ASSET1_KEY = asset1.to_key_word(),
        ASSET1_VALUE = asset1.to_value_word(),
        ASSET2_KEY = asset2.to_key_word(),
        ASSET2_VALUE = asset2.to_value_word(),
        ASSET3_KEY = asset3.to_key_word(),
        ASSET3_VALUE = asset3.to_value_word(),
    ))?;

    let expected_vault_delta =
        AccountVaultDelta::from_iters([Asset::from(asset0)], [Asset::from(asset1)]);

    let mut expected_vault_patch = AccountVaultPatch::default();
    expected_vault_patch.insert_asset(asset0.into());
    expected_vault_patch.remove_asset(Asset::from(asset1).vault_key());

    AccountUpdateTest {
        initial_storage_slots: vec![],
        initial_vault_assets: vec![asset1.into(), asset3.into()],
        input_notes_assets: vec![asset0.into(), asset2.into()],
        tx_script: Some(tx_script),
        expected_storage_patch: AccountStoragePatch::new(),
        expected_vault_delta,
        expected_vault_patch,
        expected_code: None,
    }
    .execute()
    .await
}

/// Tests that storage value/map updates combined with vault asset additions and removals are
/// reflected correctly in the resulting delta and patch.
///
/// To keep the focus on the interplay between storage and vault sub-patches, the added and
/// removed assets are deliberately disjoint - multiple updates to same-faucet assets is covered by
/// other tests.
///
/// Vault:
/// - asset_0 starts at 1000, moved out to note -> Delta: Remove asset_0, Patch: EMPTY_WORD.
/// - asset_1 is moved out to note -> Delta: Remove asset_1, Patch: EMPTY_WORD.
/// - asset_2 is moved in to vault -> Delta: Add asset_2, Patch: asset_2.
/// - asset_3 is moved in to vault -> Delta: Add asset_3, Patch: asset_3.
///
/// Storage:
/// - MOCK_VALUE_SLOT0: STORAGE_VALUE_0 -> updated_slot_value -> Patch: updated_slot_value.
/// - MOCK_MAP_SLOT[updated_map_key]: EMPTY_WORD -> updated_map_value -> Patch: updated_map_value.
/// - MOCK_VALUE_SLOT1 and the other MOCK_MAP_SLOT entries are untouched -> Patch: None.
#[tokio::test]
async fn asset_and_storage_patch() -> anyhow::Result<()> {
    let mut rng = rand::rng();

    let faucet_0: AccountId = AccountIdBuilder::new().build_with_seed(rng.random());
    let faucet_1: AccountId = AccountIdBuilder::new().build_with_seed(rng.random());
    let faucet_2: AccountId = AccountIdBuilder::new().build_with_seed(rng.random());
    let faucet_3: AccountId = AccountIdBuilder::new().build_with_seed(rng.random());

    let asset_0: Asset = FungibleAsset::new(faucet_0, 1000)?.into();
    let asset_1: Asset = NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        faucet_1,
        rng.random::<[u8; 32]>().to_vec(),
    ))
    .into();

    let asset_2: Asset = FungibleAsset::new(faucet_2, 500)?.into();
    let asset_3: Asset = NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        faucet_3,
        rng.random::<[u8; 32]>().to_vec(),
    ))
    .into();

    let updated_slot_value = Word::from([7, 9, 11, 13u32]);
    let updated_map_key = StorageMapKey::from_array([14, 15, 16, 17u32]);
    let updated_map_value = Word::from([18, 19, 20, 21u32]);

    let removed_assets = [asset_0, asset_1];
    let added_assets = [asset_2, asset_3];

    let mut send_assets_script = String::new();
    for (i, removed_asset) in removed_assets.iter().enumerate() {
        send_assets_script.push_str(&format!(
            "
            ### note {i}
            # prepare the stack for a new note creation
            push.0.1.2.3           # RECIPIENT
            push.{note_type}       # note_type
            push.{tag}             # tag

            # create the note
            exec.output_note::create
            # => [note_idx, pad(15)]

            # move the asset into the new note
            swapw dropw
            push.{ASSET_VALUE} push.{ASSET_KEY}
            call.::miden::standards::wallets::basic::move_asset_to_note
            # => [pad(16)]

            # clear the stack
            dropw dropw dropw dropw
            ",
            note_type = NoteType::Private as u8,
            tag = NoteTag::default(),
            ASSET_KEY = removed_asset.to_key_word(),
            ASSET_VALUE = removed_asset.to_value_word(),
        ));
    }

    let tx_script_src = format!(
        r#"
        use mock::account
        use miden::protocol::output_note

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")
        const MOCK_MAP_SLOT = word("{mock_map_slot}")

        begin
            ## Update value storage slot
            push.{updated_slot_value}
            push.MOCK_VALUE_SLOT0[0..2]
            call.account::set_item dropw

            ## Update map storage slot at a previously-unset key
            push.{updated_map_value}
            push.{updated_map_key}
            push.MOCK_MAP_SLOT[0..2]
            call.account::set_map_item dropw dropw dropw

            ## Move both initial vault assets out via newly created output notes
            {send_assets_script}

            dropw dropw dropw dropw
        end
        "#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
        mock_map_slot = &*MOCK_MAP_SLOT,
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_src)?;

    let mut expected_storage_patch = AccountStoragePatch::new();
    expected_storage_patch.set_item(MOCK_VALUE_SLOT0.clone(), updated_slot_value)?;
    expected_storage_patch.set_map_item(
        MOCK_MAP_SLOT.clone(),
        updated_map_key,
        updated_map_value,
    )?;

    let expected_vault_delta = AccountVaultDelta::from_iters(added_assets, removed_assets);

    let mut expected_vault_patch = AccountVaultPatch::default();
    expected_vault_patch.remove_asset(asset_0.vault_key());
    expected_vault_patch.remove_asset(asset_1.vault_key());
    expected_vault_patch.insert_asset(asset_2);
    expected_vault_patch.insert_asset(asset_3);

    AccountUpdateTest {
        initial_storage_slots: AccountStorage::mock_storage_slots(),
        initial_vault_assets: vec![asset_0, asset_1],
        input_notes_assets: vec![asset_2, asset_3],
        tx_script: Some(tx_script),
        expected_storage_patch,
        expected_vault_delta,
        expected_vault_patch,
        expected_code: None,
    }
    .execute()
    .await
}

/// Tests that the storage map updates for a _new public_ account in an executed and proven
/// transaction match up.
///
/// This is an interesting test case because:
/// - for new accounts in general, the storage map entries must be available in the advice provider
///   and the resulting delta must be convertible to a full account.
/// - it creates an account with two identical storage maps.
/// - The prover mutates the delta to account for fee logic.
#[tokio::test]
async fn proven_tx_storage_maps_matches_executed_tx_for_new_account() -> anyhow::Result<()> {
    // Use two identical maps to test that they are properly handled
    // (see also https://github.com/0xMiden/protocol/issues/2037).
    let map0 = StorageMap::with_entries([(StorageMapKey::from_raw(rand_value()), rand_value())])?;
    let map1 = map0.clone();
    let mut map2 = StorageMap::with_entries([
        (StorageMapKey::from_raw(rand_value()), rand_value()),
        (StorageMapKey::from_raw(rand_value()), rand_value()),
        (StorageMapKey::from_raw(rand_value()), rand_value()),
        (StorageMapKey::from_raw(rand_value()), rand_value()),
    ])?;

    let map0_slot_name = StorageSlotName::mock(1);
    let map1_slot_name = StorageSlotName::mock(2);
    let map2_slot_name = StorageSlotName::mock(4);

    // Build a public account so the proven transaction includes the account update.
    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(vec![
            AccountStorage::mock_value_slot0(),
            StorageSlot::with_map(map0_slot_name.clone(), map0.clone()),
            StorageSlot::with_map(map1_slot_name.clone(), map1.clone()),
            AccountStorage::mock_value_slot1(),
            StorageSlot::with_map(map2_slot_name.clone(), map2.clone()),
        ]))
        .build()?;

    // Fetch a random existing key from the map.
    let existing_key = *map2.entries().next().unwrap().0;
    let value0 = Word::from([3, 4, 5, 6u32]);

    let code = format!(
        r#"
      use mock::account

      const MAP_SLOT=word("{map2_slot_name}")

      begin
          # Update an existing key.
          push.{value0}
          push.{existing_key}
          push.MAP_SLOT[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          call.account::set_map_item

          exec.::miden::core::sys::truncate_stack
      end
      "#
    );

    let builder = CodeBuilder::with_mock_libraries();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;

    let tx = TransactionContextBuilder::new(account.clone())
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    map2.insert(existing_key, value0)?;

    for (slot_name, expected_map) in
        [(map0_slot_name, map0), (map1_slot_name, map1), (map2_slot_name, map2)]
    {
        let map_patch_entries = tx.account_delta().storage().get_map(&slot_name).unwrap().entries();
        let expected: BTreeMap<_, _> = expected_map.entries().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(map_patch_entries, &expected, "map delta does not match for slot {slot_name}",);
    }

    let proven_tx = LocalTransactionProver::default().prove_dummy(tx.clone())?;

    let proven_tx_patch = proven_tx.account_update().details().unwrap_public();

    let proven_tx_account = Account::try_from(proven_tx_patch)?;
    let exec_tx_account = Account::try_from(tx.account_patch())?;
    let exec_tx_delta_account = Account::try_from(tx.account_delta())?;

    assert_eq!(exec_tx_delta_account, exec_tx_account);
    assert_eq!(proven_tx_account.storage(), exec_tx_account.storage());

    // Check the conversion back into a full-state delta and patch works correctly.
    let proven_tx_patch_converted = AccountPatch::try_from(proven_tx_account.clone())?;
    let exec_tx_patch_converted = AccountPatch::try_from(exec_tx_account.clone())?;

    let proven_tx_delta_converted = AccountDelta::try_from(proven_tx_account)?;
    let exec_tx_delta_converted = AccountDelta::try_from(exec_tx_account)?;

    // Check that the deltas and patches from proven and executed tx, which were converted from
    // accounts are identical. This is essentially a roundtrip test.
    assert_eq!(tx.account_patch(), proven_tx_patch);
    assert_eq!(&proven_tx_patch_converted, tx.account_patch());
    assert_eq!(&exec_tx_patch_converted, tx.account_patch());

    assert_eq!(&exec_tx_delta_converted, tx.account_delta());
    assert_eq!(&proven_tx_delta_converted, tx.account_delta());

    // The commitments should match as well.
    assert_eq!(exec_tx_patch_converted.to_commitment(), tx.account_patch().to_commitment());
    assert_eq!(proven_tx_patch_converted.to_commitment(), tx.account_patch().to_commitment());

    assert_eq!(exec_tx_delta_converted.to_commitment(), tx.account_delta().to_commitment());
    assert_eq!(proven_tx_delta_converted.to_commitment(), tx.account_delta().to_commitment());

    Ok(())
}

/// Tests that creating a new account with a slot whose value is empty is correctly included in the
/// delta and not normalized away.
#[tokio::test]
async fn delta_for_new_account_retains_empty_value_storage_slots() -> anyhow::Result<()> {
    let slot_name0 = StorageSlotName::mock(0);
    let slot_name1 = StorageSlotName::mock(1);

    let slot_value2 = Word::from([1, 2, 3, 4u32]);
    let mut account = AccountBuilder::new(rand::random())
        .account_type(AccountType::Public)
        .with_component(MockAccountComponent::with_slots(vec![
            StorageSlot::with_empty_value(slot_name0.clone()),
            StorageSlot::with_value(slot_name1.clone(), slot_value2),
        ]))
        .with_auth_component(Auth::IncrNonce)
        .build()?;

    let tx = TransactionContextBuilder::new(account.clone()).build()?.execute().await?;

    let proven_tx = LocalTransactionProver::default().prove_dummy(tx.clone())?;

    let patch = proven_tx.account_update().details().unwrap_public();

    assert_eq!(patch.storage().values().count(), 2);
    assert_eq!(patch.storage().get_value(&slot_name0), Some(Word::empty()));
    assert_eq!(patch.storage().get_value(&slot_name1), Some(slot_value2));

    let recreated_account = Account::try_from(patch)?;
    // The recreated account should match the original account with the nonce incremented (and the
    // seed removed).
    account.increment_nonce(Felt::ONE)?;
    assert_eq!(recreated_account, account);

    Ok(())
}

/// Tests that creating a new account with a slot whose map is empty is correctly included in the
/// delta.
#[tokio::test]
async fn delta_for_new_account_retains_empty_map_storage_slots() -> anyhow::Result<()> {
    let slot_name0 = StorageSlotName::mock(0);

    let mut account = AccountBuilder::new(rand::random())
        .account_type(AccountType::Public)
        .with_component(MockAccountComponent::with_slots(vec![StorageSlot::with_empty_map(
            slot_name0.clone(),
        )]))
        .with_auth_component(Auth::IncrNonce)
        .build()?;

    let tx = TransactionContextBuilder::new(account.clone()).build()?.execute().await?;

    let proven_tx = LocalTransactionProver::default().prove_dummy(tx.clone())?;

    let patch = proven_tx.account_update().details().unwrap_public();

    assert_eq!(patch.storage().maps().count(), 1);
    assert!(patch.storage().get_map(&slot_name0).unwrap().is_empty());

    let recreated_account = Account::try_from(patch)?;
    // The recreated account should match the original account with the nonce incremented (and the
    // seed removed).
    account.increment_nonce(Felt::ONE)?;
    assert_eq!(recreated_account, account);

    Ok(())
}

/// Tests that adding a fungible asset with amount zero to the account vault works and does not
/// result in an account delta or patch entry.
#[tokio::test]
async fn adding_amount_zero_fungible_asset_to_account_vault_works() -> anyhow::Result<()> {
    AccountUpdateTest {
        initial_storage_slots: vec![],
        initial_vault_assets: vec![],
        input_notes_assets: vec![FungibleAsset::mock(0)],
        tx_script: None,
        expected_storage_patch: AccountStoragePatch::new(),
        expected_vault_delta: AccountVaultDelta::default(),
        expected_vault_patch: AccountVaultPatch::default(),
        expected_code: None,
    }
    .execute()
    .await
}

/// Tests that recomputing a delta correctly resets the account delta tracked by the host.
///
/// The auth procedure adds `asset0` to the vault, explicitly calls `compute_delta_commitment`,
/// and then removes `asset0` again. It then builds the tx summary (which calls
/// `compute_delta_commitment` a second time) and emits `AUTH_UNAUTHORIZED_EVENT`, so the can access
/// the delta via `TransactionSummary::account_delta`.
///
/// Without the reset performed at the start of each `compute_delta_commitment`, this would fail:
/// - The explicit call iterates the asset delta link map, sees the added `asset0`, and fires
///   `on_asset_delta_computation`, which accumulates `asset0` into the host's tracked vault delta.
/// - Removing `asset0` afterwards turns its link map entry into a net-empty entry.
/// - The summary's call iterates the link map again, but the net-empty entry does NOT fire
///   `on_asset_delta_computation`, so the previously accumulated `asset0` would remain in the
///   host's vault delta forever, leaving it non-empty even though the actual change is zero.
///
/// With the reset (the `before_asset_delta_computation` event emitted at the start of each
/// `compute_delta_commitment`), the host clears its vault delta before each iteration, so the
/// summary's call correctly produces an empty delta.
#[tokio::test]
async fn recomputing_delta_resets_host_delta() -> anyhow::Result<()> {
    let mut rng = rand::rng();
    // Test with random IDs to make sure the ordering in the MASM and Rust implementations
    // matches.
    let faucet0: AccountId = AccountIdBuilder::new().build_with_seed(rng.random());
    let faucet1: AccountId = AccountIdBuilder::new().build_with_seed(rng.random());

    let asset0 = NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        faucet0,
        rng.random::<[u8; 32]>().to_vec(),
    ));
    let asset1 = NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        faucet1,
        rng.random::<[u8; 32]>().to_vec(),
    ));

    let auth_code = format!(
        "
    use miden::protocol::native_account
    use miden::protocol::auth::AUTH_UNAUTHORIZED_EVENT

    {TEST_ACCOUNT_CONVENIENCE_WRAPPERS}

    #! Inputs:  [[AUTH_ARGS], pad(12)]
    #! Outputs: [pad(16)]
    @auth_script
    pub proc auth_test
        exec.native_account::incr_nonce drop
        # => [[AUTH_ARGS], pad(12)]

        # add asset 0 to the vault
        push.{ASSET0_VALUE} push.{ASSET0_KEY}
        exec.add_asset dropw
        # => [[AUTH_ARGS], pad(12)]

        # compute the delta to trigger the host to add the assets to the vault delta
        exec.native_account::compute_delta_commitment
        dropw
        # => [[AUTH_ARGS], pad(12)]

        # remove asset 0 for correct asset preservation
        push.{ASSET0_VALUE}
        push.{ASSET0_KEY}
        exec.remove_asset dropw
        # => [[AUTH_ARGS], pad(12)]

        # Build the tx summary.
        # Replace AUTH_ARGS with an EMPTY_WORD salt for the tx summary.
        dropw padw
        # => [SALT, pad(12)]

        exec.::miden::standards::auth::create_tx_summary
        # => [ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, SALT, pad(12)]

        adv.insert_hqword
        # => [ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, SALT, pad(12)]

        exec.::miden::standards::auth::hash_tx_summary
        # => [TX_SUMMARY_COMMITMENT, pad(12)]

        emit.AUTH_UNAUTHORIZED_EVENT

        push.0 assert.err=\"emitting the event should have aborted execution\"
    end
    ",
        ASSET0_KEY = asset0.to_key_word(),
        ASSET0_VALUE = asset0.to_value_word(),
    );

    let auth_component_code =
        CodeBuilder::with_mock_libraries().compile_component_code("test::account", auth_code)?;

    let mut builder = MockChain::builder();
    let account = Account::builder(builder.rng_mut().random())
        .account_type(AccountType::Public)
        .with_auth_component(AccountComponent::new(
            auth_component_code,
            vec![],
            AccountComponentMetadata::new("test::account"),
        )?)
        .with_component(MockAccountComponent::with_slots(vec![]))
        .with_assets(vec![asset1.into()])
        .build_existing()?;
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let tx_summary = mock_chain
        .build_tx_context(account, &[], &[])?
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let account_delta = tx_summary.account_delta();

    assert!(account_delta.vault().is_empty(), "vault delta should be effectively empty");
    assert!(account_delta.storage().is_empty(), "storage delta should be empty");
    assert_eq!(
        account_delta.nonce_delta().as_canonical_u64(),
        1,
        "nonce should have been incremented"
    );

    Ok(())
}

// TEST HELPERS
// ================================================================================================

fn parse_tx_script(code: impl AsRef<str>) -> anyhow::Result<TransactionScript> {
    let code = format!(
        "
    {TEST_ACCOUNT_CONVENIENCE_WRAPPERS}
    {code}
    ",
        code = code.as_ref()
    );

    CodeBuilder::with_mock_libraries()
        .compile_tx_script(&code)
        .context("failed to parse tx script")
}

const TEST_ACCOUNT_CONVENIENCE_WRAPPERS: &str = "
      use mock::account
      use mock::util
      use miden::protocol::output_note

      #! Inputs:  [slot_id_suffix, slot_id_prefix, VALUE]
      #! Outputs: []
      proc set_item
          repeat.10 push.0 movdn.6 end
          # => [slot_id_suffix, slot_id_prefix, VALUE, pad(10)]

          call.account::set_item
          # => [OLD_VALUE, pad(12)]

          dropw dropw dropw dropw
      end

      #! Inputs:  [slot_id_suffix, slot_id_prefix, KEY, VALUE]
      #! Outputs: []
      proc set_map_item
          repeat.6 push.0 movdn.10 end
          # => [index, KEY, VALUE, pad(6)]

          call.account::set_map_item
          # => [OLD_VALUE, pad(12)]

          dropw dropw dropw dropw
          # => []
      end

      #! Inputs:  [ASSET_KEY, ASSET_VALUE]
      #! Outputs: [FINAL_ASSET_VALUE]
      proc add_asset
          repeat.8 push.0 movdn.8 end
          # => [ASSET_KEY, ASSET_VALUE, pad(8)]

          call.account::add_asset
          # => [FINAL_ASSET_VALUE, pad(12)]

          repeat.12 movup.4 drop end
          # => [FINAL_ASSET_VALUE]
      end

      #! Inputs:  [ASSET_KEY, ASSET_VALUE]
      #! Outputs: [ASSET_VALUE]
      proc remove_asset
          padw padw swapdw
          # => [ASSET_KEY, ASSET_VALUE, pad(8)]

          call.account::remove_asset
          # => [ASSET_VALUE, pad(12)]

          repeat.12 movup.4 drop end
          # => [ASSET_VALUE]
      end
";

// DELTA-CHECK AUTH COMPONENT
// ================================================================================================

// Auth procedure that increments the nonce and, when the first felt of `AUTH_ARGS` is non-zero,
// emits `AUTH_UNAUTHORIZED_EVENT` after building the tx summary. The unauthorized event drives
// `TransactionBaseHost::build_tx_summary` which cross-checks the host-tracked delta commitment
// against the kernel-computed one — re-establishing the implicit host/kernel match check that
// existed when the kernel epilogue still produced the delta commitment.
const DELTA_CHECK_AUTH_CODE: &str = r#"
    use miden::protocol::native_account
    use miden::protocol::auth::AUTH_UNAUTHORIZED_EVENT

    #! Inputs:  [[should_emit, 0, 0, 0], pad(12)]
    #! Outputs: [pad(16)]
    @auth_script
    pub proc auth_incr_nonce_with_delta_check
        exec.native_account::incr_nonce drop
        # => [[should_emit, 0, 0, 0], pad(12)]

        dup
        if.true
            # Replace AUTH_ARGS with an EMPTY_WORD salt for the tx summary.
            dropw padw
            # => [SALT, pad(12)]

            exec.::miden::standards::auth::create_tx_summary
            # => [ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, SALT, pad(12)]

            adv.insert_hqword
            # => [ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, SALT, pad(12)]

            exec.::miden::standards::auth::hash_tx_summary
            # => [TX_SUMMARY_COMMITMENT, pad(12)]

            emit.AUTH_UNAUTHORIZED_EVENT

            push.0 assert.err="emitting the event should have aborted execution"
        end
    end
"#;

static DELTA_CHECK_AUTH_LIBRARY: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    CodeBuilder::with_mock_libraries()
        .compile_component_code("test::incr_nonce_with_delta_check_auth", DELTA_CHECK_AUTH_CODE)
        .expect("delta-check auth code should compile")
});

fn delta_check_auth_component() -> AccountComponent {
    AccountComponent::new(
        DELTA_CHECK_AUTH_LIBRARY.clone(),
        vec![],
        AccountComponentMetadata::new("test::incr_nonce_with_delta_check_auth"),
    )
    .expect("delta-check auth component should be valid")
}

// EXECUTE ACCOUNT UPDATE TEST HELPER
// ================================================================================================

struct AccountUpdateTest {
    pub initial_storage_slots: Vec<StorageSlot>,
    pub initial_vault_assets: Vec<Asset>,
    pub input_notes_assets: Vec<Asset>,
    pub tx_script: Option<TransactionScript>,
    pub expected_storage_patch: AccountStoragePatch,
    pub expected_vault_delta: AccountVaultDelta,
    pub expected_vault_patch: AccountVaultPatch,
    pub expected_code: Option<AccountCode>,
}

impl AccountUpdateTest {
    /// Runs a transaction against the same setup to validate:
    /// - that commitments match in host and kernel.
    /// - that the delta and patch match the expectation.
    ///
    /// - The first run drives the auth into emitting the unauthorized event. The host's
    ///   `build_tx_summary` checks the host-tracked delta commitment against the kernel-computed
    ///   one before surfacing [`TransactionExecutorError::Unauthorized`]. We assert that the
    ///   wrapped `TransactionSummary::account_delta` equals the delta built from the expected
    ///   parts.
    /// - The second run completes the transaction normally. The transaction executor checks that
    ///   patch commitments in host and kernel match. We assert that
    ///   `ExecutedTransaction::account_patch` equals the patch built from the expected parts.
    async fn execute(self) -> anyhow::Result<()> {
        let Self {
            initial_storage_slots,
            initial_vault_assets,
            input_notes_assets,
            tx_script,
            expected_storage_patch,
            expected_vault_delta,
            expected_vault_patch,
            expected_code,
        } = self;

        let mut builder = MockChain::builder();
        let account = Account::builder(builder.rng_mut().random())
            .account_type(AccountType::Public)
            .with_auth_component(delta_check_auth_component())
            .with_component(MockAccountComponent::with_slots(initial_storage_slots))
            .with_assets(initial_vault_assets)
            .build_existing()?;
        builder.add_account(account.clone())?;

        let mut input_note_ids = Vec::with_capacity(input_notes_assets.len());
        for note_asset in input_notes_assets {
            let input_note = builder
                .add_p2id_note(account.id(), account.id(), &[note_asset], NoteType::Public)
                .context("failed to add note with assets")?;
            input_note_ids.push(input_note.id());
        }

        let mock_chain = builder.build()?;

        let expected_nonce_delta = Felt::ONE;
        let expected_delta = AccountDelta::new(
            account.id(),
            expected_storage_patch.clone(),
            expected_vault_delta,
            expected_nonce_delta,
        )?;
        let expected_patch = AccountPatch::new(
            account.id(),
            expected_storage_patch,
            expected_vault_patch,
            expected_code,
            Some(account.nonce() + expected_nonce_delta),
        )?;

        // Delta path: emit unauthorized so the host's build_tx_summary cross-checks the delta.
        let delta_run = {
            let auth_args = Word::from([Felt::ONE, ZERO, ZERO, ZERO]);
            let mut tx = mock_chain
                .build_tx_context(account.id(), &input_note_ids, &[])?
                .auth_args(auth_args);
            if let Some(ref script) = tx_script {
                tx = tx.tx_script(script.clone());
            }
            tx.build()?.execute().await
        };
        let summary = match delta_run {
            Err(TransactionExecutorError::Unauthorized(summary)) => summary,
            Err(other) => anyhow::bail!("expected Unauthorized error, got: {other}"),
            Ok(_) => anyhow::bail!("expected Unauthorized error, got Ok"),
        };
        assert_eq!(*summary.account_delta(), expected_delta);

        // Patch path: complete the tx normally and check the patch.
        let patch_run_tx = {
            let mut tx = mock_chain
                .build_tx_context(account.id(), &input_note_ids, &[])?
                .auth_args(EMPTY_WORD);
            if let Some(script) = tx_script {
                tx = tx.tx_script(script);
            }
            tx.build()?
                .execute()
                .await
                .context("failed to execute transaction (patch run)")?
        };
        assert_eq!(*patch_run_tx.account_patch(), expected_patch);

        Ok(())
    }
}
