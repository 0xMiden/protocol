use alloc::vec::Vec;
use std::collections::BTreeMap;
use std::string::String;

use anyhow::Context;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountDelta,
    AccountId,
    AccountStorage,
    AccountStorageMode,
    AccountType,
    StorageMap,
    StorageSlot,
    StorageSlotDelta,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, AssetVault, FungibleAsset, NonFungibleAsset};
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_SENDER,
    AccountIdBuilder,
};
use miden_protocol::testing::asset::NonFungibleAssetBuilder;
use miden_protocol::testing::constants::{
    CONSUMED_ASSET_1_AMOUNT,
    CONSUMED_ASSET_3_AMOUNT,
    FUNGIBLE_ASSET_AMOUNT,
    NON_FUNGIBLE_ASSET_DATA,
    NON_FUNGIBLE_ASSET_DATA_2,
};
use miden_protocol::testing::storage::{MOCK_MAP_SLOT, MOCK_VALUE_SLOT0};
use miden_protocol::transaction::TransactionScript;
use miden_protocol::{EMPTY_WORD, Felt, FieldElement, LexicographicWord, Word, ZERO};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_tx::LocalTransactionProver;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use winter_rand_utils::rand_value;

use crate::utils::create_public_p2any_note;
use crate::{Auth, MockChain, TransactionContextBuilder};

// ACCOUNT DELTA TESTS
//
// Note that in all of these tests, the transaction executor will ensure that the account delta
// commitment computed in-kernel and in the host match.
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

/// Tests that a noop transaction with [`Auth::IncrNonce`] results in a nonce delta of 1.
#[tokio::test]
async fn delta_nonce() -> anyhow::Result<()> {
    let TestSetup { mock_chain, account_id, .. } = setup_test([], [], [])?;

    let executed_tx = mock_chain
        .build_tx_context(account_id, &[], &[])
        .expect("failed to build tx context")
        .build()?
        .execute()
        .await
        .context("failed to execute transaction")?;

    assert_eq!(executed_tx.account_delta().nonce_delta(), Felt::new(1));

    Ok(())
}

/// Tests that setting new values for value storage slots results in the correct delta.
///
/// - Slot 0: [2,4,6,8]  -> [3,4,5,6] -> EMPTY_WORD -> Delta: EMPTY_WORD
/// - Slot 1: EMPTY_WORD -> [3,4,5,6]               -> Delta: [3,4,5,6]
/// - Slot 2: [1,3,5,7]  -> [1,3,5,7]               -> Delta: None
/// - Slot 3: [1,3,5,7]  -> [2,3,4,5] -> [1,3,5,7]  -> Delta: None
#[tokio::test]
async fn storage_delta_for_value_slots() -> anyhow::Result<()> {
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

    let TestSetup { mock_chain, account_id, .. } = setup_test(
        vec![
            StorageSlot::with_value(slot_0_name.clone(), slot_0_init_value),
            StorageSlot::with_value(slot_1_name.clone(), slot_1_init_value),
            StorageSlot::with_value(slot_2_name.clone(), slot_2_init_value),
            StorageSlot::with_value(slot_3_name.clone(), slot_3_init_value),
        ],
        [],
        [],
    )?;

    let tx_script = parse_tx_script(format!(
        r#"
      const SLOT_0_NAME = word("{slot_0_name}")
      const SLOT_1_NAME = word("{slot_1_name}")
      const SLOT_2_NAME = word("{slot_2_name}")
      const SLOT_3_NAME = word("{slot_3_name}")

      begin
          push.{slot_0_tmp_value}
          push.SLOT_0_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, VALUE]
          exec.set_item
          # => []

          push.{slot_0_final_value}
          push.SLOT_0_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, VALUE]
          exec.set_item
          # => []

          push.{slot_1_final_value}
          push.SLOT_1_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, VALUE]
          exec.set_item
          # => []

          push.{slot_2_final_value}
          push.SLOT_2_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, VALUE]
          exec.set_item
          # => []

          push.{slot_3_tmp_value}
          push.SLOT_3_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, VALUE]
          exec.set_item
          # => []

          push.{slot_3_final_value}
          push.SLOT_3_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, VALUE]
          exec.set_item
          # => []
      end
      "#
    ))?;

    let executed_tx = mock_chain
        .build_tx_context(account_id, &[], &[])
        .expect("failed to build tx context")
        .tx_script(tx_script)
        .build()?
        .execute()
        .await
        .context("failed to execute transaction")?;

    let storage_values_delta = executed_tx
        .account_delta()
        .storage()
        .values()
        .map(|(slot_name, value)| (slot_name.clone(), *value))
        .collect::<BTreeMap<_, _>>();

    // Note that slots 2 and 3 are absent because their values haven't effectively changed.
    assert_eq!(
        storage_values_delta,
        BTreeMap::from_iter([(slot_0_name, slot_0_final_value), (slot_1_name, slot_1_final_value)])
    );

    Ok(())
}

/// Tests that setting new values for map storage slots results in the correct delta.
///
/// - Slot 0: key0: EMPTY_WORD -> [1,2,3,4]              -> Delta: [1,2,3,4]
/// - Slot 0: key1: EMPTY_WORD -> [1,2,3,4] -> [2,3,4,5] -> Delta: [2,3,4,5]
/// - Slot 1: key2: [1,2,3,4]  -> [1,2,3,4]              -> Delta: None
/// - Slot 1: key3: [1,2,3,4]  -> EMPTY_WORD             -> Delta: EMPTY_WORD
/// - Slot 1: key4: [1,2,3,4]  -> [2,3,4,5] -> [1,2,3,4] -> Delta: None
/// - Slot 2: key5: [1,2,3,4]  -> [2,3,4,5] -> [1,2,3,4] -> Delta: None
///   - key5 and key4 are the same scenario, but in different slots. In particular, slot 2's delta
///     map will be empty after normalization and so it shouldn't be present in the delta at all.
#[tokio::test]
async fn storage_delta_for_map_slots() -> anyhow::Result<()> {
    // Test with random keys to make sure the ordering in the MASM and Rust implementations
    // matches.
    let key0 = rand_value::<Word>();
    let key1 = rand_value::<Word>();
    let key2 = rand_value::<Word>();
    let key3 = rand_value::<Word>();
    let key4 = rand_value::<Word>();
    let key5 = rand_value::<Word>();

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

    let TestSetup { mock_chain, account_id, .. } = setup_test(
        vec![
            StorageSlot::with_map(slot_0_name.clone(), map0),
            StorageSlot::with_map(slot_1_name.clone(), map1),
            StorageSlot::with_map(slot_2_name.clone(), map2),
            // Include an empty map which does not receive any updates, to test that the "metadata
            // header" in the delta commitment is not appended if there are no updates to a map
            // slot.
            StorageSlot::with_map(StorageSlotName::mock(3), StorageMap::new()),
        ],
        [],
        [],
    )?;

    let tx_script = parse_tx_script(format!(
        r#"
      const SLOT_0_NAME = word("{slot_0_name}")
      const SLOT_1_NAME = word("{slot_1_name}")
      const SLOT_2_NAME = word("{slot_2_name}")

      begin
          push.{key0_final_value} push.{key0}
          push.SLOT_0_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key1_tmp_value} push.{key1}
          push.SLOT_0_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key1_final_value} push.{key1}
          push.SLOT_0_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key2_final_value} push.{key2}
          push.SLOT_1_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key3_final_value} push.{key3}
          push.SLOT_1_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key4_tmp_value} push.{key4}
          push.SLOT_1_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key4_final_value} push.{key4}
          push.SLOT_1_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key5_tmp_value} push.{key5}
          push.SLOT_2_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
          exec.set_map_item
          # => []

          push.{key5_final_value} push.{key5}
          push.SLOT_2_NAME[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
          exec.set_map_item
          # => []
      end
      "#
    ))?;

    let executed_tx = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await
        .context("failed to execute transaction")?;
    let maps_delta = executed_tx.account_delta().storage().maps().collect::<BTreeMap<_, _>>();

    // Note that there should be no delta for map2 since it was normalized to an empty map which
    // should be removed.
    assert_eq!(maps_delta.len(), 2);
    assert!(!maps_delta.contains_key(&slot_2_name), "map2 should not have a delta");

    let mut map0_delta = maps_delta
        .get(&slot_0_name)
        .map(|map_delta| (*map_delta).clone())
        .expect("delta for map 0 should exist")
        .into_map();

    let mut map1_delta = maps_delta
        .get(&slot_1_name)
        .map(|map_delta| (*map_delta).clone())
        .expect("delta for map 1 should exist")
        .clone()
        .into_map();

    assert_eq!(map0_delta.len(), 2);
    assert_eq!(map0_delta.remove(&LexicographicWord::new(key0)).unwrap(), key0_final_value);
    assert_eq!(map0_delta.remove(&LexicographicWord::new(key1)).unwrap(), key1_final_value);

    assert_eq!(map1_delta.len(), 1);
    assert_eq!(map1_delta.remove(&LexicographicWord::new(key3)).unwrap(), key3_final_value);

    Ok(())
}

/// Tests that increasing, decreasing the amount of a fungible asset results in the correct delta.
/// - Asset0 is increased by 100 and decreased by 200 -> Delta: -100.
/// - Asset1 is increased by 100 and decreased by 100 -> Delta: 0.
/// - Asset2 is increased by 200 and decreased by 100 -> Delta: 100.
/// - Asset3 is decreased by [`FungibleAsset::MAX_AMOUNT`] -> Delta: -MAX_AMOUNT.
/// - Asset4 is increased by [`FungibleAsset::MAX_AMOUNT`] -> Delta: MAX_AMOUNT.
#[tokio::test]
async fn fungible_asset_delta() -> anyhow::Result<()> {
    // Test with random IDs to make sure the ordering in the MASM and Rust implementations
    // matches.
    let faucet0: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::FungibleFaucet)
        .build_with_seed(rand::random());
    let faucet1: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::FungibleFaucet)
        .build_with_seed(rand::random());
    let faucet2: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::FungibleFaucet)
        .build_with_seed(rand::random());
    let faucet3: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::FungibleFaucet)
        .build_with_seed(rand::random());
    let faucet4: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::FungibleFaucet)
        .build_with_seed(rand::random());

    let original_asset0 = FungibleAsset::new(faucet0, 300)?;
    let original_asset1 = FungibleAsset::new(faucet1, 200)?;
    let original_asset2 = FungibleAsset::new(faucet2, 100)?;
    let original_asset3 = FungibleAsset::new(faucet3, FungibleAsset::MAX_AMOUNT)?;

    let added_asset0 = FungibleAsset::new(faucet0, 100)?;
    let added_asset1 = FungibleAsset::new(faucet1, 100)?;
    let added_asset2 = FungibleAsset::new(faucet2, 200)?;
    let added_asset4 = FungibleAsset::new(faucet4, FungibleAsset::MAX_AMOUNT)?;

    let removed_asset0 = FungibleAsset::new(faucet0, 200)?;
    let removed_asset1 = FungibleAsset::new(faucet1, 100)?;
    let removed_asset2 = FungibleAsset::new(faucet2, 100)?;
    let removed_asset3 = FungibleAsset::new(faucet3, FungibleAsset::MAX_AMOUNT)?;

    let TestSetup { mock_chain, account_id, notes } = setup_test(
        [],
        [original_asset0, original_asset1, original_asset2, original_asset3].map(Asset::from),
        [added_asset0, added_asset1, added_asset2, added_asset4].map(Asset::from),
    )?;

    let tx_script = parse_tx_script(format!(
        "
    begin
        push.{asset0} exec.create_note_with_asset
        # => []
        push.{asset1} exec.create_note_with_asset
        # => []
        push.{asset2} exec.create_note_with_asset
        # => []
        push.{asset3} exec.create_note_with_asset
        # => []
    end
    ",
        asset0 = Word::from(removed_asset0),
        asset1 = Word::from(removed_asset1),
        asset2 = Word::from(removed_asset2),
        asset3 = Word::from(removed_asset3),
    ))?;

    let executed_tx = mock_chain
        .build_tx_context(account_id, &notes.iter().map(Note::id).collect::<Vec<_>>(), &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await
        .context("failed to execute transaction")?;

    let mut added_assets = executed_tx
        .account_delta()
        .vault()
        .added_assets()
        .map(|asset| (asset.unwrap_fungible().faucet_id(), asset.unwrap_fungible().amount()))
        .collect::<BTreeMap<_, _>>();
    let mut removed_assets = executed_tx
        .account_delta()
        .vault()
        .removed_assets()
        .map(|asset| (asset.unwrap_fungible().faucet_id(), asset.unwrap_fungible().amount()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(added_assets.len(), 2);
    assert_eq!(removed_assets.len(), 2);

    assert_eq!(
        added_assets.remove(&original_asset2.faucet_id()).unwrap(),
        added_asset2.amount() - removed_asset2.amount()
    );
    assert_eq!(added_assets.remove(&added_asset4.faucet_id()).unwrap(), added_asset4.amount());

    assert_eq!(
        removed_assets.remove(&original_asset0.faucet_id()).unwrap(),
        removed_asset0.amount() - added_asset0.amount()
    );
    assert_eq!(
        removed_assets.remove(&original_asset3.faucet_id()).unwrap(),
        removed_asset3.amount()
    );

    Ok(())
}

/// Tests that adding, removing non-fungible assets results in the correct delta.
/// - Asset0 is added to the vault -> Delta: Add.
/// - Asset1 is removed from the vault -> Delta: Remove.
/// - Asset2 is added and removed -> Delta: No Change.
/// - Asset3 is removed and added -> Delta: No Change.
#[tokio::test]
async fn non_fungible_asset_delta() -> anyhow::Result<()> {
    let mut rng = rand::rng();
    // Test with random IDs to make sure the ordering in the MASM and Rust implementations
    // matches.
    let faucet0: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::NonFungibleFaucet)
        .build_with_seed(rng.random());
    let faucet1: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::NonFungibleFaucet)
        .build_with_seed(rng.random());
    let faucet2: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::NonFungibleFaucet)
        .build_with_seed(rng.random());
    let faucet3: AccountId = AccountIdBuilder::new()
        .account_type(AccountType::NonFungibleFaucet)
        .build_with_seed(rng.random());

    let asset0 = NonFungibleAssetBuilder::new(faucet0.prefix(), &mut rng)?.build()?;
    let asset1 = NonFungibleAssetBuilder::new(faucet1.prefix(), &mut rng)?.build()?;
    let asset2 = NonFungibleAssetBuilder::new(faucet2.prefix(), &mut rng)?.build()?;
    let asset3 = NonFungibleAssetBuilder::new(faucet3.prefix(), &mut rng)?.build()?;

    let TestSetup { mock_chain, account_id, notes } =
        setup_test([], [asset1, asset3].map(Asset::from), [asset0, asset2].map(Asset::from))?;

    let tx_script = parse_tx_script(format!(
        "
    begin
        push.{asset1} exec.create_note_with_asset
        # => []
        push.{asset2} exec.create_note_with_asset
        # => []

        # remove and re-add asset 3
        push.{asset3}
        exec.remove_asset
        # => [ASSET]
        exec.add_asset dropw
        # => []
    end
    ",
        asset1 = Word::from(asset1),
        asset2 = Word::from(asset2),
        asset3 = Word::from(asset3),
    ))?;

    let executed_tx = mock_chain
        .build_tx_context(account_id, &notes.iter().map(Note::id).collect::<Vec<_>>(), &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await
        .context("failed to execute transaction")?;

    let mut added_assets = executed_tx
        .account_delta()
        .vault()
        .added_assets()
        .map(|asset| (asset.faucet_id_prefix(), asset.unwrap_non_fungible()))
        .collect::<BTreeMap<_, _>>();
    let mut removed_assets = executed_tx
        .account_delta()
        .vault()
        .removed_assets()
        .map(|asset| (asset.faucet_id_prefix(), asset.unwrap_non_fungible()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(added_assets.len(), 1);
    assert_eq!(removed_assets.len(), 1);

    assert_eq!(added_assets.remove(&asset0.faucet_id_prefix()).unwrap(), asset0);
    assert_eq!(removed_assets.remove(&asset1.faucet_id_prefix()).unwrap(), asset1);

    Ok(())
}

/// Tests that adding and removing assets and updating value and map storage slots results in the
/// correct delta.
#[tokio::test]
async fn asset_and_storage_delta() -> anyhow::Result<()> {
    let account_assets = AssetVault::mock().assets().collect::<Vec<Asset>>();

    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()))
        .with_assets(account_assets)
        .build_existing()?;

    // updated storage
    let updated_slot_value = Word::from([7, 9, 11, 13u32]);

    // updated storage map
    let updated_map_key = Word::from([14, 15, 16, 17u32]);
    let updated_map_value = Word::from([18, 19, 20, 21u32]);

    // removed assets
    let removed_asset_1 = FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT / 2);
    let removed_asset_2 = Asset::Fungible(
        FungibleAsset::new(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().expect("id is valid"),
            FUNGIBLE_ASSET_AMOUNT,
        )
        .expect("asset is valid"),
    );
    let removed_asset_3 = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA);
    let removed_assets = [removed_asset_1, removed_asset_2, removed_asset_3];

    let tag1 =
        NoteTag::with_account_target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into()?);
    let tag2 = NoteTag::default();
    let tag3 = NoteTag::default();
    let tags = [tag1, tag2, tag3];

    let note_types = [NoteType::Private; 3];

    let mut send_asset_script = String::new();
    for i in 0..3 {
        send_asset_script.push_str(&format!(
            "
            ### note {i}
            # prepare the stack for a new note creation
            push.0.1.2.3           # recipient
            push.{NOTETYPE}        # note_type
            push.{tag}             # tag
            # => [tag, note_type, RECIPIENT]

            # create the note
            exec.output_note::create
            # => [note_idx, pad(15)]

            # move an asset to the created note to partially deplete fungible asset balance
            swapw dropw push.{REMOVED_ASSET}
            call.::miden::standards::wallets::basic::move_asset_to_note
            # => [ASSET, note_idx, pad(11)]

            # clear the stack
            dropw dropw dropw dropw
        ",
            NOTETYPE = note_types[i] as u8,
            tag = tags[i],
            REMOVED_ASSET = Word::from(removed_assets[i])
        ));
    }

    let tx_script_src = format!(
        r#"
        use mock::account
        use miden::protocol::output_note

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")
        const MOCK_MAP_SLOT = word("{mock_map_slot}")

        ## TRANSACTION SCRIPT
        ## ========================================================================================
        begin
            ## Update account storage item
            ## ------------------------------------------------------------------------------------
            # push a new value for the storage slot onto the stack
            push.{updated_slot_value}
            # => [13, 11, 9, 7]

            # get the index of account storage slot
            push.MOCK_VALUE_SLOT0[0..2]
            # => [slot_id_prefix, slot_id_suffix, 13, 11, 9, 7]
            # update the storage value
            call.account::set_item dropw
            # => []

            ## Update account storage map
            ## ------------------------------------------------------------------------------------
            # push a new VALUE for the storage map onto the stack
            push.{updated_map_value}
            # => [18, 19, 20, 21]

            # push a new KEY for the storage map onto the stack
            push.{updated_map_key}
            # => [14, 15, 16, 17, 18, 19, 20, 21]

            # get the index of account storage slot
            push.MOCK_MAP_SLOT[0..2]
            # => [slot_id_prefix, slot_id_suffix, 14, 15, 16, 17, 18, 19, 20, 21]

            # update the storage value
            call.account::set_map_item dropw dropw dropw
            # => []

            ## Send some assets from the account vault
            ## ------------------------------------------------------------------------------------
            {send_asset_script}

            dropw dropw dropw dropw
        end
    "#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
        mock_map_slot = &*MOCK_MAP_SLOT,
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_src)?;

    // Create the input note that carries the assets that we will assert later
    let input_note = {
        let faucet_id_1 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?;
        let faucet_id_3 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3)?;

        let fungible_asset_1: Asset =
            FungibleAsset::new(faucet_id_1, CONSUMED_ASSET_1_AMOUNT)?.into();
        let fungible_asset_3: Asset =
            FungibleAsset::new(faucet_id_3, CONSUMED_ASSET_3_AMOUNT)?.into();
        let nonfungible_asset_1: Asset = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA_2);

        create_public_p2any_note(
            account.id(),
            [fungible_asset_1, fungible_asset_3, nonfungible_asset_1],
        )
    };

    let tx_context = TransactionContextBuilder::new(account)
        .extend_input_notes(vec![input_note.clone()])
        .tx_script(tx_script)
        .build()?;

    // Storing assets that will be added to assert correctness later
    let added_assets = input_note.assets().iter().cloned().collect::<Vec<_>>();

    // expected delta
    // --------------------------------------------------------------------------------------------
    // execute the transaction and get the witness
    let executed_transaction = tx_context.execute().await?;

    // nonce delta
    // --------------------------------------------------------------------------------------------

    assert_eq!(executed_transaction.account_delta().nonce_delta(), Felt::new(1));

    // storage delta
    // --------------------------------------------------------------------------------------------
    // We expect one updated item and one updated map
    assert_eq!(executed_transaction.account_delta().storage().values().count(), 1);
    assert_eq!(
        executed_transaction
            .account_delta()
            .storage()
            .get(&MOCK_VALUE_SLOT0)
            .cloned()
            .map(StorageSlotDelta::unwrap_value),
        Some(updated_slot_value)
    );

    assert_eq!(executed_transaction.account_delta().storage().maps().count(), 1);
    let map_delta = executed_transaction
        .account_delta()
        .storage()
        .get(&MOCK_MAP_SLOT)
        .cloned()
        .map(StorageSlotDelta::unwrap_map)
        .unwrap();
    assert_eq!(
        *map_delta.entries().get(&LexicographicWord::new(updated_map_key)).unwrap(),
        updated_map_value
    );

    // vault delta
    // --------------------------------------------------------------------------------------------
    // assert that added assets are tracked
    assert!(
        executed_transaction
            .account_delta()
            .vault()
            .added_assets()
            .all(|x| added_assets.contains(&x))
    );
    assert_eq!(
        added_assets.len(),
        executed_transaction.account_delta().vault().added_assets().count()
    );

    // assert that removed assets are tracked
    assert!(
        executed_transaction
            .account_delta()
            .vault()
            .removed_assets()
            .all(|x| removed_assets.contains(&x))
    );
    assert_eq!(
        removed_assets.len(),
        executed_transaction.account_delta().vault().removed_assets().count()
    );
    Ok(())
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
    // (see also https://github.com/0xMiden/miden-base/issues/2037).
    let map0 = StorageMap::with_entries([(rand_value(), rand_value())])?;
    let map1 = map0.clone();
    let mut map2 = StorageMap::with_entries([
        (rand_value(), rand_value()),
        (rand_value(), rand_value()),
        (rand_value(), rand_value()),
        (rand_value(), rand_value()),
    ])?;

    let map0_slot_name = StorageSlotName::mock(1);
    let map1_slot_name = StorageSlotName::mock(2);
    let map2_slot_name = StorageSlotName::mock(4);

    // Build a public account so the proven transaction includes the account update.
    let account = AccountBuilder::new([1; 32])
        .storage_mode(AccountStorageMode::Public)
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
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
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
        let map_delta = tx
            .account_delta()
            .storage()
            .get(&slot_name)
            .cloned()
            .map(StorageSlotDelta::unwrap_map)
            .unwrap();
        assert_eq!(
            map_delta
                .entries()
                .iter()
                .map(|(key, value)| (key.inner(), value))
                .collect::<BTreeMap<_, _>>(),
            expected_map.entries().collect(),
            "map delta does not match for slot {slot_name}",
        );
    }

    let proven_tx = LocalTransactionProver::default().prove_dummy(tx.clone())?;

    let AccountUpdateDetails::Delta(proven_tx_delta) = proven_tx.account_update().details() else {
        panic!("expected delta");
    };

    let proven_tx_account = Account::try_from(proven_tx_delta)?;
    let exec_tx_account = Account::try_from(tx.account_delta())?;

    assert_eq!(proven_tx_account.storage(), exec_tx_account.storage());

    // Check the conversion back into a full-state delta works correctly.
    let proven_tx_delta_converted = AccountDelta::try_from(proven_tx_account)?;
    let exec_tx_delta_converted = AccountDelta::try_from(exec_tx_account)?;

    // Check that the deltas from proven and executed tx, which were converted from accounts are
    // identical. This is essentially a roundtrip test.
    assert_eq!(&proven_tx_delta_converted, proven_tx_delta);
    assert_eq!(&exec_tx_delta_converted, tx.account_delta());
    assert_eq!(&proven_tx_delta_converted, tx.account_delta());

    // The commitments should match as well.
    assert_eq!(proven_tx_delta_converted.to_commitment(), proven_tx_delta.to_commitment());
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
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Network)
        .with_component(MockAccountComponent::with_slots(vec![
            StorageSlot::with_empty_value(slot_name0.clone()),
            StorageSlot::with_value(slot_name1.clone(), slot_value2),
        ]))
        .with_auth_component(Auth::IncrNonce)
        .build()?;

    let tx = TransactionContextBuilder::new(account.clone()).build()?.execute().await?;

    let proven_tx = LocalTransactionProver::default().prove_dummy(tx.clone())?;

    let AccountUpdateDetails::Delta(delta) = proven_tx.account_update().details() else {
        panic!("expected delta");
    };

    assert_eq!(delta.storage().values().count(), 2);
    assert_eq!(
        delta
            .storage()
            .get(&slot_name0)
            .cloned()
            .map(StorageSlotDelta::unwrap_value)
            .unwrap(),
        Word::empty()
    );
    assert_eq!(
        delta
            .storage()
            .get(&slot_name1)
            .cloned()
            .map(StorageSlotDelta::unwrap_value)
            .unwrap(),
        slot_value2
    );

    let recreated_account = Account::try_from(delta)?;
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
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Network)
        .with_component(MockAccountComponent::with_slots(vec![StorageSlot::with_empty_map(
            slot_name0.clone(),
        )]))
        .with_auth_component(Auth::IncrNonce)
        .build()?;

    let tx = TransactionContextBuilder::new(account.clone()).build()?.execute().await?;

    let proven_tx = LocalTransactionProver::default().prove_dummy(tx.clone())?;

    let AccountUpdateDetails::Delta(delta) = proven_tx.account_update().details() else {
        panic!("expected delta");
    };

    assert_eq!(delta.storage().maps().count(), 1);
    assert!(
        delta
            .storage()
            .get(&slot_name0)
            .cloned()
            .map(StorageSlotDelta::unwrap_map)
            .unwrap()
            .is_empty()
    );

    let recreated_account = Account::try_from(delta)?;
    // The recreated account should match the original account with the nonce incremented (and the
    // seed removed).
    account.increment_nonce(Felt::ONE)?;
    assert_eq!(recreated_account, account);

    Ok(())
}

/// Tests that adding a fungible asset with amount zero to the account vault works and does not
/// result in an account delta entry.
#[tokio::test]
async fn adding_amount_zero_fungible_asset_to_account_vault_works() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let input_note = builder.add_p2id_note(
        account.id(),
        account.id(),
        &[FungibleAsset::mock(0)],
        NoteType::Private,
    )?;
    let chain = builder.build()?;

    let tx = chain
        .build_tx_context(account, &[input_note.id()], &[])?
        .build()?
        .execute()
        .await?;

    assert!(tx.account_delta().vault().is_empty());

    Ok(())
}

// TEST HELPERS
// ================================================================================================

struct TestSetup {
    mock_chain: MockChain,
    account_id: AccountId,
    notes: Vec<Note>,
}

fn setup_test(
    storage_slots: impl IntoIterator<Item = StorageSlot>,
    vault_assets: impl IntoIterator<Item = Asset>,
    note_assets: impl IntoIterator<Item = Asset>,
) -> anyhow::Result<TestSetup> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account_with_storage_and_assets(
        Auth::IncrNonce,
        storage_slots,
        vault_assets,
    )?;

    let mut notes = vec![];
    for note_asset in note_assets {
        let added_note = builder
            .add_p2id_note(account.id(), account.id(), &[note_asset], NoteType::Public)
            .context("failed to add note with asset")?;
        notes.push(added_note);
    }

    let mock_chain = builder.build()?;

    Ok(TestSetup {
        mock_chain,
        account_id: account.id(),
        notes,
    })
}

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
      use miden::protocol::output_note

      #! Inputs:  [slot_id_prefix, slot_id_suffix, VALUE]
      #! Outputs: []
      proc set_item
          repeat.10 push.0 movdn.6 end
          # => [slot_id_prefix, slot_id_suffix, VALUE, pad(10)]

          call.account::set_item
          # => [OLD_VALUE, pad(12)]

          dropw dropw dropw dropw
      end

      #! Inputs:  [slot_id_prefix, slot_id_suffix, KEY, VALUE]
      #! Outputs: []
      proc set_map_item
          repeat.6 push.0 movdn.10 end
          # => [index, KEY, VALUE, pad(6)]

          call.account::set_map_item
          # => [OLD_VALUE, pad(12)]

          dropw dropw dropw dropw
          # => []
      end

      #! Inputs:  [ASSET]
      #! Outputs: []
      proc create_note_with_asset
          push.0.1.2.3           # recipient
          push.2                 # note_type private
          push.0xC0000000        # tag
          # => [tag, note_type, RECIPIENT, ASSET]

          exec.output_note::create
          # => [note_idx, ASSET]

          movdn.4
          # => [ASSET, note_idx]

          exec.move_asset_to_note
          # => []
      end

      #! Inputs:  [ASSET, note_idx]
      #! Outputs: []
      proc move_asset_to_note
          repeat.11 push.0 movdn.5 end
          # => [ASSET, note_idx, pad(11)]

          call.account::move_asset_to_note

          # return values are unused
          dropw dropw dropw dropw
      end

      #! Inputs:  [ASSET]
      #! Outputs: [ASSET']
      proc add_asset
          repeat.12 push.0 movdn.4 end
          # => [ASSET, pad(12)]

          call.account::add_asset
          # => [ASSET', pad(12)]

          repeat.12 movup.4 drop end
          # => [ASSET']
      end

      #! Inputs:  [ASSET]
      #! Outputs: [ASSET]
      proc remove_asset
          repeat.12 push.0 movdn.4 end
          # => [ASSET, pad(12)]

          call.account::remove_asset
          # => [ASSET, pad(12)]

          repeat.12 movup.4 drop end
          # => [ASSET]
      end
";
