//! This module tests lazy loading.
//!
//! Once lazy loading is enabled generally, it can be removed and/or integrated into other tests.

use miden_protocol::LexicographicWord;
use miden_protocol::account::{AccountId, AccountStorage, StorageSlotDelta};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_NATIVE_ASSET_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
};
use miden_protocol::testing::constants::FUNGIBLE_ASSET_AMOUNT;
use miden_protocol::testing::storage::MOCK_MAP_SLOT;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::note::NoteBuilder;

use super::Word;
use crate::{Auth, MockChain, TransactionContextBuilder};

// ASSET LAZY LOADING
// ================================================================================================

/// Tests that adding two different assets to the account vault succeeds when lazy loading is
/// enabled.
#[tokio::test]
async fn adding_fungible_assets_with_lazy_loading_succeeds() -> anyhow::Result<()> {
    let faucet_id1: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let faucet_id2: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().unwrap();

    let fungible_asset1 =
        FungibleAsset::new(faucet_id1, FungibleAsset::MAX_AMOUNT - FUNGIBLE_ASSET_AMOUNT)?;
    let fungible_asset2 = FungibleAsset::new(faucet_id2, FUNGIBLE_ASSET_AMOUNT)?;

    // Build a note that adds the assets to the input vault of the transaction. This is necessary
    // to adhere to asset preservation rules.
    let asset_note = NoteBuilder::new(faucet_id1, rand::rng())
        .add_assets([fungible_asset1, fungible_asset2].map(Asset::from))
        .build()?;

    let code = format!(
        "
      use mock::account

      begin
          push.{FUNGIBLE_ASSET1}
          call.account::add_asset dropw

          push.{FUNGIBLE_ASSET2}
          call.account::add_asset dropw
      end
      ",
        FUNGIBLE_ASSET1 = Word::from(fungible_asset1),
        FUNGIBLE_ASSET2 = Word::from(fungible_asset2)
    );

    let builder = CodeBuilder::with_mock_libraries();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;
    let tx_context = TransactionContextBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .extend_input_notes(vec![asset_note])
        .with_source_manager(source_manager)
        .build()?;
    let account = tx_context.account().clone();
    let tx = tx_context.execute().await?;

    let mut account_vault = account.vault().clone();
    account_vault.add_asset(fungible_asset1.into())?;
    account_vault.add_asset(fungible_asset2.into())?;

    assert_eq!(tx.final_account().vault_root(), account_vault.root());

    Ok(())
}

/// Tests that removing two different assets from the account vault succeeds when lazy loading is
/// enabled.
#[tokio::test]
async fn removing_fungible_assets_with_lazy_loading_succeeds() -> anyhow::Result<()> {
    let faucet_id1: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let faucet_id2: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().unwrap();

    let fungible_asset1 =
        FungibleAsset::new(faucet_id1, FungibleAsset::MAX_AMOUNT - FUNGIBLE_ASSET_AMOUNT)?;
    let fungible_asset2 = FungibleAsset::new(faucet_id2, FUNGIBLE_ASSET_AMOUNT)?;

    let code = format!(
        "
      use mock::account
      use mock::util

      begin
          push.{FUNGIBLE_ASSET1}
          call.account::remove_asset
          # => []

          # move asset to note to adhere to asset preservation rules
          exec.util::create_default_note_with_asset
          # => []

          push.{FUNGIBLE_ASSET2}
          call.account::remove_asset
          # => [ASSET]

          # move asset to note to adhere to asset preservation rules
          exec.util::create_default_note_with_asset
          # => []
      end
      ",
        FUNGIBLE_ASSET1 = Word::from(fungible_asset1),
        FUNGIBLE_ASSET2 = Word::from(fungible_asset2)
    );

    let builder = CodeBuilder::with_mock_libraries();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;

    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account_with_assets(
        crate::Auth::IncrNonce,
        [fungible_asset1, fungible_asset2].map(Asset::from),
    )?;
    let tx_context = builder
        .build()?
        .build_tx_context(account, &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;
    let account = tx_context.account().clone();
    let tx = tx_context.execute().await?;

    let mut account_vault = account.vault().clone();
    account_vault.remove_asset(fungible_asset1.into())?;
    account_vault.remove_asset(fungible_asset2.into())?;

    assert_eq!(tx.final_account().vault_root(), account_vault.root());

    Ok(())
}

/// Tests that a transaction against an account with a non-empty vault successfully loads the fee
/// asset during the epilogue.
///
/// The non-empty vault is important for the test because the advice provider's merkle store has all
/// merkle paths for an empty vault by default, and so there would be nothing to load.
#[tokio::test]
async fn loading_fee_asset_succeeds() -> anyhow::Result<()> {
    let mut builder =
        MockChain::builder().native_asset_id(ACCOUNT_ID_NATIVE_ASSET_FAUCET.try_into()?);
    let account = builder.add_existing_mock_account_with_assets(
        Auth::IncrNonce,
        [
            FungibleAsset::mock(23),
            FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?, 50)?.into(),
        ],
    )?;
    builder.build()?.build_tx_context(account, &[], &[])?.build()?.execute().await?;

    Ok(())
}

// STORAGE LAZY LOADING
// ================================================================================================

/// Tests that updating or inserting a map item into a storage map succeeds when lazy loading is
/// enabled.
#[tokio::test]
async fn setting_map_item_with_lazy_loading_succeeds() -> anyhow::Result<()> {
    // Fetch a random existing key from the map.
    let mock_map = AccountStorage::mock_map();
    let existing_key = *mock_map.entries().next().unwrap().0;

    let non_existent_key = Word::from([5, 5, 5, 5u32]);
    assert!(
        mock_map.open(&non_existent_key).get(&non_existent_key).unwrap() == Word::empty(),
        "test setup requires that the non existent key does not exist"
    );

    // The slot name of the mock map in account storage.
    let mock_map_slot = &*MOCK_MAP_SLOT;

    let value0 = Word::from([3, 4, 5, 6u32]);
    let value1 = Word::from([9, 8, 7, 6u32]);

    let code = format!(
        r#"
      use mock::account

      const MOCK_MAP_SLOT = word("{mock_map_slot}")

      begin
          # Update an existing key.
          push.{value0}
          push.{existing_key}
          push.MOCK_MAP_SLOT[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
          call.account::set_map_item

          # Insert a non-existent key.
          push.{value1}
          push.{non_existent_key}
          push.MOCK_MAP_SLOT[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]
          call.account::set_map_item

          exec.::miden::core::sys::truncate_stack
      end
      "#
    );

    let builder = CodeBuilder::with_mock_libraries();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;

    let tx = TransactionContextBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    let map_delta = tx
        .account_delta()
        .storage()
        .get(mock_map_slot)
        .cloned()
        .map(StorageSlotDelta::unwrap_map)
        .unwrap();
    assert_eq!(map_delta.entries().get(&LexicographicWord::new(existing_key)).unwrap(), &value0);
    assert_eq!(
        map_delta.entries().get(&LexicographicWord::new(non_existent_key)).unwrap(),
        &value1
    );

    Ok(())
}

/// Tests that getting a map item from a storage map succeeds when lazy loading is enabled.
#[tokio::test]
async fn getting_map_item_with_lazy_loading_succeeds() -> anyhow::Result<()> {
    // Fetch a random existing key from the map.
    let mock_map = AccountStorage::mock_map();
    let (existing_key, existing_value) = mock_map.entries().next().unwrap();

    let non_existent_key = Word::from([5, 5, 5, 5u32]);
    assert!(
        mock_map.open(&non_existent_key).get(&non_existent_key).unwrap() == Word::empty(),
        "test setup requires that the non existent key does not exist"
    );

    let mock_map_slot = &*MOCK_MAP_SLOT;

    let code = format!(
        r#"
      use miden::core::word
      use mock::account

      const MOCK_MAP_SLOT = word("{mock_map_slot}")

      begin
          # Fetch value from existing key.
          push.{existing_key}
          push.MOCK_MAP_SLOT[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY]
          call.account::get_map_item

          push.{existing_value}
          assert_eqw.err="existing value does not match expected value"

          # Fetch a non-existent key.
          push.{non_existent_key}
          push.MOCK_MAP_SLOT[0..2]
          # => [slot_id_prefix, slot_id_suffix, KEY]
          call.account::get_map_item

          padw assert_eqw.err="non-existent value should be the empty word"

          exec.::miden::core::sys::truncate_stack
      end
      "#
    );

    let builder = CodeBuilder::with_mock_libraries();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;

    TransactionContextBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    Ok(())
}
