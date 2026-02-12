use anyhow::Context;
use assert_matches::assert_matches;
use miden_protocol::account::{AccountId, StorageMap, StorageSlot, StorageSlotName};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_NATIVE_ASSET_FAUCET;
use miden_protocol::transaction::{ExecutedTransaction, OutputNote};
use miden_protocol::{self, Felt, Word};
use miden_tx::TransactionExecutorError;
use winter_rand_utils::rand_value;

use crate::utils::create_public_p2any_note;
use crate::{Auth, MockChain};

// FEE TESTS
// ================================================================================================

/// Tests that a simple wallet account can be created with non-zero fees.
#[tokio::test]
async fn create_account_with_fees() -> anyhow::Result<()> {
    let note_amount = 10_000;

    let mut builder = MockChain::builder().verification_base_fee(50);
    let account = builder.create_new_wallet(Auth::IncrNonce)?;
    let fee_note = builder.add_p2id_note_with_fee(account.id(), note_amount)?;
    let chain = builder.build()?;

    let tx = chain
        .build_tx_context(account, &[fee_note.id()], &[])?
        .build()?
        .execute()
        .await
        .context("failed to execute account-creating transaction")?;

    let expected_fee = tx.compute_fee();
    assert_eq!(expected_fee, tx.fee().amount());

    // We expect that the new account contains the note_amount minus the paid fee.
    let added_asset = FungibleAsset::new(chain.native_asset_id(), note_amount)?.sub(tx.fee())?;

    assert_eq!(tx.account_delta().nonce_delta(), Felt::new(1));
    // except for the nonce, the storage delta should be empty
    assert!(tx.account_delta().storage().is_empty());
    assert_eq!(tx.account_delta().vault().added_assets().count(), 1);
    assert_eq!(tx.account_delta().vault().removed_assets().count(), 0);
    assert_eq!(tx.account_delta().vault().added_assets().next().unwrap(), added_asset.into());
    assert_eq!(tx.final_account().nonce(), Felt::new(1));
    // account commitment should not be the empty word
    assert_ne!(tx.account_delta().to_commitment(), Word::empty());

    Ok(())
}

/// Tests that the transaction executor host aborts the transaction if the balance of the native
/// asset in the account does not cover the computed fee.
#[tokio::test]
async fn tx_host_aborts_if_account_balance_does_not_cover_fee() -> anyhow::Result<()> {
    let account_amount = 100;
    let note_amount = 100;
    let native_asset_id = AccountId::try_from(ACCOUNT_ID_NATIVE_ASSET_FAUCET)?;

    let mut builder =
        MockChain::builder().native_asset_id(native_asset_id).verification_base_fee(50);
    let native_asset = FungibleAsset::new(native_asset_id, account_amount)?;
    let account =
        builder.add_existing_wallet_with_assets(Auth::IncrNonce, [native_asset.into()])?;
    let fee_note = builder.add_p2id_note_with_fee(account.id(), note_amount)?;
    let chain = builder.build()?;

    let err = chain
        .build_tx_context(account, &[fee_note.id()], &[])?
        .build()?
        .execute()
        .await
        .unwrap_err();

    assert_matches!(
        err,
        TransactionExecutorError::InsufficientFee { account_balance, tx_fee: _ } => {
            assert_eq!(account_balance, account_amount + note_amount);
        }
    );

    Ok(())
}

/// Tests that the _actual_ number of cycles after compute_fee is called are less than the
/// _predicted_ number of cycles (based on the constants) across a diverse set of transactions.
///
/// TODO: Once smt::set supports multiple leaves, this case should be tested explicitly here.
#[rstest::rstest]
#[case::create_account_no_storage(create_account_no_storage_no_fees().await?)]
#[case::mutate_account_with_storage(mutate_account_with_storage().await?)]
#[case::create_output_notes(create_output_notes().await?)]
#[tokio::test]
async fn num_tx_cycles_after_compute_fee_are_less_than_estimated(
    #[case] tx: ExecutedTransaction,
) -> anyhow::Result<()> {
    // These constants should always be updated together with the equivalent constants in
    // epilogue.masm.
    const SMT_SET_ADDITIONAL_CYCLES: usize = 250;
    const NUM_POST_COMPUTE_FEE_CYCLES: usize = 500;

    assert!(
        tx.measurements().after_tx_cycles_obtained
            < NUM_POST_COMPUTE_FEE_CYCLES + SMT_SET_ADDITIONAL_CYCLES,
        "estimated number of cycles is not larger than the measurements, so they need to be updated"
    );

    Ok(())
}

/// Returns a transaction that creates an account without storage and 0 fees.
async fn create_account_no_storage_no_fees() -> anyhow::Result<ExecutedTransaction> {
    let mut builder = MockChain::builder();
    let account = builder.create_new_wallet(Auth::IncrNonce)?;
    builder
        .build()?
        .build_tx_context(account, &[], &[])?
        .build()?
        .execute()
        .await
        .map_err(From::from)
}

/// Returns a transaction that mutates an account with storage and consumes a note.
async fn mutate_account_with_storage() -> anyhow::Result<ExecutedTransaction> {
    let native_asset_id = AccountId::try_from(ACCOUNT_ID_NATIVE_ASSET_FAUCET)?;
    let native_asset = FungibleAsset::new(native_asset_id, 10_000)?;
    let mut builder =
        MockChain::builder().native_asset_id(native_asset_id).verification_base_fee(100);
    let account = builder.add_existing_mock_account_with_storage_and_assets(
        Auth::IncrNonce,
        [
            StorageSlot::with_value(StorageSlotName::mock(0), rand_value()),
            StorageSlot::with_map(
                StorageSlotName::mock(1),
                StorageMap::with_entries([(rand_value(), rand_value())])?,
            ),
        ],
        [Asset::from(native_asset), NonFungibleAsset::mock(&[1, 2, 3, 4])],
    )?;
    let p2id_note = builder.add_p2id_note(
        account.id(),
        account.id(),
        &[FungibleAsset::mock(250)],
        NoteType::Public,
    )?;
    builder
        .build()?
        .build_tx_context(account, &[p2id_note.id()], &[])?
        .build()?
        .execute()
        .await
        .map_err(From::from)
}

/// Returns a transaction that consumes two notes and creates two notes.
async fn create_output_notes() -> anyhow::Result<ExecutedTransaction> {
    let native_asset_id = AccountId::try_from(ACCOUNT_ID_NATIVE_ASSET_FAUCET)?;
    let native_asset = FungibleAsset::new(native_asset_id, 10_000)?;
    let mut builder =
        MockChain::builder().native_asset_id(native_asset_id).verification_base_fee(20);
    let account = builder.add_existing_mock_account_with_storage_and_assets(
        Auth::IncrNonce,
        [
            StorageSlot::with_map(
                StorageSlotName::mock(0),
                StorageMap::with_entries([(rand_value(), rand_value())])?,
            ),
            StorageSlot::with_value(StorageSlotName::mock(1), rand_value()),
        ],
        [Asset::from(native_asset), NonFungibleAsset::mock(&[1, 2, 3, 4])],
    )?;
    let note_asset0 = FungibleAsset::mock(200).unwrap_fungible();
    let note_asset1 = FungibleAsset::mock(500).unwrap_fungible();

    // This creates a note that adds the given assets to the account vault.
    let asset_note =
        create_public_p2any_note(account.id(), [Asset::from(note_asset0.add(note_asset1)?)]);
    builder.add_output_note(OutputNote::Full(asset_note.clone()));

    let output_note0 = create_public_p2any_note(account.id(), [note_asset0.into()]);
    let output_note1 = create_public_p2any_note(account.id(), [note_asset1.into()]);

    let spawn_note = builder.add_spawn_note([&output_note0, &output_note1])?;
    builder
        .build()?
        .build_tx_context(account, &[asset_note.id(), spawn_note.id()], &[])?
        .extend_expected_output_notes(vec![
            OutputNote::Full(output_note0),
            OutputNote::Full(output_note1),
        ])
        .build()?
        .execute()
        .await
        .map_err(From::from)
}
