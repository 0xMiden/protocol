use assert_matches::assert_matches;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
use miden_protocol::errors::AssetVaultError;
use miden_protocol::errors::tx_kernel::{
    ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW,
    ERR_VAULT_FUNGIBLE_MAX_AMOUNT_EXCEEDED,
    ERR_VAULT_GET_BALANCE_CAN_ONLY_BE_CALLED_ON_FUNGIBLE_ASSET,
    ERR_VAULT_NON_FUNGIBLE_ASSET_ALREADY_EXISTS,
    ERR_VAULT_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
};
use miden_protocol::testing::constants::{FUNGIBLE_ASSET_AMOUNT, NON_FUNGIBLE_ASSET_DATA};
use miden_protocol::transaction::memory;
use miden_protocol::{Felt, ONE, Word, ZERO};

use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::{TransactionContextBuilder, assert_execution_error};

/// Tests that account::get_balance returns the correct amount.
#[tokio::test]
async fn get_balance_returns_correct_amount() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let code = format!(
        r#"
        use $kernel::prologue
        use miden::protocol::active_account

        begin
            exec.prologue::prepare_transaction

            push.{suffix} push.{prefix}
            exec.active_account::get_balance
            # => [balance]

            # truncate the stack
            swap drop
        end
            "#,
        prefix = faucet_id.prefix().as_felt(),
        suffix = faucet_id.suffix(),
    );

    let exec_output = tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_element(0).as_int(),
        tx_context.account().vault().get_balance(faucet_id).unwrap()
    );

    Ok(())
}

/// Tests that asset_vault::peek_balance returns the correct amount.
#[tokio::test]
async fn peek_balance_returns_correct_amount() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();

    let code = format!(
        r#"
        use $kernel::prologue
        use $kernel::memory
        use $kernel::asset_vault

        begin
            exec.prologue::prepare_transaction

            exec.memory::get_account_vault_root_ptr
            push.{suffix} push.{prefix}
            # => [prefix, suffix, account_vault_root_ptr, balance]

            # emit an event to fetch the merkle path for the asset since peek_balance does not do
            # that
            emit.event("miden::protocol::account::vault_before_get_balance")
            # => [prefix, suffix, account_vault_root_ptr, balance]

            exec.asset_vault::peek_balance
            # => [peeked_balance]

            # truncate the stack
            swap drop
        end
            "#,
        prefix = faucet_id.prefix().as_felt(),
        suffix = faucet_id.suffix(),
    );

    let exec_output = tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_element(0).as_int(),
        tx_context.account().vault().get_balance(faucet_id).unwrap()
    );

    Ok(())
}

#[tokio::test]
async fn test_get_balance_non_fungible_fails() -> anyhow::Result<()> {
    // Disable lazy loading otherwise the handler will return an error before the transaction kernel
    // can abort, which is what we want to test.
    let tx_context = TransactionContextBuilder::with_existing_mock_account()
        .disable_lazy_loading()
        .build()?;

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET).unwrap();
    let code = format!(
        "
        use $kernel::prologue
        use miden::protocol::active_account

        begin
            exec.prologue::prepare_transaction
            push.{suffix} push.{prefix}
            exec.active_account::get_balance
        end
        ",
        prefix = faucet_id.prefix().as_felt(),
        suffix = faucet_id.suffix(),
    );

    let exec_result = tx_context.execute_code(&code).await;

    assert_execution_error!(
        exec_result,
        ERR_VAULT_GET_BALANCE_CAN_ONLY_BE_CALLED_ON_FUNGIBLE_ASSET
    );

    Ok(())
}

#[tokio::test]
async fn test_has_non_fungible_asset() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let non_fungible_asset =
        tx_context.account().vault().assets().find(Asset::is_non_fungible).unwrap();

    let code = format!(
        "
        use $kernel::prologue
        use miden::protocol::active_account

        begin
            exec.prologue::prepare_transaction
            push.{non_fungible_asset_key}
            exec.active_account::has_non_fungible_asset

            # truncate the stack
            swap drop
        end
        ",
        non_fungible_asset_key = Word::from(non_fungible_asset)
    );

    let exec_output = tx_context.execute_code(&code).await?;

    assert_eq!(exec_output.get_stack_element(0), ONE);

    Ok(())
}

#[tokio::test]
async fn test_add_fungible_asset_success() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let mut account_vault = tx_context.account().vault().clone();
    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let amount = FungibleAsset::MAX_AMOUNT - FUNGIBLE_ASSET_AMOUNT;
    let add_fungible_asset = Asset::try_from(Word::new([
        Felt::new(amount),
        ZERO,
        faucet_id.suffix(),
        faucet_id.prefix().as_felt(),
    ]))
    .unwrap();

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET}
            call.account::add_asset

            # truncate the stack
            swapw dropw
        end
        ",
        FUNGIBLE_ASSET = Word::from(add_fungible_asset)
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word_be(0),
        Word::from(account_vault.add_asset(add_fungible_asset).unwrap())
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(memory::NATIVE_ACCT_VAULT_ROOT_PTR),
        account_vault.root()
    );

    Ok(())
}

#[tokio::test]
async fn test_add_non_fungible_asset_fail_overflow() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let mut account_vault = tx_context.account().vault().clone();

    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let amount = FungibleAsset::MAX_AMOUNT - FUNGIBLE_ASSET_AMOUNT + 1;
    let add_fungible_asset = Asset::try_from(Word::new([
        Felt::new(amount),
        ZERO,
        faucet_id.suffix(),
        faucet_id.prefix().as_felt(),
    ]))
    .unwrap();

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET}
            call.account::add_asset
        end
        ",
        FUNGIBLE_ASSET = Word::from(add_fungible_asset)
    );

    let exec_result = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_result, ERR_VAULT_FUNGIBLE_MAX_AMOUNT_EXCEEDED);
    assert!(account_vault.add_asset(add_fungible_asset).is_err());

    Ok(())
}

#[tokio::test]
async fn test_add_non_fungible_asset_success() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into()?;
    let mut account_vault = tx_context.account().vault().clone();
    let add_non_fungible_asset = Asset::NonFungible(NonFungibleAsset::new(
        &NonFungibleAssetDetails::new(faucet_id.prefix(), vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
    )?);

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET}
            call.account::add_asset

            # truncate the stack
            swapw dropw
        end
        ",
        FUNGIBLE_ASSET = Word::from(add_non_fungible_asset)
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word_be(0),
        Word::from(account_vault.add_asset(add_non_fungible_asset)?)
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(memory::NATIVE_ACCT_VAULT_ROOT_PTR),
        account_vault.root()
    );

    Ok(())
}

#[tokio::test]
async fn test_add_non_fungible_asset_fail_duplicate() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into().unwrap();
    let mut account_vault = tx_context.account().vault().clone();
    let non_fungible_asset_details =
        NonFungibleAssetDetails::new(faucet_id.prefix(), NON_FUNGIBLE_ASSET_DATA.to_vec()).unwrap();
    let non_fungible_asset =
        Asset::NonFungible(NonFungibleAsset::new(&non_fungible_asset_details).unwrap());

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{NON_FUNGIBLE_ASSET}
            call.account::add_asset
        end
        ",
        NON_FUNGIBLE_ASSET = Word::from(non_fungible_asset)
    );

    let exec_result = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_result, ERR_VAULT_NON_FUNGIBLE_ASSET_ALREADY_EXISTS);
    assert!(account_vault.add_asset(non_fungible_asset).is_err());

    Ok(())
}

#[tokio::test]
async fn test_remove_fungible_asset_success_no_balance_remaining() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let mut account_vault = tx_context.account().vault().clone();

    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let amount = FUNGIBLE_ASSET_AMOUNT;
    let remove_fungible_asset = Asset::try_from(Word::new([
        Felt::new(amount),
        ZERO,
        faucet_id.suffix(),
        faucet_id.prefix().as_felt(),
    ]))
    .unwrap();

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET}
            call.account::remove_asset

            # truncate the stack
            swapw dropw
        end
        ",
        FUNGIBLE_ASSET = Word::from(remove_fungible_asset)
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word_be(0),
        Word::from(account_vault.remove_asset(remove_fungible_asset).unwrap())
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(memory::NATIVE_ACCT_VAULT_ROOT_PTR),
        account_vault.root()
    );

    Ok(())
}

#[tokio::test]
async fn test_remove_fungible_asset_fail_remove_too_much() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let amount = FUNGIBLE_ASSET_AMOUNT + 1;
    let remove_fungible_asset = Asset::try_from(Word::new([
        Felt::new(amount),
        ZERO,
        faucet_id.suffix(),
        faucet_id.prefix().as_felt(),
    ]))
    .unwrap();

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET}
            call.account::remove_asset
        end
        ",
        FUNGIBLE_ASSET = Word::from(remove_fungible_asset)
    );

    let exec_result = tx_context.execute_code(&code).await;

    assert_execution_error!(
        exec_result,
        ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW
    );

    Ok(())
}

#[tokio::test]
async fn test_remove_fungible_asset_success_balance_remaining() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let mut account_vault = tx_context.account().vault().clone();

    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let amount = FUNGIBLE_ASSET_AMOUNT - 1;
    let remove_fungible_asset = Asset::try_from(Word::new([
        Felt::new(amount),
        ZERO,
        faucet_id.suffix(),
        faucet_id.prefix().as_felt(),
    ]))
    .unwrap();

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET}
            call.account::remove_asset

            # truncate the stack
            swapw dropw
        end
        ",
        FUNGIBLE_ASSET = Word::from(remove_fungible_asset)
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word_be(0),
        Word::from(account_vault.remove_asset(remove_fungible_asset).unwrap())
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(memory::NATIVE_ACCT_VAULT_ROOT_PTR),
        account_vault.root()
    );

    Ok(())
}

#[tokio::test]
async fn test_remove_inexisting_non_fungible_asset_fails() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1.try_into().unwrap();
    let mut account_vault = tx_context.account().vault().clone();

    let non_fungible_asset_details =
        NonFungibleAssetDetails::new(faucet_id.prefix(), NON_FUNGIBLE_ASSET_DATA.to_vec()).unwrap();
    let nonfungible = NonFungibleAsset::new(&non_fungible_asset_details).unwrap();
    let non_existent_non_fungible_asset = Asset::NonFungible(nonfungible);

    assert_matches!(
        account_vault.remove_asset(non_existent_non_fungible_asset).unwrap_err(),
        AssetVaultError::NonFungibleAssetNotFound(err_asset) if err_asset == nonfungible,
        "asset must not be in the vault before the test",
    );

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET}
            call.account::remove_asset
        end
        ",
        FUNGIBLE_ASSET = Word::from(non_existent_non_fungible_asset)
    );

    let exec_result = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_result, ERR_VAULT_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND);
    assert_matches!(
        account_vault.remove_asset(non_existent_non_fungible_asset).unwrap_err(),
        AssetVaultError::NonFungibleAssetNotFound(err_asset) if err_asset == nonfungible,
        "asset should not be in the vault after the test",
    );

    Ok(())
}

#[tokio::test]
async fn test_remove_non_fungible_asset_success() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into().unwrap();
    let mut account_vault = tx_context.account().vault().clone();
    let non_fungible_asset_details =
        NonFungibleAssetDetails::new(faucet_id.prefix(), NON_FUNGIBLE_ASSET_DATA.to_vec()).unwrap();
    let non_fungible_asset =
        Asset::NonFungible(NonFungibleAsset::new(&non_fungible_asset_details).unwrap());

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET}
            call.account::remove_asset

            # truncate the stack
            swapw dropw
        end
        ",
        FUNGIBLE_ASSET = Word::from(non_fungible_asset)
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word_be(0),
        Word::from(account_vault.remove_asset(non_fungible_asset).unwrap())
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(memory::NATIVE_ACCT_VAULT_ROOT_PTR),
        account_vault.root()
    );

    Ok(())
}
