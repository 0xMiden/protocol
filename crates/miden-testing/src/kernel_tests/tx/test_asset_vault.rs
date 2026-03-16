use assert_matches::assert_matches;
use miden_protocol::ONE;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{
    Asset,
    AssetVaultKey,
    FungibleAsset,
    NonFungibleAsset,
    NonFungibleAssetDetails,
};
use miden_protocol::errors::protocol::ERR_VAULT_GET_BALANCE_CAN_ONLY_BE_CALLED_ON_FUNGIBLE_ASSET;
use miden_protocol::errors::tx_kernel::{
    ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW,
    ERR_VAULT_FUNGIBLE_MAX_AMOUNT_EXCEEDED,
    ERR_VAULT_NON_FUNGIBLE_ASSET_ALREADY_EXISTS,
    ERR_VAULT_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND,
};
use miden_protocol::errors::{AssetError, AssetVaultError};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
};
use miden_protocol::testing::constants::{FUNGIBLE_ASSET_AMOUNT, NON_FUNGIBLE_ASSET_DATA};
use miden_protocol::transaction::memory;

use crate::executor::CodeExecutor;
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

            push.{prefix}
            push.{suffix}
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
        exec_output.get_stack_element(0).as_canonical_u64(),
        tx_context.account().vault().get_balance(faucet_id).unwrap()
    );

    Ok(())
}

/// Tests that asset_vault::peek_asset returns the correct asset.
#[tokio::test]
async fn peek_asset_returns_correct_asset() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let asset_key = AssetVaultKey::new_fungible(faucet_id).unwrap();

    let code = format!(
        r#"
        use $kernel::prologue
        use $kernel::memory
        use $kernel::asset_vault

        begin
            exec.prologue::prepare_transaction

            exec.memory::get_account_vault_root_ptr
            push.{ASSET_KEY}
            # => [ASSET_KEY, account_vault_root_ptr]

            # emit an event to fetch the merkle path for the asset since peek_asset does not do
            # that
            emit.event("miden::protocol::account::vault_before_get_asset")
            # => [ASSET_KEY, account_vault_root_ptr]

            exec.asset_vault::peek_asset
            # => [PEEKED_ASSET_VALUE]

            # truncate the stack
            swapw dropw
        end
            "#,
        ASSET_KEY = asset_key.to_word()
    );

    let exec_output = tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word(0),
        tx_context.account().vault().get(asset_key).unwrap().to_value_word()
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
            push.{prefix} push.{suffix}
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
            push.{NON_FUNGIBLE_ASSET_KEY}
            exec.active_account::has_non_fungible_asset

            # truncate the stack
            swap drop
        end
        ",
        NON_FUNGIBLE_ASSET_KEY = non_fungible_asset.to_key_word(),
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
    let add_fungible_asset = FungibleAsset::new(faucet_id, amount)?;

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.account::add_asset

            # truncate the stack
            swapdw dropw dropw
        end
        ",
        FUNGIBLE_ASSET_KEY = add_fungible_asset.to_key_word(),
        FUNGIBLE_ASSET_VALUE = add_fungible_asset.to_value_word(),
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word(0),
        account_vault
            .add_asset(Asset::Fungible(add_fungible_asset))
            .unwrap()
            .to_value_word()
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
    let add_fungible_asset = FungibleAsset::new(faucet_id, amount)?;

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.account::add_asset
            dropw dropw
        end
        ",
        FUNGIBLE_ASSET_KEY = add_fungible_asset.to_key_word(),
        FUNGIBLE_ASSET_VALUE = add_fungible_asset.to_value_word(),
    );

    let exec_result = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_result, ERR_VAULT_FUNGIBLE_MAX_AMOUNT_EXCEEDED);
    assert!(account_vault.add_asset(Asset::Fungible(add_fungible_asset)).is_err());

    Ok(())
}

#[tokio::test]
async fn test_add_non_fungible_asset_success() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into()?;
    let mut account_vault = tx_context.account().vault().clone();
    let add_non_fungible_asset = Asset::NonFungible(NonFungibleAsset::new(
        &NonFungibleAssetDetails::new(faucet_id, vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
    )?);

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{NON_FUNGIBLE_ASSET_VALUE}
            push.{NON_FUNGIBLE_ASSET_KEY}
            call.account::add_asset

            # truncate the stack
            swapdw dropw dropw
        end
        ",
        NON_FUNGIBLE_ASSET_KEY = add_non_fungible_asset.to_key_word(),
        NON_FUNGIBLE_ASSET_VALUE = add_non_fungible_asset.to_value_word(),
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word(0),
        account_vault.add_asset(add_non_fungible_asset)?.to_value_word()
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
        NonFungibleAssetDetails::new(faucet_id, NON_FUNGIBLE_ASSET_DATA.to_vec()).unwrap();
    let non_fungible_asset =
        Asset::NonFungible(NonFungibleAsset::new(&non_fungible_asset_details).unwrap());

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{NON_FUNGIBLE_ASSET_VALUE}
            push.{NON_FUNGIBLE_ASSET_KEY}
            call.account::add_asset
            dropw dropw
        end
        ",
        NON_FUNGIBLE_ASSET_KEY = non_fungible_asset.to_key_word(),
        NON_FUNGIBLE_ASSET_VALUE = non_fungible_asset.to_value_word(),
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
    let remove_fungible_asset = FungibleAsset::new(faucet_id, amount)?;

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.account::remove_asset

            # truncate the stack
            exec.::miden::core::sys::truncate_stack
        end
        ",
        FUNGIBLE_ASSET_KEY = remove_fungible_asset.to_key_word(),
        FUNGIBLE_ASSET_VALUE = remove_fungible_asset.to_value_word(),
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word(0),
        account_vault
            .remove_asset(Asset::Fungible(remove_fungible_asset))
            .unwrap()
            .to_value_word()
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
    let remove_fungible_asset = FungibleAsset::new(faucet_id, amount)?;

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.account::remove_asset
        end
        ",
        FUNGIBLE_ASSET_KEY = remove_fungible_asset.to_key_word(),
        FUNGIBLE_ASSET_VALUE = remove_fungible_asset.to_value_word(),
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
    let remove_fungible_asset = FungibleAsset::new(faucet_id, amount)?;

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.account::remove_asset

            # truncate the stack
            exec.::miden::core::sys::truncate_stack
        end
        ",
        FUNGIBLE_ASSET_KEY = remove_fungible_asset.to_key_word(),
        FUNGIBLE_ASSET_VALUE = remove_fungible_asset.to_value_word(),
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word(0),
        account_vault
            .remove_asset(Asset::Fungible(remove_fungible_asset))
            .unwrap()
            .to_value_word()
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
        NonFungibleAssetDetails::new(faucet_id, NON_FUNGIBLE_ASSET_DATA.to_vec()).unwrap();
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
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.account::remove_asset
        end
        ",
        FUNGIBLE_ASSET_KEY = non_existent_non_fungible_asset.to_key_word(),
        FUNGIBLE_ASSET_VALUE = non_existent_non_fungible_asset.to_value_word(),
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
        NonFungibleAssetDetails::new(faucet_id, NON_FUNGIBLE_ASSET_DATA.to_vec()).unwrap();
    let non_fungible_asset =
        Asset::NonFungible(NonFungibleAsset::new(&non_fungible_asset_details).unwrap());

    let code = format!(
        "
        use $kernel::prologue
        use mock::account

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.account::remove_asset

            # truncate the stack
            exec.::miden::core::sys::truncate_stack
        end
        ",
        FUNGIBLE_ASSET_KEY = non_fungible_asset.to_key_word(),
        FUNGIBLE_ASSET_VALUE = non_fungible_asset.to_value_word(),
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word(0),
        account_vault.remove_asset(non_fungible_asset).unwrap().to_value_word()
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(memory::NATIVE_ACCT_VAULT_ROOT_PTR),
        account_vault.root()
    );

    Ok(())
}

/// Tests that adding two fungible assets results in the expected value.
#[tokio::test]
async fn test_merge_fungible_asset_success() -> anyhow::Result<()> {
    let asset0 = FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT);
    let asset1 = FungibleAsset::mock(FungibleAsset::MAX_AMOUNT - FUNGIBLE_ASSET_AMOUNT);
    let merged_asset = asset0.unwrap_fungible().add(asset1.unwrap_fungible())?;

    // Check merging is commutative by checking asset0 + asset1 = asset1 + asset0.
    for (asset_a, asset_b) in [(asset0, asset1), (asset1, asset0)] {
        let code = format!(
            "
        use $kernel::fungible_asset

        begin
            push.{ASSETA}
            push.{ASSETB}
            exec.fungible_asset::merge
            # => [MERGED_ASSET]

            # truncate the stack
            swapw dropw
        end
        ",
            ASSETA = asset_a.to_value_word(),
            ASSETB = asset_b.to_value_word(),
        );

        let exec_output = CodeExecutor::with_default_host().run(&code).await?;

        assert_eq!(exec_output.get_stack_word(0), merged_asset.to_value_word());
    }

    Ok(())
}

/// Tests that adding two fungible assets fails when the added amounts exceed
/// [`FungibleAsset::MAX_AMOUNT`].
#[tokio::test]
async fn test_merge_fungible_asset_fails_when_max_amount_exceeded() -> anyhow::Result<()> {
    let asset0 = FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT);
    let asset1 = FungibleAsset::mock(FungibleAsset::MAX_AMOUNT + 1 - FUNGIBLE_ASSET_AMOUNT);

    // Check merging fails for both asset0 + asset1 and asset1 + asset0.
    for (asset_a, asset_b) in [(asset0, asset1), (asset1, asset0)] {
        // Sanity check that the Rust implementation errors.
        assert_matches!(
            asset_a.unwrap_fungible().add(asset_b.unwrap_fungible()).unwrap_err(),
            AssetError::FungibleAssetAmountTooBig(_)
        );

        let code = format!(
            "
        use $kernel::fungible_asset

        begin
            push.{ASSETA}
            push.{ASSETB}
            exec.fungible_asset::merge
            # => [MERGED_ASSET]

            # truncate the stack
            swapw dropw
        end
        ",
            ASSETA = asset_a.to_value_word(),
            ASSETB = asset_b.to_value_word(),
        );

        let exec_output = CodeExecutor::with_default_host().run(&code).await;

        assert_execution_error!(exec_output, ERR_VAULT_FUNGIBLE_MAX_AMOUNT_EXCEEDED);
    }

    Ok(())
}

/// Tests that splitting a fungible asset returns the correct remaining amount.
#[rstest::rstest]
#[case::different_amounts(FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT), FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT - 1))]
#[case::same_amounts(
    FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT),
    FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT)
)]
#[tokio::test]
async fn test_split_fungible_asset_success(
    #[case] asset0: Asset,
    #[case] asset1: Asset,
) -> anyhow::Result<()> {
    let split_asset = asset0.unwrap_fungible().sub(asset1.unwrap_fungible())?;

    let code = format!(
        "
        use $kernel::fungible_asset

        begin
            push.{ASSET0}
            push.{ASSET1}
            exec.fungible_asset::split
            # => [NEW_ASSET_VALUE_0]

            # truncate the stack
            swapw dropw
        end
        ",
        ASSET0 = asset0.to_value_word(),
        ASSET1 = asset1.to_value_word(),
    );

    let exec_output = CodeExecutor::with_default_host().run(&code).await?;

    assert_eq!(exec_output.get_stack_word(0), split_asset.to_value_word());

    Ok(())
}

/// Tests that splitting a fungible asset fails when the amount to withdraw exceeds the balance.
#[tokio::test]
async fn test_split_fungible_asset_fails_when_amount_exceeds_balance() -> anyhow::Result<()> {
    let asset0 = FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT);
    let asset1 = FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT + 1);

    // Sanity check that the Rust implementation errors.
    assert_matches!(
        asset0.unwrap_fungible().sub(asset1.unwrap_fungible()).unwrap_err(),
        AssetError::FungibleAssetAmountNotSufficient { .. }
    );

    let code = format!(
        "
        use $kernel::fungible_asset

        begin
            push.{ASSET0}
            push.{ASSET1}
            exec.fungible_asset::split
            # => [SPLIT_ASSET]

            # truncate the stack
            swapw dropw
        end
        ",
        ASSET0 = asset0.to_value_word(),
        ASSET1 = asset1.to_value_word(),
    );

    let exec_output = CodeExecutor::with_default_host().run(&code).await;

    assert_execution_error!(
        exec_output,
        ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW
    );

    Ok(())
}

/// Tests that merging two different fungible assets fails.
#[tokio::test]
async fn test_merge_different_fungible_assets_fails() -> anyhow::Result<()> {
    // Create two fungible assets from different faucets
    let faucet_id1: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let faucet_id2: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap();

    let asset0 = FungibleAsset::new(faucet_id1, FUNGIBLE_ASSET_AMOUNT)?;
    let asset1 = FungibleAsset::new(faucet_id2, FUNGIBLE_ASSET_AMOUNT)?;

    // Sanity check that the Rust implementation errors when adding assets from different faucets.
    assert_matches!(
        asset0.add(asset1).unwrap_err(),
        AssetError::FungibleAssetInconsistentVaultKeys { .. }
    );

    Ok(())
}
