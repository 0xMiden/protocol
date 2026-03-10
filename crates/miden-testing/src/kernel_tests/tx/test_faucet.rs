use alloc::sync::Arc;

use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{
    AssetCallbackFlag,
    AssetId,
    AssetVaultKey,
    FungibleAsset,
    NonFungibleAsset,
};
use miden_protocol::errors::tx_kernel::{
    ERR_FUNGIBLE_ASSET_AMOUNT_EXCEEDS_MAX_AMOUNT,
    ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN,
    ERR_NON_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN,
    ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW,
    ERR_VAULT_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::testing::constants::{
    CONSUMED_ASSET_1_AMOUNT,
    FUNGIBLE_ASSET_AMOUNT,
    NON_FUNGIBLE_ASSET_DATA,
    NON_FUNGIBLE_ASSET_DATA_2,
};
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::mock_account::MockAccountExt;

use crate::utils::create_public_p2any_note;
use crate::{TransactionContextBuilder, assert_execution_error, assert_transaction_executor_error};

// FUNGIBLE FAUCET MINT TESTS
// ================================================================================================

#[tokio::test]
async fn test_mint_fungible_asset_succeeds() -> anyhow::Result<()> {
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let asset = FungibleAsset::new(faucet_id, FUNGIBLE_ASSET_AMOUNT)?;

    let code = format!(
        r#"
        use mock::faucet->mock_faucet
        use miden::protocol::faucet
        use $kernel::asset_vault
        use $kernel::memory
        use $kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # mint asset
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.mock_faucet::mint

            # assert the correct asset is returned
            push.{FUNGIBLE_ASSET_VALUE}
            assert_eqw.err="minted asset does not match expected asset"

            # assert the input vault has been updated
            exec.memory::get_input_vault_root_ptr
            push.{FUNGIBLE_ASSET_KEY}
            exec.asset_vault::get_asset
            # => [ASSET_VALUE]

            # extract balance from asset
            movdn.3 drop drop drop
            # => [balance]

            push.{FUNGIBLE_ASSET_AMOUNT} assert_eq.err="input vault should contain minted asset"

            # truncate the stack
            dropw
        end
        "#,
        FUNGIBLE_ASSET_KEY = asset.to_key_word(),
        FUNGIBLE_ASSET_VALUE = asset.to_value_word(),
    );

    TransactionContextBuilder::with_fungible_faucet(faucet_id.into())
        .build()?
        .execute_code(&code)
        .await?;

    Ok(())
}

/// Tests that minting a fungible asset on a non-faucet account fails.
#[tokio::test]
async fn mint_fungible_asset_fails_on_non_faucet_account() -> anyhow::Result<()> {
    let account = setup_non_faucet_account()?;
    let asset = FungibleAsset::mock(50);

    let code = format!(
        "
      use mock::faucet

      begin
          push.{ASSET_VALUE}
          push.{ASSET_KEY}
          call.faucet::mint
      end
      ",
        ASSET_KEY = asset.to_key_word(),
        ASSET_VALUE = asset.to_value_word(),
    );
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(code)?;

    let result = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN);

    Ok(())
}

#[tokio::test]
async fn test_mint_fungible_asset_inconsistent_faucet_id() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_fungible_faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)
            .build()?;

    let asset = FungibleAsset::mock(5);
    let code = format!(
        "
        use $kernel::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{ASSET_VALUE}
            push.{ASSET_KEY}
            call.faucet::mint
        end
        ",
        ASSET_KEY = asset.to_key_word(),
        ASSET_VALUE = asset.to_value_word(),
    );

    let exec_output = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN);
    Ok(())
}

/// Tests that minting a fungible asset with [`FungibleAsset::MAX_AMOUNT`] + 1 fails.
#[tokio::test]
async fn test_mint_fungible_asset_fails_when_amount_exceeds_max_representable_amount()
-> anyhow::Result<()> {
    let code = format!(
        "
        use mock::faucet

        begin
            push.0
            push.0
            push.0
            push.{max_amount_plus_1}
            # => [ASSET_VALUE]

            push.{ASSET_KEY}
            # => [ASSET_KEY, ASSET_VALUE]

            call.faucet::mint
            dropw dropw
        end
    ",
        ASSET_KEY = FungibleAsset::mock(0).to_key_word(),
        max_amount_plus_1 = FungibleAsset::MAX_AMOUNT + 1,
    );
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(code)?;

    let result =
        TransactionContextBuilder::with_fungible_faucet(FungibleAsset::mock_issuer().into())
            .tx_script(tx_script)
            .build()?
            .execute()
            .await;

    assert_transaction_executor_error!(result, ERR_FUNGIBLE_ASSET_AMOUNT_EXCEEDS_MAX_AMOUNT);
    Ok(())
}

// NON-FUNGIBLE FAUCET MINT TESTS
// ================================================================================================

#[tokio::test]
async fn test_mint_non_fungible_asset_succeeds() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_non_fungible_faucet(NonFungibleAsset::mock_issuer().into())
            .build()?;
    let non_fungible_asset = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA);

    let code = format!(
        r#"
        use miden::core::collections::smt

        use $kernel::account
        use $kernel::asset_vault
        use $kernel::memory
        use $kernel::prologue
        use mock::faucet->mock_faucet

        begin
            # mint asset
            exec.prologue::prepare_transaction
            push.{NON_FUNGIBLE_ASSET_VALUE}
            push.{NON_FUNGIBLE_ASSET_KEY}
            call.mock_faucet::mint

            # assert the correct asset is returned
            push.{NON_FUNGIBLE_ASSET_VALUE}
            assert_eqw.err="minted asset does not match expected asset"

            # assert the input vault has been updated.
            exec.memory::get_input_vault_root_ptr
            push.{NON_FUNGIBLE_ASSET_KEY}
            exec.asset_vault::get_asset
            push.{NON_FUNGIBLE_ASSET_VALUE}
            assert_eqw.err="vault should contain asset"

            dropw
        end
        "#,
        NON_FUNGIBLE_ASSET_KEY = non_fungible_asset.to_key_word(),
        NON_FUNGIBLE_ASSET_VALUE = non_fungible_asset.to_value_word(),
    );

    tx_context.execute_code(&code).await?;

    Ok(())
}

#[tokio::test]
async fn test_mint_non_fungible_asset_fails_inconsistent_faucet_id() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_non_fungible_faucet(
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
    )
    .build()?;
    let non_fungible_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let code = format!(
        "
        use $kernel::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{asset_value}
            push.{asset_key}
            call.faucet::mint
        end
        ",
        asset_key = non_fungible_asset.to_key_word(),
        asset_value = non_fungible_asset.to_value_word(),
    );

    let exec_output = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_NON_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN);
    Ok(())
}

/// Tests that minting a non-fungible asset on a non-faucet account fails.
#[tokio::test]
async fn mint_non_fungible_asset_fails_on_non_faucet_account() -> anyhow::Result<()> {
    let account = setup_non_faucet_account()?;
    let asset = FungibleAsset::mock(50);

    let code = format!(
        "
      use mock::faucet

      begin
          push.{ASSET_VALUE}
          push.{ASSET_KEY}
          call.faucet::mint
      end
      ",
        ASSET_KEY = asset.to_key_word(),
        ASSET_VALUE = asset.to_value_word(),
    );
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(code)?;

    let result = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN);

    Ok(())
}

/// Tests minting a fungible asset with callbacks enabled.
#[tokio::test]
async fn test_mint_fungible_asset_with_callbacks_enabled() -> anyhow::Result<()> {
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();
    let asset = FungibleAsset::new(faucet_id, FUNGIBLE_ASSET_AMOUNT)?;

    // Build a vault key with callbacks enabled.
    let vault_key = AssetVaultKey::new(AssetId::default(), faucet_id, AssetCallbackFlag::Enabled)?;

    let code = format!(
        r#"
        use mock::faucet->mock_faucet
        use $kernel::prologue

        begin
            exec.prologue::prepare_transaction

            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.mock_faucet::mint

            dropw dropw
        end
        "#,
        FUNGIBLE_ASSET_KEY = vault_key.to_word(),
        FUNGIBLE_ASSET_VALUE = asset.to_value_word(),
    );

    TransactionContextBuilder::with_fungible_faucet(faucet_id.into())
        .build()?
        .execute_code(&code)
        .await?;

    Ok(())
}

// FUNGIBLE FAUCET BURN TESTS
// ================================================================================================

#[tokio::test]
async fn test_burn_fungible_asset_succeeds() -> anyhow::Result<()> {
    let account = Account::mock_fungible_faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1);
    let asset = FungibleAsset::new(account.id(), 100u64).unwrap().into();
    let note = create_public_p2any_note(ACCOUNT_ID_SENDER.try_into().unwrap(), [asset]);
    let tx_context =
        TransactionContextBuilder::new(account).extend_input_notes(vec![note]).build()?;

    let code = format!(
        r#"
        use mock::faucet->mock_faucet
        use miden::protocol::faucet
        use $kernel::asset_vault
        use $kernel::memory
        use $kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # burn asset
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.mock_faucet::burn

            # assert the correct asset is returned
            push.{FUNGIBLE_ASSET_VALUE}
            assert_eqw.err="burnt asset does not match expected asset"

            # assert the input vault has been updated
            exec.memory::get_input_vault_root_ptr

            push.{FUNGIBLE_ASSET_KEY}
            exec.asset_vault::get_asset
            # => [ASSET_VALUE]

            # extract balance from asset
            movdn.3 drop drop drop
            # => [balance]

            push.{final_input_vault_asset_amount}
            assert_eq.err="vault balance does not match expected balance"

            exec.::miden::core::sys::truncate_stack
        end
        "#,
        FUNGIBLE_ASSET_VALUE = asset.to_value_word(),
        FUNGIBLE_ASSET_KEY = asset.to_key_word(),
        final_input_vault_asset_amount = CONSUMED_ASSET_1_AMOUNT - FUNGIBLE_ASSET_AMOUNT,
    );

    tx_context.execute_code(&code).await?;

    Ok(())
}

/// Tests that burning a fungible asset on a non-faucet account fails.
#[tokio::test]
async fn burn_fungible_asset_fails_on_non_faucet_account() -> anyhow::Result<()> {
    let account = setup_non_faucet_account()?;
    let asset = FungibleAsset::mock(50);

    let code = format!(
        "
      use mock::faucet

      begin
          push.{FUNGIBLE_ASSET_VALUE}
          push.{FUNGIBLE_ASSET_KEY}
          call.faucet::burn
      end
      ",
        FUNGIBLE_ASSET_VALUE = asset.to_value_word(),
        FUNGIBLE_ASSET_KEY = asset.to_key_word(),
    );
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(code)?;

    let result = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN);

    Ok(())
}

#[tokio::test]
async fn test_burn_fungible_asset_inconsistent_faucet_id() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_fungible_faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .build()?;

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap();
    let fungible_asset = FungibleAsset::new(faucet_id, FUNGIBLE_ASSET_AMOUNT)?;

    let code = format!(
        "
        use $kernel::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.faucet::burn
        end
        ",
        FUNGIBLE_ASSET_VALUE = fungible_asset.to_value_word(),
        FUNGIBLE_ASSET_KEY = fungible_asset.to_key_word(),
    );

    let exec_output = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN);
    Ok(())
}

#[tokio::test]
async fn test_burn_fungible_asset_insufficient_input_amount() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_fungible_faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)
            .build()?;

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap();
    let fungible_asset = FungibleAsset::new(faucet_id, CONSUMED_ASSET_1_AMOUNT + 1)?;

    let code = format!(
        "
        use $kernel::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET_VALUE}
            push.{FUNGIBLE_ASSET_KEY}
            call.faucet::burn
        end
        ",
        FUNGIBLE_ASSET_VALUE = fungible_asset.to_value_word(),
        FUNGIBLE_ASSET_KEY = fungible_asset.to_key_word(),
    );

    let exec_output = tx_context.execute_code(&code).await;

    assert_execution_error!(
        exec_output,
        ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW
    );
    Ok(())
}

// NON-FUNGIBLE FAUCET BURN TESTS
// ================================================================================================

#[tokio::test]
async fn test_burn_non_fungible_asset_succeeds() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_non_fungible_faucet(NonFungibleAsset::mock_issuer().into())
            .build()?;
    let non_fungible_asset_burnt = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA_2);

    let code = format!(
        r#"
        use $kernel::account
        use $kernel::asset_vault
        use $kernel::memory
        use $kernel::prologue
        use mock::faucet->mock_faucet

        begin
            exec.prologue::prepare_transaction

            # add non-fungible asset to the vault
            exec.memory::get_input_vault_root_ptr
            push.{NON_FUNGIBLE_ASSET_VALUE}
            push.{NON_FUNGIBLE_ASSET_KEY}
            exec.asset_vault::add_non_fungible_asset dropw

            # check that the non-fungible asset is presented in the input vault
            exec.memory::get_input_vault_root_ptr
            push.{NON_FUNGIBLE_ASSET_KEY}
            exec.asset_vault::get_asset
            push.{NON_FUNGIBLE_ASSET_VALUE}
            assert_eqw.err="input vault should contain the asset"

            # burn the non-fungible asset
            push.{NON_FUNGIBLE_ASSET_VALUE}
            push.{NON_FUNGIBLE_ASSET_KEY}
            call.mock_faucet::burn

            # assert the correct asset is returned
            push.{NON_FUNGIBLE_ASSET_VALUE}
            assert_eqw.err="burnt asset does not match expected asset"

            # assert the input vault has been updated and does not have the burnt asset
            exec.memory::get_input_vault_root_ptr
            push.{NON_FUNGIBLE_ASSET_KEY}
            exec.asset_vault::get_asset
            # the returned word should be empty, indicating the asset is absent
            padw assert_eqw.err="input vault should not contain burned asset"

            dropw
        end
        "#,
        NON_FUNGIBLE_ASSET_KEY = non_fungible_asset_burnt.to_key_word(),
        NON_FUNGIBLE_ASSET_VALUE = non_fungible_asset_burnt.to_value_word(),
    );

    tx_context.execute_code(&code).await?;
    Ok(())
}

#[tokio::test]
async fn test_burn_non_fungible_asset_fails_does_not_exist() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_non_fungible_faucet(NonFungibleAsset::mock_issuer().into())
            .build()?;

    let non_fungible_asset_burnt = NonFungibleAsset::mock(&[1, 2, 3]);

    let code = format!(
        "
        use $kernel::prologue
        use mock::faucet

        begin
            # burn asset
            exec.prologue::prepare_transaction
            push.{NON_FUNGIBLE_ASSET_VALUE}
            push.{NON_FUNGIBLE_ASSET_KEY}
            call.faucet::burn
        end
        ",
        NON_FUNGIBLE_ASSET_VALUE = non_fungible_asset_burnt.to_value_word(),
        NON_FUNGIBLE_ASSET_KEY = non_fungible_asset_burnt.to_key_word(),
    );

    let exec_output = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_VAULT_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND);
    Ok(())
}

/// Tests that burning a non-fungible asset on a non-faucet account fails.
#[tokio::test]
async fn burn_non_fungible_asset_fails_on_non_faucet_account() -> anyhow::Result<()> {
    let account = setup_non_faucet_account()?;
    let asset = FungibleAsset::mock(50);

    let code = format!(
        "
      use mock::faucet

      begin
          push.{ASSET_VALUE}
          push.{ASSET_KEY}
          call.faucet::burn
      end
      ",
        ASSET_VALUE = asset.to_value_word(),
        ASSET_KEY = asset.to_key_word(),
    );
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(code)?;

    let result = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN);

    Ok(())
}

#[tokio::test]
async fn test_burn_non_fungible_asset_fails_inconsistent_faucet_id() -> anyhow::Result<()> {
    let non_fungible_asset_burnt = NonFungibleAsset::mock(&[1, 2, 3]);

    // Run code from a different non-fungible asset issuer
    let tx_context = TransactionContextBuilder::with_non_fungible_faucet(
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
    )
    .build()?;

    let code = format!(
        "
        use $kernel::prologue
        use mock::faucet

        begin
            # burn asset
            exec.prologue::prepare_transaction
            push.{NON_FUNGIBLE_ASSET_VALUE}
            push.{NON_FUNGIBLE_ASSET_KEY}
            call.faucet::burn
        end
        ",
        NON_FUNGIBLE_ASSET_VALUE = non_fungible_asset_burnt.to_value_word(),
        NON_FUNGIBLE_ASSET_KEY = non_fungible_asset_burnt.to_key_word(),
    );

    let exec_output = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_NON_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN);
    Ok(())
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates a regular account that exposes the faucet mint and burn procedures.
///
/// This is used to test that calling these procedures fails as expected.
fn setup_non_faucet_account() -> anyhow::Result<Account> {
    use miden_protocol::account::component::AccountComponentMetadata;

    // Build a custom non-faucet account that (invalidly) exposes faucet procedures.
    let faucet_code = CodeBuilder::with_mock_libraries_with_source_manager(Arc::new(
        DefaultSourceManager::default(),
    ))
    .compile_component_code(
        "test::non_faucet_component",
        "pub use ::miden::protocol::faucet::mint
         pub use ::miden::protocol::faucet::burn",
    )?;
    let metadata = AccountComponentMetadata::new(
        "test::non_faucet_component",
        [AccountType::RegularAccountUpdatableCode],
    );
    let faucet_component = AccountComponent::new(faucet_code, vec![], metadata)?;
    Ok(AccountBuilder::new([4; 32])
        .account_type(AccountType::RegularAccountUpdatableCode)
        .with_auth_component(NoopAuthComponent)
        .with_component(faucet_component)
        .build_existing()?)
}
