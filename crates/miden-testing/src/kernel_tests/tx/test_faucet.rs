use alloc::sync::Arc;

use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{FungibleAsset, NonFungibleAsset};
use miden_protocol::errors::tx_kernel::{
    ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN,
    ERR_FUNGIBLE_ASSET_FORMAT_ELEMENT_ZERO_MUST_BE_WITHIN_LIMITS,
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
use miden_protocol::{Felt, Word};
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
            push.{FUNGIBLE_ASSET}
            call.mock_faucet::mint

            # assert the correct asset is returned
            push.{FUNGIBLE_ASSET}
            assert_eqw.err="minted asset does not match expected asset"

            # assert the input vault has been updated
            exec.memory::get_input_vault_root_ptr
            push.{ASSET_KEY}
            exec.asset_vault::get_asset
            # => [ASSET]

            # extract balance from asset
            drop drop drop
            # => [balance]

            push.{FUNGIBLE_ASSET_AMOUNT} assert_eq.err="input vault should contain minted asset"
        end
        "#,
        FUNGIBLE_ASSET = Word::from(asset),
        ASSET_KEY = asset.vault_key(),
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

    let code = format!(
        "
      use mock::faucet

      begin
          push.{asset}
          call.faucet::mint
      end
      ",
        asset = Word::from(FungibleAsset::mock(50))
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

    let code = format!(
        "
        use $kernel::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{asset}
            call.faucet::mint
        end
        ",
        asset = Word::from(FungibleAsset::mock(5))
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
            push.{max_amount_plus_1}
            push.0
            push.{faucet_id_suffix}
            push.{faucet_id_prefix}
            # => [faucet_id_prefix, faucet_id_suffix, 0, max_amount_plus_1]

            call.faucet::mint
            dropw
        end
    ",
        faucet_id_prefix = FungibleAsset::mock_issuer().prefix().as_felt(),
        faucet_id_suffix = FungibleAsset::mock_issuer().suffix(),
        max_amount_plus_1 = Felt::try_from(FungibleAsset::MAX_AMOUNT + 1).unwrap(),
    );
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(code)?;

    let result =
        TransactionContextBuilder::with_fungible_faucet(FungibleAsset::mock_issuer().into())
            .tx_script(tx_script)
            .build()?
            .execute()
            .await;

    assert_transaction_executor_error!(
        result,
        ERR_FUNGIBLE_ASSET_FORMAT_ELEMENT_ZERO_MUST_BE_WITHIN_LIMITS
    );
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
            push.{non_fungible_asset}
            call.mock_faucet::mint

            # assert the correct asset is returned
            push.{non_fungible_asset}
            assert_eqw.err="minted asset does not match expected asset"

            # assert the input vault has been updated.
            exec.memory::get_input_vault_root_ptr
            push.{ASSET_KEY}
            exec.asset_vault::get_asset
            push.{non_fungible_asset}
            assert_eqw.err="vault should contain asset"

            dropw
        end
        "#,
        ASSET_KEY = non_fungible_asset.vault_key(),
        non_fungible_asset = Word::from(non_fungible_asset),
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
            push.{non_fungible_asset}
            call.faucet::mint
        end
        ",
        non_fungible_asset = Word::from(non_fungible_asset)
    );

    let exec_output = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_NON_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN);
    Ok(())
}

/// Tests that minting a non-fungible asset on a non-faucet account fails.
#[tokio::test]
async fn mint_non_fungible_asset_fails_on_non_faucet_account() -> anyhow::Result<()> {
    let account = setup_non_faucet_account()?;

    let code = format!(
        "
      use mock::faucet

      begin
          push.{asset}
          call.faucet::mint
      end
      ",
        asset = Word::from(FungibleAsset::mock(50))
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
            push.{FUNGIBLE_ASSET}
            call.mock_faucet::burn

            # assert the correct asset is returned
            push.{FUNGIBLE_ASSET}
            assert_eqw.err="burnt asset does not match expected asset"

            # assert the input vault has been updated
            exec.memory::get_input_vault_root_ptr

            push.{ASSET_KEY}
            exec.asset_vault::get_asset
            # => [ASSET]

            # extract balance from asset
            drop drop drop
            # => [balance]

            push.{final_input_vault_asset_amount}
            assert_eq.err="vault balance does not match expected balance"
        end
        "#,
        FUNGIBLE_ASSET = Word::from(asset),
        ASSET_KEY = asset.vault_key(),
        final_input_vault_asset_amount = CONSUMED_ASSET_1_AMOUNT - FUNGIBLE_ASSET_AMOUNT,
    );

    tx_context.execute_code(&code).await?;

    Ok(())
}

/// Tests that burning a fungible asset on a non-faucet account fails.
#[tokio::test]
async fn burn_fungible_asset_fails_on_non_faucet_account() -> anyhow::Result<()> {
    let account = setup_non_faucet_account()?;

    let code = format!(
        "
      use mock::faucet

      begin
          push.{asset}
          call.faucet::burn
      end
      ",
        asset = Word::from(FungibleAsset::mock(50))
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

    let code = format!(
        "
        use $kernel::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{FUNGIBLE_ASSET_AMOUNT} push.0 push.{suffix} push.{prefix}
            call.faucet::burn
        end
        ",
        prefix = faucet_id.prefix().as_felt(),
        suffix = faucet_id.suffix(),
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

    let code = format!(
        "
        use $kernel::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{saturating_amount} push.0 push.{suffix} push.{prefix}
            call.faucet::burn
        end
        ",
        prefix = faucet_id.prefix().as_felt(),
        suffix = faucet_id.suffix(),
        saturating_amount = CONSUMED_ASSET_1_AMOUNT + 1
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
            exec.memory::get_input_vault_root_ptr push.{non_fungible_asset}
            exec.asset_vault::add_non_fungible_asset dropw

            # check that the non-fungible asset is presented in the input vault
            exec.memory::get_input_vault_root_ptr
            push.{ASSET_KEY}
            exec.asset_vault::get_asset
            push.{non_fungible_asset}
            assert_eqw.err="input vault should contain the asset"

            # burn the non-fungible asset
            push.{non_fungible_asset}
            call.mock_faucet::burn

            # assert the correct asset is returned
            push.{non_fungible_asset}
            assert_eqw.err="burnt asset does not match expected asset"

            # assert the input vault has been updated and does not have the burnt asset
            exec.memory::get_input_vault_root_ptr
            push.{ASSET_KEY}
            exec.asset_vault::get_asset
            # the returned word should be empty, indicating the asset is absent
            padw assert_eqw.err="input vault should not contain burned asset"

            dropw
        end
        "#,
        ASSET_KEY = non_fungible_asset_burnt.vault_key(),
        non_fungible_asset = Word::from(non_fungible_asset_burnt),
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
            push.{non_fungible_asset}
            call.faucet::burn
        end
        ",
        non_fungible_asset = Word::from(non_fungible_asset_burnt)
    );

    let exec_output = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_VAULT_NON_FUNGIBLE_ASSET_TO_REMOVE_NOT_FOUND);
    Ok(())
}

/// Tests that burning a non-fungible asset on a non-faucet account fails.
#[tokio::test]
async fn burn_non_fungible_asset_fails_on_non_faucet_account() -> anyhow::Result<()> {
    let account = setup_non_faucet_account()?;

    let code = format!(
        "
      use mock::faucet

      begin
          push.{asset}
          call.faucet::burn
      end
      ",
        asset = Word::from(FungibleAsset::mock(50))
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
            push.{non_fungible_asset}
            call.faucet::burn
        end
        ",
        non_fungible_asset = Word::from(non_fungible_asset_burnt)
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
    // Build a custom non-faucet account that (invalidly) exposes faucet procedures.
    let faucet_code = CodeBuilder::with_mock_libraries_with_source_manager(Arc::new(
        DefaultSourceManager::default(),
    ))
    .compile_component_code(
        "test::non_faucet_component",
        "pub use ::miden::protocol::faucet::mint
         pub use ::miden::protocol::faucet::burn",
    )?;
    let faucet_component = AccountComponent::new(faucet_code, vec![])?
        .with_supported_type(AccountType::RegularAccountUpdatableCode);
    Ok(AccountBuilder::new([4; 32])
        .account_type(AccountType::RegularAccountUpdatableCode)
        .with_auth_component(NoopAuthComponent)
        .with_component(faucet_component)
        .build_existing()?)
}
