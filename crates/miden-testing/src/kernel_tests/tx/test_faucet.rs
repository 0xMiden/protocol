use alloc::sync::Arc;

use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountStorage,
    AccountType,
    StorageMap,
};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{FungibleAsset, NonFungibleAsset};
use miden_protocol::errors::tx_kernel::{
    ERR_FAUCET_NEW_TOTAL_SUPPLY_WOULD_EXCEED_MAX_ASSET_AMOUNT,
    ERR_FAUCET_NON_FUNGIBLE_ASSET_ALREADY_ISSUED,
    ERR_FAUCET_NON_FUNGIBLE_ASSET_TO_BURN_NOT_FOUND,
    ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN,
    ERR_NON_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN,
    ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW,
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
    FUNGIBLE_FAUCET_INITIAL_BALANCE,
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
    let expected_final_amount = FUNGIBLE_FAUCET_INITIAL_BALANCE + FUNGIBLE_ASSET_AMOUNT;

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
            push.{prefix} push.{suffix} push.0 push.{FUNGIBLE_ASSET_AMOUNT}
            call.mock_faucet::mint

            # assert the correct asset is returned
            push.{prefix} push.{suffix} push.0 push.{FUNGIBLE_ASSET_AMOUNT}
            assert_eqw.err="minted asset does not match expected asset"

            # assert the input vault has been updated
            exec.memory::get_input_vault_root_ptr
            push.{suffix} push.{prefix}
            exec.asset_vault::get_balance
            push.{FUNGIBLE_ASSET_AMOUNT} assert_eq.err="input vault should contain minted asset"

            exec.faucet::get_total_issuance
            push.{expected_final_amount}
            assert_eq.err="expected total issuance to be {expected_final_amount}"
        end
        "#,
        prefix = faucet_id.prefix().as_felt(),
        suffix = faucet_id.suffix(),
    );

    TransactionContextBuilder::with_fungible_faucet(
        faucet_id.into(),
        Felt::new(FUNGIBLE_FAUCET_INITIAL_BALANCE),
    )
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
    let tx_context = TransactionContextBuilder::with_fungible_faucet(
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        Felt::new(10),
    )
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

#[tokio::test]
async fn test_mint_fungible_asset_fails_saturate_max_amount() -> anyhow::Result<()> {
    let code = format!(
        "
        use mock::faucet

        begin
            push.{asset}
            call.faucet::mint
        end
    ",
        asset = Word::from(FungibleAsset::mock(FungibleAsset::MAX_AMOUNT))
    );
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(code)?;

    let result = TransactionContextBuilder::with_fungible_faucet(
        FungibleAsset::mock_issuer().into(),
        Felt::new(1),
    )
    .tx_script(tx_script)
    .build()?
    .execute()
    .await;

    assert_transaction_executor_error!(
        result,
        ERR_FAUCET_NEW_TOTAL_SUPPLY_WOULD_EXCEED_MAX_ASSET_AMOUNT
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
    let asset_vault_key = non_fungible_asset.vault_key();

    let code = format!(
        r#"
        use miden::core::collections::smt

        use $kernel::account
        use $kernel::asset_vault
        use $kernel::memory
        use $kernel::prologue
        use mock::faucet->mock_faucet

        const FAUCET_SYSDATA_SLOT_NAME = word("{faucet_sysdata_slot_name}")

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
            push.{non_fungible_asset}
            exec.asset_vault::has_non_fungible_asset
            assert.err="vault should contain asset"

            # assert the non-fungible asset has been added to the faucet smt
            push.FAUCET_SYSDATA_SLOT_NAME[2..4]
            exec.account::get_item
            push.{asset_vault_key}
            exec.smt::get
            push.{non_fungible_asset}
            assert_eqw.err="minted asset should have been added to faucet SMT"
            dropw
        end
        "#,
        faucet_sysdata_slot_name = AccountStorage::faucet_sysdata_slot(),
        non_fungible_asset = Word::from(non_fungible_asset),
        asset_vault_key = StorageMap::hash_key(asset_vault_key.into()),
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

#[tokio::test]
async fn test_mint_non_fungible_asset_fails_asset_already_exists() -> anyhow::Result<()> {
    let tx_context =
        TransactionContextBuilder::with_non_fungible_faucet(NonFungibleAsset::mock_issuer().into())
            .build()?;

    let non_fungible_asset = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA_2);

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

    assert_execution_error!(exec_output, ERR_FAUCET_NON_FUNGIBLE_ASSET_ALREADY_ISSUED);

    Ok(())
}

// FUNGIBLE FAUCET BURN TESTS
// ================================================================================================

#[tokio::test]
async fn test_burn_fungible_asset_succeeds() -> anyhow::Result<()> {
    let tx_context = {
        let account = Account::mock_fungible_faucet(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
            Felt::new(FUNGIBLE_FAUCET_INITIAL_BALANCE),
        );
        let note = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::new(account.id(), 100u64).unwrap().into()],
        );
        TransactionContextBuilder::new(account).extend_input_notes(vec![note]).build()?
    };

    let faucet_id = tx_context.account().id();
    let expected_final_amount = FUNGIBLE_FAUCET_INITIAL_BALANCE - FUNGIBLE_ASSET_AMOUNT;

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
            push.{prefix} push.{suffix} push.0 push.{FUNGIBLE_ASSET_AMOUNT}
            call.mock_faucet::burn

            # assert the correct asset is returned
            push.{prefix} push.{suffix} push.0 push.{FUNGIBLE_ASSET_AMOUNT}
            assert_eqw.err="burnt asset does not match expected asset"

            # assert the input vault has been updated
            exec.memory::get_input_vault_root_ptr

            push.{suffix} push.{prefix}
            exec.asset_vault::get_balance

            push.{final_input_vault_asset_amount}
            assert_eq.err="vault balance does not match expected balance"

            exec.faucet::get_total_issuance
            push.{expected_final_amount}
            assert_eq.err="expected total issuance to be {expected_final_amount}"
        end
        "#,
        prefix = faucet_id.prefix().as_felt(),
        suffix = faucet_id.suffix(),
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
    let tx_context = TransactionContextBuilder::with_fungible_faucet(
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        Felt::new(FUNGIBLE_FAUCET_INITIAL_BALANCE),
    )
    .build()?;

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap();

    let code = format!(
        "
        use $kernel::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{prefix} push.{suffix} push.0 push.{FUNGIBLE_ASSET_AMOUNT}
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
    let tx_context = TransactionContextBuilder::with_fungible_faucet(
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        Felt::new(FUNGIBLE_FAUCET_INITIAL_BALANCE),
    )
    .build()?;

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap();

    let code = format!(
        "
        use $kernel::prologue
        use mock::faucet

        begin
            exec.prologue::prepare_transaction
            push.{prefix} push.{suffix} push.0 push.{saturating_amount}
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
    let burnt_asset_vault_key = non_fungible_asset_burnt.vault_key();

    let code = format!(
        r#"
        use $kernel::account
        use $kernel::asset_vault
        use $kernel::memory
        use $kernel::prologue
        use mock::faucet->mock_faucet

        const FAUCET_SYSDATA_SLOT_NAME = word("{faucet_sysdata_slot_name}")

        begin
            exec.prologue::prepare_transaction

            # add non-fungible asset to the vault
            exec.memory::get_input_vault_root_ptr push.{non_fungible_asset}
            exec.asset_vault::add_non_fungible_asset dropw

            # check that the non-fungible asset is presented in the input vault
            exec.memory::get_input_vault_root_ptr
            push.{non_fungible_asset}
            exec.asset_vault::has_non_fungible_asset
            assert.err="input vault should contain the asset"

            # check that the non-fungible asset is in the account map
            push.{burnt_asset_vault_key}
            push.FAUCET_SYSDATA_SLOT_NAME[2..4]
            exec.account::get_map_item
            push.{non_fungible_asset}
            assert_eqw.err="non-fungible asset should be in the account map"
            dropw

            # burn the non-fungible asset
            push.{non_fungible_asset}
            call.mock_faucet::burn

            # assert the correct asset is returned
            push.{non_fungible_asset}
            assert_eqw.err="burnt asset does not match expected asset"

            # assert the input vault has been updated and does not have the burnt asset
            exec.memory::get_input_vault_root_ptr
            push.{non_fungible_asset}
            exec.asset_vault::has_non_fungible_asset
            not assert.err="input vault should not contain burned asset"

            # assert that the non-fungible asset is no longer in the account map
            push.{burnt_asset_vault_key}
            push.FAUCET_SYSDATA_SLOT_NAME[2..4]
            exec.account::get_map_item
            padw
            assert_eqw.err="burnt asset should have been removed from map"
            dropw
        end
        "#,
        faucet_sysdata_slot_name = AccountStorage::faucet_sysdata_slot(),
        non_fungible_asset = Word::from(non_fungible_asset_burnt),
        burnt_asset_vault_key = burnt_asset_vault_key,
    );

    tx_context.execute_code(&code).await.unwrap();
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

    assert_execution_error!(exec_output, ERR_FAUCET_NON_FUNGIBLE_ASSET_TO_BURN_NOT_FOUND);
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

    assert_execution_error!(exec_output, ERR_FAUCET_NON_FUNGIBLE_ASSET_TO_BURN_NOT_FOUND);
    Ok(())
}

// IS NON FUNGIBLE ASSET ISSUED TESTS
// ================================================================================================

#[tokio::test]
async fn test_is_non_fungible_asset_issued_succeeds() -> anyhow::Result<()> {
    // NON_FUNGIBLE_ASSET_DATA_2 is "issued" during the mock faucet creation, so it is already in
    // the map of issued assets.
    let tx_context =
        TransactionContextBuilder::with_non_fungible_faucet(NonFungibleAsset::mock_issuer().into())
            .build()?;

    let non_fungible_asset_1 = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA);
    let non_fungible_asset_2 = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA_2);

    let code = format!(
        r#"
        use $kernel::prologue
        use miden::protocol::faucet

        begin
            exec.prologue::prepare_transaction

            # check that NON_FUNGIBLE_ASSET_DATA_2 is already issued
            push.{non_fungible_asset_2}
            exec.faucet::is_non_fungible_asset_issued

            # assert that NON_FUNGIBLE_ASSET_DATA_2 is issued
            eq.1 assert.err="non fungible asset data 2 should have been issued"

            # check that NON_FUNGIBLE_ASSET_DATA was not issued yet
            push.{non_fungible_asset_1}
            exec.faucet::is_non_fungible_asset_issued

            # assert that NON_FUNGIBLE_ASSET_DATA is not issued
            eq.0 assert.err="non fungible asset data should have been issued"
        end
        "#,
        non_fungible_asset_1 = Word::from(non_fungible_asset_1),
        non_fungible_asset_2 = Word::from(non_fungible_asset_2),
    );

    tx_context.execute_code(&code).await.unwrap();
    Ok(())
}

// GET TOTAL ISSUANCE TESTS
// ================================================================================================

#[tokio::test]
async fn test_get_total_issuance_succeeds() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_fungible_faucet(
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        Felt::new(FUNGIBLE_FAUCET_INITIAL_BALANCE),
    )
    .build()?;

    let code = format!(
        r#"
        use $kernel::prologue
        use miden::protocol::faucet

        begin
            exec.prologue::prepare_transaction

            # get the fungible faucet balance
            exec.faucet::get_total_issuance
            # => [total_issuance]

            # assert the correct balance is returned
            push.{FUNGIBLE_FAUCET_INITIAL_BALANCE} assert_eq.err="total issuance did not match expected value"
            # => []
        end
        "#,
    );

    tx_context.execute_code(&code).await.unwrap();
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
