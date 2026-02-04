use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use miden_processor::fast::ExecutionOutput;
use miden_processor::{AdviceInputs, Felt};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountProcedureRoot,
    AccountStorage,
    AccountStorageMode,
    StorageSlot,
};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
use miden_protocol::errors::tx_kernel::{
    ERR_FOREIGN_ACCOUNT_CONTEXT_AGAINST_NATIVE_ACCOUNT,
    ERR_FOREIGN_ACCOUNT_INVALID_COMMITMENT,
    ERR_FOREIGN_ACCOUNT_MAX_NUMBER_EXCEEDED,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
};
use miden_protocol::testing::storage::STORAGE_LEAVES_2;
use miden_protocol::transaction::memory::{
    ACCOUNT_DATA_LENGTH,
    ACCT_ACTIVE_STORAGE_SLOTS_SECTION_OFFSET,
    ACCT_CODE_COMMITMENT_OFFSET,
    ACCT_ID_AND_NONCE_OFFSET,
    ACCT_NUM_PROCEDURES_OFFSET,
    ACCT_NUM_STORAGE_SLOTS_OFFSET,
    ACCT_PROCEDURES_SECTION_OFFSET,
    ACCT_STORAGE_COMMITMENT_OFFSET,
    ACCT_VAULT_ROOT_OFFSET,
    NATIVE_ACCOUNT_DATA_PTR,
};
use miden_protocol::{FieldElement, Word, ZERO};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_tx::LocalTransactionProver;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::{Auth, MockChainBuilder, assert_execution_error, assert_transaction_executor_error};

// SIMPLE FPI TESTS
// ================================================================================================

// FOREIGN PROCEDURE INVOCATION TESTS
// ================================================================================================

#[tokio::test]
async fn test_fpi_memory_single_account() -> anyhow::Result<()> {
    // Prepare the test data
    let mock_value_slot0 = AccountStorage::mock_value_slot0();
    let mock_map_slot = AccountStorage::mock_map_slot();
    let foreign_account_code_source = "
        use miden::protocol::active_account

        pub proc get_item_foreign
            # make this foreign procedure unique to make sure that we invoke the procedure of the
            # foreign account, not the native one
            push.1 drop
            exec.active_account::get_item

            # truncate the stack
            movup.6 movup.6 drop drop
        end

        pub proc get_map_item_foreign
            # make this foreign procedure unique to make sure that we invoke the procedure of the
            # foreign account, not the native one
            push.2 drop
            exec.active_account::get_map_item
        end
    ";

    let source_manager = Arc::new(DefaultSourceManager::default());
    let foreign_account_component = AccountComponent::new(
        CodeBuilder::with_source_manager(source_manager.clone())
            .compile_component_code("test::foreign_account", foreign_account_code_source)?,
        vec![mock_value_slot0.clone(), mock_map_slot.clone()],
    )?
    .with_supports_all_types();

    let foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(foreign_account_component)
        .build_existing()?;

    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(vec![AccountStorage::mock_map_slot()]))
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    let fpi_inputs = mock_chain
        .get_foreign_account_inputs(foreign_account.id())
        .expect("failed to get foreign account inputs");

    let tx_context = mock_chain
        .build_tx_context(native_account.id(), &[], &[])
        .expect("failed to build tx context")
        .foreign_accounts(vec![fpi_inputs])
        .with_source_manager(source_manager)
        .build()?;

    // GET ITEM
    // --------------------------------------------------------------------------------------------
    // Check the correctness of the memory layout after `get_item_foreign` account procedure
    // invocation

    let code = format!(
        r#"
        use miden::core::sys

        use $kernel::prologue
        use miden::protocol::tx

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        begin
            exec.prologue::prepare_transaction

            # pad the stack for the `execute_foreign_procedure` execution
            padw padw
            # => [pad(8)]

            # push the slot name of desired storage item
            push.MOCK_VALUE_SLOT0[0..2]

            # get the hash of the `get_item_foreign` procedure of the foreign account
            push.{get_item_foreign_hash}

            # push the foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT,
            #     slot_id_prefix, slot_id_suffix, pad(8)]

            exec.tx::execute_foreign_procedure
            # => [STORAGE_VALUE_1]

            # truncate the stack
            exec.sys::truncate_stack
            end
            "#,
        mock_value_slot0 = mock_value_slot0.name(),
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
        get_item_foreign_hash = foreign_account.code().procedures()[1].mast_root(),
    );

    let exec_output = tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word_be(0),
        mock_value_slot0.content().value(),
        "Value at the top of the stack should be equal to [1, 2, 3, 4]",
    );

    foreign_account_data_memory_assertions(&foreign_account, &exec_output);

    // GET MAP ITEM
    // --------------------------------------------------------------------------------------------
    // Check the correctness of the memory layout after `get_map_item` account procedure invocation

    let code = format!(
        r#"
        use miden::core::sys

        use $kernel::prologue
        use miden::protocol::tx

        const MOCK_MAP_SLOT = word("{mock_map_slot}")

        begin
            exec.prologue::prepare_transaction

            # pad the stack for the `execute_foreign_procedure` execution
            padw
            # => [pad(4)]

            # push the key of desired storage item
            push.{map_key}

            # push the slot name of the desired storage item
            push.MOCK_MAP_SLOT[0..2]

            # get the hash of the `get_map_item_foreign` account procedure
            push.{get_map_item_foreign_hash}

            # push the foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT,
            #     slot_id_prefix, slot_id_suffix, MAP_KEY, pad(4)]

            exec.tx::execute_foreign_procedure
            # => [MAP_VALUE]

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#,
        mock_map_slot = mock_map_slot.name(),
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
        map_key = STORAGE_LEAVES_2[0].0,
        get_map_item_foreign_hash = foreign_account.code().procedures()[2].mast_root(),
    );

    let exec_output = tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_stack_word_be(0),
        STORAGE_LEAVES_2[0].1,
        "Value at the top of the stack should be equal [1, 2, 3, 4]",
    );

    foreign_account_data_memory_assertions(&foreign_account, &exec_output);

    // GET ITEM TWICE
    // --------------------------------------------------------------------------------------------
    // Check the correctness of the memory layout after two consecutive invocations of the
    // `get_item` account procedures. Invoking two foreign procedures from the same account should
    // result in reuse of the loaded account.

    let code = format!(
        r#"
        use miden::core::sys

        use $kernel::prologue
        use miden::protocol::tx

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        begin
            exec.prologue::prepare_transaction

            ### Get the storage item at index 0 #####################
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw
            # => [pad(8)]

            # push the slot name of desired storage item
            push.MOCK_VALUE_SLOT0[0..2]

            # get the hash of the `get_item_foreign` procedure of the foreign account
            push.{get_item_foreign_hash}

            # push the foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT,
            #     slot_id_prefix, slot_id_suffix, pad(8)]

            exec.tx::execute_foreign_procedure dropw
            # => []

            ### Get the storage item at index 0 again ###############
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw
            # => [pad(8)]

            # push the slot name of the desired storage item
            push.MOCK_VALUE_SLOT0[0..2]

            # get the hash of the `get_item_foreign` procedure of the foreign account
            push.{get_item_foreign_hash}

            # push the foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT,
            #     slot_id_prefix, slot_id_suffix, pad(8)]

            exec.tx::execute_foreign_procedure

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#,
        mock_value_slot0 = mock_value_slot0.name(),
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
        get_item_foreign_hash = foreign_account.code().procedures()[1].mast_root(),
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    // Check that the second invocation of the foreign procedure from the same account does not load
    // the account data again: already loaded data should be reused.
    //
    // Native account:    [8192; 16383]  <- initialized during prologue
    // Foreign account:   [16384; 24575] <- initialized during first FPI
    // Next account slot: [24576; 32767] <- should not be initialized
    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_ACCOUNT_DATA_PTR + ACCOUNT_DATA_LENGTH as u32 * 2),
        Word::empty(),
        "Memory starting from 24576 should stay uninitialized"
    );
    Ok(())
}

#[tokio::test]
async fn test_fpi_memory_two_accounts() -> anyhow::Result<()> {
    // Prepare the test data
    let mock_value_slot0 = AccountStorage::mock_value_slot0();
    let mock_value_slot1 = AccountStorage::mock_value_slot1();

    let foreign_account_code_source_1 = "
        use miden::protocol::active_account

        pub proc get_item_foreign_1
            # make this foreign procedure unique to make sure that we invoke the procedure of the
            # foreign account, not the native one
            push.1 drop
            exec.active_account::get_item

            # truncate the stack
            movup.6 movup.6 drop drop
        end
    ";
    let foreign_account_code_source_2 = "
        use miden::protocol::active_account

        pub proc get_item_foreign_2
            # make this foreign procedure unique to make sure that we invoke the procedure of the
            # foreign account, not the native one
            push.2 drop
            exec.active_account::get_item

            # truncate the stack
            movup.6 movup.6 drop drop
        end
    ";

    let foreign_account_component_1 = AccountComponent::new(
        CodeBuilder::default()
            .compile_component_code("test::foreign_account_1", foreign_account_code_source_1)?,
        vec![mock_value_slot0.clone()],
    )?
    .with_supports_all_types();

    let foreign_account_component_2 = AccountComponent::new(
        CodeBuilder::default()
            .compile_component_code("test::foreign_account_2", foreign_account_code_source_2)?,
        vec![mock_value_slot1.clone()],
    )?
    .with_supports_all_types();

    let foreign_account_1 = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(foreign_account_component_1)
        .build_existing()?;

    let foreign_account_2 = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(foreign_account_component_2)
        .build_existing()?;

    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    let mut mock_chain = MockChainBuilder::with_accounts([
        native_account.clone(),
        foreign_account_1.clone(),
        foreign_account_2.clone(),
    ])?
    .build()?;
    mock_chain.prove_next_block()?;
    let foreign_account_inputs_1 = mock_chain
        .get_foreign_account_inputs(foreign_account_1.id())
        .expect("failed to get foreign account inputs");

    let foreign_account_inputs_2 = mock_chain
        .get_foreign_account_inputs(foreign_account_2.id())
        .expect("failed to get foreign account inputs");

    let tx_context = mock_chain
        .build_tx_context(native_account.id(), &[], &[])?
        .foreign_accounts(vec![foreign_account_inputs_1, foreign_account_inputs_2])
        .build()?;

    // GET ITEM TWICE WITH TWO ACCOUNTS
    // --------------------------------------------------------------------------------------------
    // Check the correctness of the memory layout after two invocations of the `get_item` account
    // procedures separated by the call of this procedure against another foreign account. Invoking
    // two foreign procedures from the same account should result in reuse of the loaded account.

    let code = format!(
        r#"
        use miden::core::sys

        use $kernel::prologue
        use miden::protocol::tx

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")
        const MOCK_VALUE_SLOT1 = word("{mock_value_slot1}")

        begin
            exec.prologue::prepare_transaction

            ### Get the storage item from the first account
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw
            # => [pad(8)]

            # push the slot name of desired storage item
            push.MOCK_VALUE_SLOT0[0..2]

            # get the hash of the `get_item_foreign` procedure of the foreign account
            push.{get_item_foreign_1_hash}

            # push the foreign account ID
            push.{foreign_1_suffix} push.{foreign_1_prefix}
            # => [foreign_account_1_id_prefix, foreign_account_1_id_suffix, FOREIGN_PROC_ROOT,
            #     slot_id_prefix, slot_id_suffix, pad(8)]

            exec.tx::execute_foreign_procedure dropw
            # => []

            ### Get the storage item from the second account
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw
            # => [pad(8)]

            # push the slot name of desired storage item
            push.MOCK_VALUE_SLOT1[0..2]

            # get the hash of the `get_item_foreign_2` procedure of the foreign account 2
            push.{get_item_foreign_2_hash}

            # push the foreign account ID
            push.{foreign_2_suffix} push.{foreign_2_prefix}
            # => [foreign_account_2_id_prefix, foreign_account_2_id_suffix, FOREIGN_PROC_ROOT,
            #     slot_id_prefix, slot_id_suffix, pad(8)]

            exec.tx::execute_foreign_procedure dropw
            # => []

            ### Get the storage item from the first account again
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw
            # => [pad(8)]

            # push the slot name of desired storage item
            push.MOCK_VALUE_SLOT0[0..2]

            # get the hash of the `get_item_foreign_1` procedure of the foreign account 1
            push.{get_item_foreign_1_hash}

            # push the foreign account ID
            push.{foreign_1_suffix} push.{foreign_1_prefix}
            # => [foreign_account_1_id_prefix, foreign_account_1_id_suffix, FOREIGN_PROC_ROOT,
            #     slot_id_prefix, slot_id_suffix, pad(8)]

            exec.tx::execute_foreign_procedure

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#,
        mock_value_slot0 = mock_value_slot0.name(),
        mock_value_slot1 = mock_value_slot1.name(),
        get_item_foreign_1_hash = foreign_account_1.code().procedures()[1].mast_root(),
        get_item_foreign_2_hash = foreign_account_2.code().procedures()[1].mast_root(),
        foreign_1_prefix = foreign_account_1.id().prefix().as_felt(),
        foreign_1_suffix = foreign_account_1.id().suffix(),
        foreign_2_prefix = foreign_account_2.id().prefix().as_felt(),
        foreign_2_suffix = foreign_account_2.id().suffix(),
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    // Check the correctness of the memory layout after multiple foreign procedure invocations from
    // different foreign accounts
    //
    // Native account:    [8192; 16383]  <- initialized during prologue
    // Foreign account 1: [16384; 24575] <- initialized during first FPI
    // Foreign account 2: [24576; 32767] <- initialized during second FPI
    // Next account slot: [32768; 40959] <- should not be initialized

    // check that the first word of the first foreign account slot is correct
    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_ACCOUNT_DATA_PTR + ACCOUNT_DATA_LENGTH as u32),
        Word::new([
            foreign_account_1.id().suffix(),
            foreign_account_1.id().prefix().as_felt(),
            ZERO,
            foreign_account_1.nonce()
        ])
    );

    // check that the first word of the second foreign account slot is correct
    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_ACCOUNT_DATA_PTR + ACCOUNT_DATA_LENGTH as u32 * 2),
        Word::new([
            foreign_account_2.id().suffix(),
            foreign_account_2.id().prefix().as_felt(),
            ZERO,
            foreign_account_2.nonce()
        ])
    );

    // check that the first word of the third foreign account slot was not initialized
    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_ACCOUNT_DATA_PTR + ACCOUNT_DATA_LENGTH as u32 * 3),
        Word::empty(),
        "Memory starting from 32768 should stay uninitialized"
    );

    Ok(())
}

/// Test the correctness of the foreign procedure execution.
///
/// It checks the foreign account code loading, providing the mast forest to the executor,
/// construction of the account procedure maps and execution the foreign procedure in order to
/// obtain the data from the foreign account's storage slot.
#[tokio::test]
async fn test_fpi_execute_foreign_procedure() -> anyhow::Result<()> {
    // Prepare the test data
    let mock_value_slot0 = AccountStorage::mock_value_slot0();
    let mock_map_slot = AccountStorage::mock_map_slot();

    let foreign_account_code_source = "
        use miden::protocol::active_account

        pub proc get_item_foreign
            # make this foreign procedure unique to make sure that we invoke the procedure of the
            # foreign account, not the native one
            push.1 drop
            exec.active_account::get_item

            # truncate the stack
            movup.6 movup.6 drop drop
        end

        pub proc get_map_item_foreign
            # make this foreign procedure unique to make sure that we invoke the procedure of the
            # foreign account, not the native one
            push.2 drop
            exec.active_account::get_map_item
        end
    ";

    let source_manager = Arc::new(DefaultSourceManager::default());
    let foreign_account_component = AccountComponent::new(
        CodeBuilder::with_kernel_library(source_manager.clone())
            .compile_component_code("foreign_account", foreign_account_code_source)?,
        vec![mock_value_slot0.clone(), mock_map_slot.clone()],
    )?
    .with_supports_all_types();

    let foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(foreign_account_component.clone())
        .build_existing()?;

    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    let code = format!(
        r#"
        use miden::core::sys

        use miden::protocol::tx

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")
        const MOCK_MAP_SLOT = word("{mock_map_slot}")

        begin
            # get the storage item
            # pad the stack for the `execute_foreign_procedure` execution
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw
            # => [pad(8)]

            # push the slot name of desired storage item
            push.MOCK_VALUE_SLOT0[0..2]

            # get the hash of the `get_item_foreign` account procedure
            procref.::foreign_account::get_item_foreign

            # push the foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT
            #     slot_id_prefix, slot_id_suffix, pad(8)]]

            exec.tx::execute_foreign_procedure
            # => [STORAGE_VALUE]

            # assert the correctness of the obtained value
            push.1.2.3.4 assert_eqw.err="foreign proc returned unexpected value"
            # => []

            # get an item from the storage map
            # pad the stack for the `execute_foreign_procedure` execution
            padw
            # => [pad(4)]

            # push the key of desired storage item
            push.{map_key}

            # push the slot name of the desired storage map
            push.MOCK_MAP_SLOT[0..2]

            # get the hash of the `get_map_item_foreign` account procedure
            procref.::foreign_account::get_map_item_foreign

            # push the foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT,
            #     slot_id_prefix, slot_id_suffix, MAP_ITEM_KEY, pad(4)]

            exec.tx::execute_foreign_procedure
            # => [MAP_VALUE]

            # assert the correctness of the obtained value
            push.1.2.3.4 assert_eqw.err="foreign proc returned unexpected value"
            # => []

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#,
        mock_value_slot0 = mock_value_slot0.name(),
        mock_map_slot = mock_map_slot.name(),
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
        map_key = STORAGE_LEAVES_2[0].0,
    );

    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .with_dynamically_linked_library(foreign_account_component.component_code())?
        .compile_tx_script(code)?;

    let foreign_account_inputs = mock_chain
        .get_foreign_account_inputs(foreign_account.id())
        .expect("failed to get foreign account inputs");

    mock_chain
        .build_tx_context(native_account.id(), &[], &[])
        .expect("failed to build tx context")
        .foreign_accounts([foreign_account_inputs])
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Test that a foreign account can get the balance of a fungible asset and check the presence of a
/// non-fungible asset.
#[tokio::test]
async fn foreign_account_can_get_balance_and_presence_of_asset() -> anyhow::Result<()> {
    let fungible_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?;
    let non_fungible_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET)?;

    // Create two different assets.
    let fungible_asset = Asset::Fungible(FungibleAsset::new(fungible_faucet_id, 1)?);
    let non_fungible_asset = Asset::NonFungible(NonFungibleAsset::new(
        &NonFungibleAssetDetails::new(non_fungible_faucet_id.prefix(), vec![1, 2, 3])?,
    )?);

    let foreign_account_code_source = format!(
        "
        use miden::protocol::active_account

        pub proc get_asset_balance
            # get balance of first asset
            push.{fungible_faucet_id_suffix} push.{fungible_faucet_id_prefix}
            exec.active_account::get_balance
            # => [balance]

            # check presence of non fungible asset
            push.{non_fungible_asset_word}
            exec.active_account::has_non_fungible_asset
            # => [has_asset, balance]

            # add the balance and the bool
            add
            # => [has_asset_balance]

            # keep only the result on stack
            swap drop
            # => [has_asset_balance]
        end
        ",
        fungible_faucet_id_prefix = fungible_faucet_id.prefix().as_felt(),
        fungible_faucet_id_suffix = fungible_faucet_id.suffix(),
        non_fungible_asset_word = Word::from(non_fungible_asset),
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let foreign_account_component = AccountComponent::new(
        CodeBuilder::with_source_manager(source_manager.clone())
            .compile_component_code("foreign_account_code", foreign_account_code_source)?,
        vec![],
    )?
    .with_supports_all_types();

    let foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(foreign_account_component.clone())
        .with_assets(vec![fungible_asset, non_fungible_asset])
        .build_existing()?;

    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    let code = format!(
        "
        use miden::core::sys

        use miden::protocol::tx

        begin
            # Get the added balance of two assets from foreign account
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw padw push.0.0.0
            # => [pad(15)]

            # get the hash of the `get_asset_balance` procedure
            procref.::foreign_account_code::get_asset_balance

            # push the foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, pad(15)]

            exec.tx::execute_foreign_procedure
            # => [has_asset_balance]

            # assert that the non fungible asset exists and the fungible asset has balance 1
            push.2 assert_eq.err=\"Total balance should be 2\"
            # => []

            # truncate the stack
            exec.sys::truncate_stack
        end
        ",
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
    );

    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .with_dynamically_linked_library(foreign_account_component.component_code())?
        .compile_tx_script(code)?;

    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(foreign_account.id())?;

    mock_chain
        .build_tx_context(native_account.id(), &[], &[])?
        .foreign_accounts([foreign_account_inputs])
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Test that the `miden::get_initial_balance` procedure works correctly being called from a foreign
/// account.
#[tokio::test]
async fn foreign_account_get_initial_balance() -> anyhow::Result<()> {
    let fungible_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?;
    let fungible_asset = Asset::Fungible(FungibleAsset::new(fungible_faucet_id, 10)?);

    let foreign_account_code_source = format!(
        "
        use miden::protocol::active_account

        pub proc get_initial_balance
            # push the faucet ID on the stack
            push.{fungible_faucet_id_suffix} push.{fungible_faucet_id_prefix}

            # get the initial balance of the asset associated with the provided faucet ID
            exec.active_account::get_balance
            # => [initial_balance]

            # truncate the stack
            swap drop
            # => [initial_balance]
        end
        ",
        fungible_faucet_id_prefix = fungible_faucet_id.prefix().as_felt(),
        fungible_faucet_id_suffix = fungible_faucet_id.suffix(),
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let foreign_account_component = AccountComponent::new(
        CodeBuilder::with_source_manager(source_manager.clone())
            .compile_component_code("foreign_account_code", foreign_account_code_source)?,
        vec![],
    )?
    .with_supports_all_types();

    let foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(foreign_account_component.clone())
        .with_assets(vec![fungible_asset])
        .build_existing()?;

    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    let code = format!(
        "
        use miden::core::sys

        use miden::protocol::tx

        begin
            # Get the initial balance of the fungible asset from the foreign account

            # pad the stack for the `execute_foreign_procedure` execution
            padw padw padw push.0.0.0
            # => [pad(15)]

            # get the hash of the `get_initial_balance` procedure
            procref.::foreign_account_code::get_initial_balance

            # push the foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, pad(15)]

            exec.tx::execute_foreign_procedure
            # => [init_foreign_balance]

            # assert that the initial balance of the asset in the foreign account equals 10
            push.10 assert_eq.err=\"Initial balance should be 10\"
            # => []

            # truncate the stack
            exec.sys::truncate_stack
        end
        ",
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
    );

    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .with_dynamically_linked_library(foreign_account_component.component_code())?
        .compile_tx_script(code)?;

    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(foreign_account.id())?;

    mock_chain
        .build_tx_context(native_account.id(), &[], &[])?
        .foreign_accounts([foreign_account_inputs])
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    Ok(())
}

// NESTED FPI TESTS
// ================================================================================================

/// Test the correctness of the cyclic foreign procedure calls.
///
/// It checks that the account data pointers are correctly added and removed from the account data
/// stack.
///
/// The call chain in this test looks like so:
/// `Native -> First FA -> Second FA -> First FA`
#[tokio::test]
async fn test_nested_fpi_cyclic_invocation() -> anyhow::Result<()> {
    // ------ SECOND FOREIGN ACCOUNT ---------------------------------------------------------------
    let mock_value_slot0 = AccountStorage::mock_value_slot0();
    let mock_value_slot1 = AccountStorage::mock_value_slot1();

    let second_foreign_account_code_source = format!(
        r#"
        use miden::protocol::tx
        use miden::protocol::active_account

        use miden::core::sys

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")
        const MOCK_VALUE_SLOT1 = word("{mock_value_slot1}")

        pub proc second_account_foreign_proc
            # get the storage item at value1
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw
            # => [pad(8)]

            # push the index of desired storage item
            push.MOCK_VALUE_SLOT1[0..2]

            # get the hash of the `get_item_foreign` account procedure from the advice stack
            adv_push.4

            # push the foreign account ID from the advice stack
            adv_push.2
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT,
            #     slot_id_prefix, slot_id_suffix, pad(8)]

            exec.tx::execute_foreign_procedure
            # => [storage_value]

            # make sure that the resulting value equals 5
            dup push.5 assert_eq.err="value should have been 5"

            # get the first element of the value0 storage slot (it should be 1) and add it to the
            # obtained foreign value.
            push.MOCK_VALUE_SLOT0[0..2] exec.active_account::get_item
            drop drop drop
            add

            # assert that the resulting value equals 6
            dup push.6 assert_eq.err="value should have been 6"

            exec.sys::truncate_stack
        end
    "#,
        mock_value_slot0 = mock_value_slot0.name(),
        mock_value_slot1 = mock_value_slot1.name(),
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let second_foreign_account_component = AccountComponent::new(
        CodeBuilder::with_kernel_library(source_manager.clone()).compile_component_code(
            "test::second_foreign_account",
            second_foreign_account_code_source,
        )?,
        vec![mock_value_slot0.clone()],
    )?
    .with_supports_all_types();

    let second_foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(second_foreign_account_component)
        .build_existing()?;

    // ------ FIRST FOREIGN ACCOUNT ---------------------------------------------------------------
    let first_foreign_account_code_source = format!(
        r#"
        use miden::protocol::tx
        use miden::protocol::active_account

        use miden::core::sys

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        pub proc first_account_foreign_proc
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw padw push.0.0.0
            # => [pad(15)]

            # get the hash of the `second_account_foreign_proc` account procedure from the advice stack
            adv_push.4

            # push the ID of the second foreign account from the advice stack
            adv_push.2
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, storage_item_index, pad(14)]

            exec.tx::execute_foreign_procedure
            # => [storage_value]

            # get the second element of the value0 storage slot (it should be 2) and add it to the
            # obtained foreign value.
            push.MOCK_VALUE_SLOT0[0..2] exec.active_account::get_item
            drop drop swap drop
            add

            # assert that the resulting value equals 8
            dup push.8 assert_eq.err="value should have been 8"

            exec.sys::truncate_stack
        end

        pub proc get_item_foreign
            # make this foreign procedure unique to make sure that we invoke the procedure of the
            # foreign account, not the native one
            push.1 drop
            exec.active_account::get_item

            # return the first element of the resulting word
            drop drop drop
        end
    "#,
        mock_value_slot0 = mock_value_slot0.name(),
    );

    let first_foreign_account_component = AccountComponent::new(
        CodeBuilder::with_kernel_library(source_manager.clone())
            .compile_component_code("first_foreign_account", first_foreign_account_code_source)?,
        vec![mock_value_slot0.clone(), mock_value_slot1.clone()],
    )?
    .with_supports_all_types();

    let first_foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(first_foreign_account_component.clone())
        .build_existing()?;

    // ------ NATIVE ACCOUNT ---------------------------------------------------------------
    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    let mut mock_chain = MockChainBuilder::with_accounts([
        native_account.clone(),
        first_foreign_account.clone(),
        second_foreign_account.clone(),
    ])?
    .build()?;
    mock_chain.prove_next_block()?;
    let foreign_account_inputs = vec![
        mock_chain
            .get_foreign_account_inputs(first_foreign_account.id())
            .expect("failed to get foreign account inputs"),
        mock_chain
            .get_foreign_account_inputs(second_foreign_account.id())
            .expect("failed to get foreign account inputs"),
    ];

    // push the hashes of the foreign procedures and account IDs to the advice stack to be able to
    // call them dynamically.
    let mut advice_inputs = AdviceInputs::default();
    advice_inputs
        .stack
        .extend(*second_foreign_account.code().procedures()[1].mast_root());
    advice_inputs.stack.extend([
        second_foreign_account.id().suffix(),
        second_foreign_account.id().prefix().as_felt(),
    ]);

    advice_inputs
        .stack
        .extend(*first_foreign_account.code().procedures()[2].mast_root());
    advice_inputs.stack.extend([
        first_foreign_account.id().suffix(),
        first_foreign_account.id().prefix().as_felt(),
    ]);

    let code = format!(
        r#"
        use miden::core::sys
        use miden::protocol::tx

        begin
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw padw push.0.0.0
            # => [pad(15)]

            # get the hash of the `first_account_foreign_proc` procedure
            procref.::first_foreign_account::first_account_foreign_proc

            # push the foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, storage_item_index, pad(14)]

            exec.tx::execute_foreign_procedure
            # => [storage_value]

            # add 10 to the returning value
            add.10

            # assert that the resulting value equals 18
            push.18 assert_eq.err="sum should be 18"
            # => []

            exec.sys::truncate_stack
        end
        "#,
        foreign_prefix = first_foreign_account.id().prefix().as_felt(),
        foreign_suffix = first_foreign_account.id().suffix(),
    );

    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .with_dynamically_linked_library(first_foreign_account_component.component_code())?
        .compile_tx_script(code)?;

    mock_chain
        .build_tx_context(native_account.id(), &[], &[])
        .expect("failed to build tx context")
        .foreign_accounts(foreign_account_inputs)
        .extend_advice_inputs(advice_inputs)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Proves a transaction that uses FPI with two foreign accounts.
///
/// Call chain:
/// `Native -> First FA -> Second FA`
///
/// Each foreign account has unique code. The first foreign account calls a procedure on the second
/// foreign account via FPI. We then prove the executed transaction to ensure code for multiple
/// foreign accounts is correctly loaded into the prover host's MAST store.
#[tokio::test]
async fn test_prove_fpi_two_foreign_accounts_chain() -> anyhow::Result<()> {
    // ------ SECOND FOREIGN ACCOUNT ---------------------------------------------------------------
    // unique procedure which just leaves a constant on the stack
    let second_foreign_account_code_source = r#"
        use miden::core::sys

        pub proc second_account_foreign_proc
            # leave a constant result on the stack
            push.3

            # truncate any padding
            exec.sys::truncate_stack
        end
    "#;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let second_foreign_account_component = AccountComponent::new(
        CodeBuilder::with_kernel_library(source_manager.clone())
            .compile_component_code("foreign_account", second_foreign_account_code_source)?,
        vec![],
    )?
    .with_supports_all_types();

    let second_foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(second_foreign_account_component.clone())
        .build_existing()?;

    // ------ FIRST FOREIGN ACCOUNT ---------------------------------------------------------------
    // unique procedure which calls the second foreign account via FPI and then returns
    let first_foreign_account_code_source = format!(
        r#"
        use miden::protocol::tx
        use miden::core::sys

        pub proc first_account_foreign_proc
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw padw push.0.0.0
            # => [pad(15)]

            # get the hash of the `second_account_foreign_proc` using procref
            procref.::foreign_account::second_account_foreign_proc

            # push the ID of the second foreign account
            push.{second_foreign_suffix} push.{second_foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, pad(15)]

            # call the second foreign account
            exec.tx::execute_foreign_procedure
            # => [result_from_second]

            # keep the result and drop any padding if present
            exec.sys::truncate_stack
        end
        "#,
        second_foreign_prefix = second_foreign_account.id().prefix().as_felt(),
        second_foreign_suffix = second_foreign_account.id().suffix(),
    );

    // Link against the second foreign account.
    let first_foreign_account_code = CodeBuilder::with_kernel_library(source_manager.clone())
        .with_dynamically_linked_library(second_foreign_account_component.component_code())?
        .compile_component_code("first_foreign_account", first_foreign_account_code_source)?;
    let first_foreign_account_component =
        AccountComponent::new(first_foreign_account_code, vec![])?.with_supports_all_types();

    let first_foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(first_foreign_account_component.clone())
        .build_existing()?;

    // ------ NATIVE ACCOUNT ---------------------------------------------------------------
    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    let mut mock_chain = MockChainBuilder::with_accounts([
        native_account.clone(),
        first_foreign_account.clone(),
        second_foreign_account.clone(),
    ])?
    .build()?;
    mock_chain.prove_next_block()?;

    let foreign_account_inputs = vec![
        mock_chain
            .get_foreign_account_inputs(first_foreign_account.id())
            .expect("failed to get foreign account inputs"),
        mock_chain
            .get_foreign_account_inputs(second_foreign_account.id())
            .expect("failed to get foreign account inputs"),
    ];

    // ------ TRANSACTION SCRIPT (Native) ----------------------------------------------------------
    // Call the first foreign account's procedure. It will call into the second FA via FPI.
    let code = format!(
        r#"
        use miden::core::sys
        use miden::protocol::tx

        begin
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw padw push.0.0.0
            # => [pad(15)]

            # get the hash of the `first_account_foreign_proc` procedure
            procref.::first_foreign_account::first_account_foreign_proc

            # push the first foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, pad(15)]

            exec.tx::execute_foreign_procedure
            # => [result_from_second]

            # assert the result returned from the second FA is 3
            dup push.3 assert_eq.err="result from second foreign account should be 3"

            # truncate any remaining stack items
            exec.sys::truncate_stack
        end
        "#,
        foreign_prefix = first_foreign_account.id().prefix().as_felt(),
        foreign_suffix = first_foreign_account.id().suffix(),
    );

    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .with_dynamically_linked_library(first_foreign_account_component.component_code())?
        .compile_tx_script(code)?;

    let executed_transaction = mock_chain
        .build_tx_context(native_account.id(), &[], &[])
        .expect("failed to build tx context")
        .foreign_accounts(foreign_account_inputs)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    // Prove the executed transaction which uses FPI across two foreign accounts.
    LocalTransactionProver::default().prove(executed_transaction)?;

    Ok(())
}

/// Test that code will panic in attempt to create more than 63 foreign accounts.
///
/// Attempt to create a 64th foreign account first triggers the assert during the account data
/// loading, but we have an additional assert during the account stack push just in case.
#[tokio::test]
async fn test_nested_fpi_stack_overflow() -> anyhow::Result<()> {
    let mut foreign_accounts = Vec::new();
    let mock_value_slot0 = AccountStorage::mock_value_slot0();

    let last_foreign_account_code_source = format!(
        r#"
                use miden::protocol::active_account

                const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

                pub proc get_item_foreign
                    # make this foreign procedure unique to make sure that we invoke the procedure
                    # of the foreign account, not the native one
                    push.1 drop

                    # push the index of desired storage item
                    push.MOCK_VALUE_SLOT0[0..2]

                    exec.active_account::get_item

                    # return the first element of the resulting word
                    drop drop drop

                    # make sure that the resulting value equals 1
                    assert.err="expected value to be 1"
                end
        "#,
        mock_value_slot0 = mock_value_slot0.name(),
    );

    let last_foreign_account_code = CodeBuilder::default()
        .compile_component_code("test::last_foreign_account", last_foreign_account_code_source)
        .unwrap();
    let last_foreign_account_component =
        AccountComponent::new(last_foreign_account_code, vec![mock_value_slot0.clone()])
            .unwrap()
            .with_supports_all_types();

    let last_foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(last_foreign_account_component)
        .build_existing()
        .unwrap();

    foreign_accounts.push(last_foreign_account);

    for foreign_account_index in 0..63 {
        let next_account = foreign_accounts.last().unwrap();

        let foreign_account_code_source = format!(
                    "
                use miden::protocol::tx
                use miden::core::sys

                pub proc read_first_foreign_storage_slot_{foreign_account_index}
                    # pad the stack for the `execute_foreign_procedure` execution
                    padw padw padw push.0.0.0
                    # => [pad(15)]

                    # get the hash of the `get_item` account procedure
                    push.{next_account_proc_hash}

                    # push the foreign account ID
                    push.{next_foreign_suffix} push.{next_foreign_prefix}
                    # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, storage_item_index, pad(14)]

                    exec.tx::execute_foreign_procedure
                    # => [storage_value]

                    exec.sys::truncate_stack
                end
            ",
                    next_account_proc_hash = next_account.code().procedures()[1].mast_root(),
                    next_foreign_suffix = next_account.id().suffix(),
                    next_foreign_prefix = next_account.id().prefix().as_felt(),
                );

        let foreign_account_code = CodeBuilder::default()
            .compile_component_code(
                format!("test::foreign_account_chain_{foreign_account_index}"),
                foreign_account_code_source,
            )
            .unwrap();
        let foreign_account_component = AccountComponent::new(foreign_account_code, vec![])
            .unwrap()
            .with_supports_all_types();

        let foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
            .with_auth_component(Auth::IncrNonce)
            .with_component(foreign_account_component)
            .build_existing()
            .unwrap();

        foreign_accounts.push(foreign_account)
    }

    // ------ NATIVE ACCOUNT ---------------------------------------------------------------
    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .storage_mode(AccountStorageMode::Public)
        .build_existing()
        .unwrap();

    let mut mock_chain = MockChainBuilder::with_accounts(
        [vec![native_account.clone()], foreign_accounts.clone()].concat(),
    )
    .unwrap()
    .build()
    .unwrap();

    mock_chain.prove_next_block().unwrap();

    let foreign_accounts: Vec<_> = foreign_accounts
        .iter()
        .map(|acc| {
            mock_chain
                .get_foreign_account_inputs(acc.id())
                .expect("failed to get foreign account inputs")
        })
        .collect();

    let code = format!(
                "
            use miden::core::sys

            use miden::protocol::tx

            begin
                # pad the stack for the `execute_foreign_procedure` execution
                padw padw padw push.0.0.0
                # => [pad(15)]

                # get the hash of the `get_item` account procedure
                push.{foreign_account_proc_hash}

                # push the foreign account ID
                push.{foreign_suffix} push.{foreign_prefix}
                # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, storage_item_index, pad(14)]

                exec.tx::execute_foreign_procedure
                # => [storage_value]

                exec.sys::truncate_stack
            end
            ",
                foreign_account_proc_hash =
                    foreign_accounts.last().unwrap().0.code().procedures()[1].mast_root(),
                foreign_prefix = foreign_accounts.last().unwrap().0.id().prefix().as_felt(),
                foreign_suffix = foreign_accounts.last().unwrap().0.id().suffix(),
            );

    let tx_script = CodeBuilder::default().compile_tx_script(code).unwrap();

    let tx_context = mock_chain
        .build_tx_context(native_account.id(), &[], &[])?
        .foreign_accounts(foreign_accounts)
        .tx_script(tx_script)
        .build()?;

    let result = tx_context.execute().await;

    assert_transaction_executor_error!(result, ERR_FOREIGN_ACCOUNT_MAX_NUMBER_EXCEEDED);
    Ok(())
}

/// Test that code will panic in attempt to call a procedure from the native account.
#[tokio::test]
async fn test_nested_fpi_native_account_invocation() -> anyhow::Result<()> {
    // ------ FIRST FOREIGN ACCOUNT ---------------------------------------------------------------
    let foreign_account_code_source = "
        use miden::protocol::tx

        use miden::core::sys

        pub proc first_account_foreign_proc
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw padw push.0.0.0
            # => [pad(15)]

            # get the hash of the native account procedure from the advice stack
            adv_push.4

            # push the ID of the native account from the advice stack
            adv_push.2
            # => [native_account_id_prefix, native_account_id_suffix, NATIVE_PROC_ROOT, pad(15)]

            exec.tx::execute_foreign_procedure
            # => [storage_value]

            exec.sys::truncate_stack
        end
    ";

    let foreign_account_component = AccountComponent::new(
        CodeBuilder::default()
            .compile_component_code("foreign_account", foreign_account_code_source)?,
        vec![],
    )?
    .with_supports_all_types();

    let foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(foreign_account_component.clone())
        .build_existing()?;

    // ------ NATIVE ACCOUNT ---------------------------------------------------------------
    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block().unwrap();

    let code = format!(
        "
        use miden::core::sys

        use miden::protocol::tx

        begin
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw padw push.0.0.0
            # => [pad(15)]

            # get the hash of the `get_item` account procedure
            push.{first_account_foreign_proc_hash}

            # push the foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, storage_item_index, pad(14)]

            exec.tx::execute_foreign_procedure
            # => [storage_value]

            exec.sys::truncate_stack
        end
        ",
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
        first_account_foreign_proc_hash = foreign_account.code().procedures()[1].mast_root(),
    );

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(foreign_account_component.component_code())?
        .compile_tx_script(code)?;

    let foreign_account_inputs = mock_chain
        .get_foreign_account_inputs(foreign_account.id())
        .expect("failed to get foreign account inputs");

    // push the hash of the native procedure and native account IDs to the advice stack to be able
    // to call them dynamically.
    let mut advice_inputs = AdviceInputs::default();
    advice_inputs.stack.extend(*native_account.code().procedures()[3].mast_root());
    advice_inputs
        .stack
        .extend([native_account.id().suffix(), native_account.id().prefix().as_felt()]);

    let result = mock_chain
        .build_tx_context(native_account.id(), &[], &[])
        .expect("failed to build tx context")
        .foreign_accounts(vec![foreign_account_inputs])
        .extend_advice_inputs(advice_inputs)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FOREIGN_ACCOUNT_CONTEXT_AGAINST_NATIVE_ACCOUNT);
    Ok(())
}

/// Test that providing an account whose commitment does not match the one in the account tree
/// results in an error.
#[tokio::test]
async fn test_fpi_stale_account() -> anyhow::Result<()> {
    // Prepare the test data
    let foreign_account_code_source = "
        use miden::protocol::native_account

        # code is not used in this test
        pub proc set_some_item_foreign
            push.34.1
            exec.native_account::set_item
        end
    ";

    let mock_value_slot0 = AccountStorage::mock_value_slot0();
    let foreign_account_component = AccountComponent::new(
        CodeBuilder::default()
            .compile_component_code("foreign_account_invalid", foreign_account_code_source)?,
        vec![mock_value_slot0.clone()],
    )?
    .with_supports_all_types();

    let mut foreign_account = AccountBuilder::new([5; 32])
        .with_auth_component(Auth::IncrNonce)
        .with_component(foreign_account_component)
        .build_existing()?;

    let native_account = AccountBuilder::new([4; 32])
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(vec![AccountStorage::mock_map_slot()]))
        .build_existing()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    // Make the foreign account invalid.
    // --------------------------------------------------------------------------------------------

    // Modify the account's storage to change its storage commitment and in turn the account
    // commitment.
    foreign_account.storage_mut().set_item(
        mock_value_slot0.name(),
        Word::from([Felt::ONE, Felt::ONE, Felt::ONE, Felt::ONE]),
    )?;

    // We pass the modified foreign account with a witness that is valid against the ref block. This
    // means the foreign account's commitment does not match the commitment that the account witness
    // proves inclusion for.
    let (_foreign_account, foreign_account_witness) = mock_chain
        .get_foreign_account_inputs(foreign_account.id())
        .expect("failed to get foreign account inputs");

    // The account tree from which the transaction inputs are fetched here has the state from the
    // original unmodified foreign account. This should result in the foreign account's proof to be
    // invalid for this account tree root.
    let tx_context = mock_chain
        .build_tx_context(native_account, &[], &[])?
        .foreign_accounts(vec![(foreign_account.clone(), foreign_account_witness)])
        .build()?;

    // Attempt to run FPI.
    // --------------------------------------------------------------------------------------------

    let code = format!(
        "
      use miden::core::sys

      use $kernel::prologue
      use miden::protocol::tx

      begin
          exec.prologue::prepare_transaction

          # pad the stack for the `execute_foreign_procedure` execution
          padw padw padw padw
          # => [pad(16)]

          # push some hash onto the stack - for this test it does not matter
          push.[1,2,3,4]
          # => [FOREIGN_PROC_ROOT, pad(16)]

          # push the foreign account ID
          push.{foreign_suffix} push.{foreign_prefix}
          # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, pad(16)]

          exec.tx::execute_foreign_procedure
        end
      ",
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
    );

    let result = tx_context.execute_code(&code).await.map(|_| ());
    assert_execution_error!(result, ERR_FOREIGN_ACCOUNT_INVALID_COMMITMENT);

    Ok(())
}

/// This test checks that our `miden::get_id` and `miden::get_native_id` procedures return IDs of
/// the current and native account respectively while being called from the foreign account.
#[tokio::test]
async fn test_fpi_get_account_id() -> anyhow::Result<()> {
    let foreign_account_code_source = "
        use miden::protocol::active_account
        use miden::protocol::native_account

        pub proc get_current_and_native_ids
            # get the ID of the current (foreign) account
            exec.active_account::get_id
            # => [acct_id_prefix, acct_id_suffix, pad(16)]

            # get the ID of the native account
            exec.native_account::get_id
            # => [native_acct_id_prefix, native_acct_id_suffix, acct_id_prefix, acct_id_suffix, pad(16)]

            # truncate the stack
            swapw dropw
            # => [native_acct_id_prefix, native_acct_id_suffix, acct_id_prefix, acct_id_suffix, pad(12)]
        end
    ";

    let foreign_account_component = AccountComponent::new(
        CodeBuilder::default()
            .compile_component_code("foreign_account", foreign_account_code_source)?,
        Vec::new(),
    )?
    .with_supports_all_types();

    let foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(foreign_account_component.clone())
        .build_existing()?;

    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    let code = format!(
        r#"
        use miden::core::sys

        use miden::protocol::tx
        use miden::protocol::account_id

        begin
            # get the IDs of the foreign and native accounts
            # pad the stack for the `execute_foreign_procedure` execution
            padw padw padw push.0.0.0
            # => [pad(15)]

            # get the hash of the `get_current_and_native_ids` foreign account procedure
            procref.::foreign_account::get_current_and_native_ids

            # push the foreign account ID
            push.{foreign_suffix} push.{foreign_prefix}
            # => [foreign_account_id_prefix, foreign_account_id_suffix, FOREIGN_PROC_ROOT, pad(15)]

            exec.tx::execute_foreign_procedure
            # => [native_acct_id_prefix, native_acct_id_suffix, acct_id_prefix, acct_id_suffix]

            # push the expected native account ID and check that it is equal to the one returned
            # from the FPI
            push.{expected_native_suffix} push.{expected_native_prefix}
            exec.account_id::is_equal
            assert.err="native account ID returned from the FPI is not equal to the expected one"
            # => [acct_id_prefix, acct_id_suffix]

            # push the expected foreign account ID and check that it is equal to the one returned
            # from the FPI
            push.{foreign_suffix} push.{foreign_prefix}
            exec.account_id::is_equal
            assert.err="foreign account ID returned from the FPI is not equal to the expected one"
            # => []

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#,
        foreign_suffix = foreign_account.id().suffix(),
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        expected_native_suffix = native_account.id().suffix(),
        expected_native_prefix = native_account.id().prefix().as_felt(),
    );

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(foreign_account_component.component_code())?
        .compile_tx_script(code)?;

    let foreign_account_inputs = mock_chain
        .get_foreign_account_inputs(foreign_account.id())
        .expect("failed to get foreign account inputs");

    mock_chain
        .build_tx_context(native_account.id(), &[], &[])
        .expect("failed to build tx context")
        .foreign_accounts(vec![foreign_account_inputs])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

// HELPER FUNCTIONS
// ================================================================================================

fn foreign_account_data_memory_assertions(
    foreign_account: &Account,
    exec_output: &ExecutionOutput,
) {
    let foreign_account_data_ptr = NATIVE_ACCOUNT_DATA_PTR + ACCOUNT_DATA_LENGTH as u32;

    assert_eq!(
        exec_output.get_kernel_mem_word(foreign_account_data_ptr + ACCT_ID_AND_NONCE_OFFSET),
        Word::new([
            foreign_account.id().suffix(),
            foreign_account.id().prefix().as_felt(),
            ZERO,
            foreign_account.nonce()
        ]),
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(foreign_account_data_ptr + ACCT_VAULT_ROOT_OFFSET),
        foreign_account.vault().root(),
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(foreign_account_data_ptr + ACCT_STORAGE_COMMITMENT_OFFSET),
        foreign_account.storage().to_commitment(),
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(foreign_account_data_ptr + ACCT_CODE_COMMITMENT_OFFSET),
        foreign_account.code().commitment(),
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(foreign_account_data_ptr + ACCT_NUM_STORAGE_SLOTS_OFFSET),
        Word::from([u16::try_from(foreign_account.storage().slots().len()).unwrap(), 0, 0, 0]),
    );

    for (i, elements) in foreign_account
        .storage()
        .to_elements()
        .chunks(StorageSlot::NUM_ELEMENTS / 2)
        .enumerate()
    {
        assert_eq!(
            exec_output.get_kernel_mem_word(
                foreign_account_data_ptr
                    + ACCT_ACTIVE_STORAGE_SLOTS_SECTION_OFFSET
                    + (i as u32) * 4
            ),
            Word::try_from(elements).unwrap(),
        )
    }

    assert_eq!(
        exec_output.get_kernel_mem_word(foreign_account_data_ptr + ACCT_NUM_PROCEDURES_OFFSET),
        Word::from([u16::try_from(foreign_account.code().num_procedures()).unwrap(), 0, 0, 0]),
    );

    for (i, elements) in foreign_account
        .code()
        .as_elements()
        .chunks(AccountProcedureRoot::NUM_ELEMENTS)
        .enumerate()
    {
        assert_eq!(
            exec_output.get_kernel_mem_word(
                foreign_account_data_ptr + ACCT_PROCEDURES_SECTION_OFFSET + (i as u32) * 4
            ),
            Word::try_from(elements).unwrap(),
        );
    }
}

/// Test that get_initial_item and get_initial_map_item work correctly with foreign accounts.
#[tokio::test]
async fn test_get_initial_item_and_get_initial_map_item_with_foreign_account() -> anyhow::Result<()>
{
    // Create a native account
    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    let mock_value_slot0 = AccountStorage::mock_value_slot0();
    let mock_map_slot = AccountStorage::mock_map_slot();
    let (map_key, map_value) = STORAGE_LEAVES_2[0];

    // Create foreign procedures that test get_initial_item and get_initial_map_item
    let foreign_account_code_source = format!(
        r#"
        use miden::protocol::active_account
        use miden::core::sys

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        pub proc test_get_initial_item
            push.MOCK_VALUE_SLOT0[0..2]
            exec.active_account::get_initial_item
            exec.sys::truncate_stack
        end

        pub proc test_get_initial_map_item
            exec.active_account::get_initial_map_item
            exec.sys::truncate_stack
        end
    "#,
        mock_value_slot0 = mock_value_slot0.name()
    );

    let foreign_account_component = AccountComponent::new(
        CodeBuilder::default()
            .compile_component_code("foreign_account", foreign_account_code_source)?,
        vec![mock_value_slot0.clone(), mock_map_slot.clone()],
    )?
    .with_supports_all_types();

    let foreign_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(foreign_account_component.clone())
        .build_existing()?;

    // Create the mock chain with both accounts
    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(foreign_account.id())?;

    let code = format!(
        r#"
        use miden::core::sys
        use miden::protocol::tx

        const MOCK_MAP_SLOT = word("{mock_map_slot}")

        begin
            # Test get_initial_item on foreign account
            padw padw padw push.0.0.0
            # => [pad(15)]
            procref.::foreign_account::test_get_initial_item
            push.{foreign_account_id_suffix} push.{foreign_account_id_prefix}
            exec.tx::execute_foreign_procedure
            push.{expected_value_slot_0}
            assert_eqw.err="foreign account get_initial_item should work"

            # Test get_initial_map_item on foreign account
            padw padw push.0.0
            push.{map_key}
            push.MOCK_MAP_SLOT[0..2]
            procref.::foreign_account::test_get_initial_map_item
            push.{foreign_account_id_suffix} push.{foreign_account_id_prefix}
            exec.tx::execute_foreign_procedure
            push.{map_value}
            assert_eqw.err="foreign account get_initial_map_item should work"

            exec.sys::truncate_stack
        end
        "#,
        mock_map_slot = mock_map_slot.name(),
        foreign_account_id_prefix = foreign_account.id().prefix().as_felt(),
        foreign_account_id_suffix = foreign_account.id().suffix(),
        expected_value_slot_0 = mock_value_slot0.content().value(),
        map_key = &map_key,
        map_value = &map_value,
    );

    let tx_script = CodeBuilder::with_mock_libraries()
        .with_dynamically_linked_library(foreign_account_component.component_code())?
        .compile_tx_script(code)?;

    mock_chain
        .build_tx_context(native_account.id(), &[], &[])?
        .foreign_accounts(vec![foreign_account_inputs])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}
