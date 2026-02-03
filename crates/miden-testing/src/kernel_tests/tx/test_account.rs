use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::BTreeMap;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_processor::{ExecutionError, Word};
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountCode,
    AccountComponent,
    AccountId,
    AccountStorage,
    AccountStorageMode,
    AccountType,
    StorageMap,
    StorageSlot,
    StorageSlotContent,
    StorageSlotDelta,
    StorageSlotId,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::assembly::diagnostics::NamedSource;
use miden_protocol::assembly::diagnostics::reporting::PrintDiagnostic;
use miden_protocol::assembly::{DefaultSourceManager, Library};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::errors::tx_kernel::{
    ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO,
    ERR_ACCOUNT_ID_SUFFIX_MOST_SIGNIFICANT_BIT_MUST_BE_ZERO,
    ERR_ACCOUNT_ID_UNKNOWN_STORAGE_MODE,
    ERR_ACCOUNT_ID_UNKNOWN_VERSION,
    ERR_ACCOUNT_NONCE_AT_MAX,
    ERR_ACCOUNT_NONCE_CAN_ONLY_BE_INCREMENTED_ONCE,
    ERR_ACCOUNT_UNKNOWN_STORAGE_SLOT_NAME,
};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::testing::storage::{MOCK_MAP_SLOT, MOCK_VALUE_SLOT0, MOCK_VALUE_SLOT1};
use miden_protocol::transaction::{OutputNote, TransactionKernel};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{LexicographicWord, StarkField};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_tx::LocalTransactionProver;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use winter_rand_utils::rand_value;

use super::{Felt, StackInputs, ZERO};
use crate::executor::CodeExecutor;
use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::utils::create_public_p2any_note;
use crate::{
    Auth,
    ExecError,
    MockChain,
    TransactionContextBuilder,
    TxContextInput,
    assert_transaction_executor_error,
};

// ACCOUNT COMMITMENT TESTS
// ================================================================================================

#[tokio::test]
pub async fn compute_commitment() -> anyhow::Result<()> {
    let account = Account::mock(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);

    // Precompute a commitment to a changed account so we can assert it during tx script execution.
    let mut account_clone = account.clone();
    let key = Word::from([1, 2, 3, 4u32]);
    let value = Word::from([2, 3, 4, 5u32]);
    let mock_map_slot = &*MOCK_MAP_SLOT;
    account_clone.storage_mut().set_map_item(mock_map_slot, key, value).unwrap();
    let expected_commitment = account_clone.commitment();

    let tx_script = format!(
        r#"
        use miden::core::word

        use miden::protocol::active_account
        use mock::account->mock_account

        const MOCK_MAP_SLOT = word("{mock_map_slot}")

        begin
            exec.active_account::get_initial_commitment
            # => [INITIAL_COMMITMENT]

            exec.active_account::compute_commitment
            # => [CURRENT_COMMITMENT, INITIAL_COMMITMENT]

            assert_eqw.err="initial and current commitment should be equal when no changes have been made"
            # => []

            call.mock_account::compute_storage_commitment
            # => [STORAGE_COMMITMENT0, pad(12)]
            swapdw dropw dropw swapw dropw
            # => [STORAGE_COMMITMENT0]

            # update a value in the storage map
            padw push.0.0.0
            push.{value}
            push.{key}
            push.MOCK_MAP_SLOT[0..2]
            # => [slot_id_prefix, slot_id_suffix, KEY, VALUE, pad(7)]
            call.mock_account::set_map_item
            dropw dropw dropw dropw
            # => [STORAGE_COMMITMENT0]

            # compute the commitment which will recompute the storage commitment
            exec.active_account::compute_commitment
            # => [CURRENT_COMMITMENT, STORAGE_COMMITMENT0]

            push.{expected_commitment}
            assert_eqw.err="current commitment should match expected one"
            # => [STORAGE_COMMITMENT0]

            padw padw padw padw
            call.mock_account::compute_storage_commitment
            # => [STORAGE_COMMITMENT1, pad(12), STORAGE_COMMITMENT0]
            swapdw dropw dropw swapw dropw
            # => [STORAGE_COMMITMENT1, STORAGE_COMMITMENT0]

            # assert that the commitment has changed
            exec.word::eq
            assertz.err="storage commitment should have been updated by compute_commitment"
            # => []
        end
    "#,
        key = &key,
        value = &value,
        expected_commitment = &expected_commitment,
    );

    let tx_context_builder = TransactionContextBuilder::new(account);
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script)?;
    let tx_context = tx_context_builder.tx_script(tx_script).build()?;

    tx_context
        .execute()
        .await
        .map_err(|err| anyhow::anyhow!("failed to execute transaction: {err}"))?;

    Ok(())
}

// ACCOUNT ID TESTS
// ================================================================================================

#[tokio::test]
async fn test_account_type() -> anyhow::Result<()> {
    let procedures = vec![
        ("is_fungible_faucet", AccountType::FungibleFaucet),
        ("is_non_fungible_faucet", AccountType::NonFungibleFaucet),
        ("is_updatable_account", AccountType::RegularAccountUpdatableCode),
        ("is_immutable_account", AccountType::RegularAccountImmutableCode),
    ];

    let test_cases = [
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
    ];

    for (procedure, expected_type) in procedures {
        let mut has_type = false;

        for account_id in test_cases.iter() {
            let account_id = AccountId::try_from(*account_id).unwrap();

            let code = format!(
                "
                use $kernel::account_id

                begin
                    exec.account_id::{procedure}
                end
                "
            );

            let exec_output = CodeExecutor::with_default_host()
                .stack_inputs(StackInputs::new(vec![account_id.prefix().as_felt()])?)
                .run(&code)
                .await?;

            let type_matches = account_id.account_type() == expected_type;
            let expected_result = Felt::from(type_matches);
            has_type |= type_matches;

            assert_eq!(
                exec_output.get_stack_element(0),
                expected_result,
                "Rust and Masm check on account type diverge. proc: {} account_id: {} account_type: {:?} expected_type: {:?}",
                procedure,
                account_id,
                account_id.account_type(),
                expected_type,
            );
        }

        assert!(has_type, "missing test for type {expected_type:?}");
    }

    Ok(())
}

#[tokio::test]
async fn test_account_validate_id() -> anyhow::Result<()> {
    let test_cases = [
        (ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE, None),
        (ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE, None),
        (ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, None),
        (ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET, None),
        (
            // Set version to a non-zero value (10).
            ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE | (0x0a << 64),
            Some(ERR_ACCOUNT_ID_UNKNOWN_VERSION),
        ),
        (
            // Set most significant bit to `1`.
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET | (0x80 << 56),
            Some(ERR_ACCOUNT_ID_SUFFIX_MOST_SIGNIFICANT_BIT_MUST_BE_ZERO),
        ),
        (
            // Set storage mode to an unknown value (0b11).
            ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE | (0b11 << (64 + 6)),
            Some(ERR_ACCOUNT_ID_UNKNOWN_STORAGE_MODE),
        ),
        (
            // Set lower 8 bits to a non-zero value (1).
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET | 1,
            Some(ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO),
        ),
    ];

    for (account_id, expected_error) in test_cases.iter() {
        // Manually split the account ID into prefix and suffix since we can't use AccountId methods
        // on invalid ids.
        let prefix = Felt::try_from((account_id / (1u128 << 64)) as u64).unwrap();
        let suffix = Felt::try_from((account_id % (1u128 << 64)) as u64).unwrap();

        let code = "
            use $kernel::account_id

            begin
                exec.account_id::validate
            end
            ";

        let result = CodeExecutor::with_default_host()
            .stack_inputs(StackInputs::new(vec![suffix, prefix]).unwrap())
            .run(code)
            .await;

        match (result.map_err(ExecError::into_execution_error), expected_error) {
            (Ok(_), None) => (),
            (Ok(_), Some(err)) => {
                anyhow::bail!("expected error {err} but validation was successful")
            },
            (Err(ExecutionError::FailedAssertion { err_code, err_msg, .. }), Some(err)) => {
                if err_code != err.code() {
                    anyhow::bail!(
                        "actual error \"{}\" (code: {err_code}) did not match expected error {err}",
                        err_msg.as_ref().map(AsRef::as_ref).unwrap_or("<no message>")
                    );
                }
            },
            (Err(err), None) => {
                return Err(anyhow::anyhow!(
                    "validation is supposed to succeed but error occurred: {}",
                    PrintDiagnostic::new(&err)
                ));
            },
            (Err(err), Some(_)) => {
                return Err(anyhow::anyhow!(
                    "unexpected different error than expected: {}",
                    PrintDiagnostic::new(&err)
                ));
            },
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_is_faucet_procedure() -> anyhow::Result<()> {
    let test_cases = [
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
    ];

    for account_id in test_cases.iter() {
        let account_id = AccountId::try_from(*account_id).unwrap();

        let code = format!(
            "
            use $kernel::account_id

            begin
                push.{prefix}
                exec.account_id::is_faucet
                # => [is_faucet, account_id_prefix]

                # truncate the stack
                swap drop
            end
            ",
            prefix = account_id.prefix().as_felt(),
        );

        let exec_output = CodeExecutor::with_default_host().run(&code).await?;

        let is_faucet = account_id.is_faucet();
        assert_eq!(
            exec_output.get_stack_element(0),
            Felt::new(is_faucet as u64),
            "Rust and MASM is_faucet diverged for account_id {account_id}"
        );
    }

    Ok(())
}

// ACCOUNT CODE TESTS
// ================================================================================================

// TODO: update this test once the ability to change the account code will be implemented
#[tokio::test]
pub async fn test_compute_code_commitment() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build().unwrap();
    let account = tx_context.account();

    let code = format!(
        r#"
        use $kernel::prologue
        use mock::account->mock_account

        begin
            exec.prologue::prepare_transaction
            # get the code commitment
            call.mock_account::get_code_commitment
            push.{expected_code_commitment}
            assert_eqw.err="actual code commitment is not equal to the expected one"
        end
        "#,
        expected_code_commitment = account.code().commitment()
    );

    tx_context.execute_code(&code).await?;

    Ok(())
}

// ACCOUNT STORAGE TESTS
// ================================================================================================

#[tokio::test]
async fn test_get_item() -> anyhow::Result<()> {
    for storage_item in [AccountStorage::mock_value_slot0(), AccountStorage::mock_value_slot1()] {
        let tx_context = TransactionContextBuilder::with_existing_mock_account().build().unwrap();

        let code = format!(
            r#"
            use $kernel::account
            use $kernel::prologue

            const SLOT_NAME = word("{slot_name}")

            begin
                exec.prologue::prepare_transaction

                # push the account storage item index
                push.SLOT_NAME[0..2]
                # => [slot_id_prefix, slot_id_suffix]

                # assert the item value is correct
                exec.account::get_item
                push.{item_value}
                assert_eqw.err="expected item to have value {item_value}"
            end
            "#,
            slot_name = storage_item.name(),
            item_value = &storage_item.content().value(),
        );

        tx_context.execute_code(&code).await.unwrap();
    }

    Ok(())
}

#[tokio::test]
async fn test_get_map_item() -> anyhow::Result<()> {
    let slot = AccountStorage::mock_map_slot();
    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(vec![slot.clone()]))
        .build_existing()
        .unwrap();

    let tx_context = TransactionContextBuilder::new(account).build().unwrap();

    let StorageSlotContent::Map(map) = slot.content() else {
        panic!("expected map")
    };

    for (key, expected_value) in map.entries() {
        let code = format!(
            r#"
            use $kernel::prologue
            use mock::account

            const SLOT_NAME = word("{slot_name}")

            begin
                exec.prologue::prepare_transaction

                # get the map item
                push.{key}
                push.SLOT_NAME[0..2]
                call.account::get_map_item
                # => [VALUE]

                push.{expected_value}
                assert_eqw.err="value did not match {expected_value}"

                exec.::miden::core::sys::truncate_stack
            end
            "#,
            slot_name = slot.name(),
        );

        tx_context.execute_code(&code).await?;
    }

    Ok(())
}

#[tokio::test]
async fn test_get_storage_slot_type() -> anyhow::Result<()> {
    for slot_name in [
        AccountStorage::mock_value_slot0().name(),
        AccountStorage::mock_value_slot1().name(),
        AccountStorage::mock_map_slot().name(),
    ] {
        let tx_context = TransactionContextBuilder::with_existing_mock_account().build().unwrap();
        let (slot_idx, slot) = tx_context
            .account()
            .storage()
            .slots()
            .iter()
            .enumerate()
            .find(|(_, slot)| slot.name() == slot_name)
            .unwrap();

        let code = format!(
            "
            use $kernel::account
            use $kernel::prologue

            begin
                exec.prologue::prepare_transaction

                # push the account storage slot index
                push.{slot_idx}

                # get the type of the respective storage slot
                exec.account::get_storage_slot_type

                # truncate the stack
                swap drop
            end
            ",
        );

        let exec_output = &tx_context.execute_code(&code).await.unwrap();

        assert_eq!(
            slot.slot_type(),
            StorageSlotType::try_from(
                u8::try_from(exec_output.get_stack_element(0).as_int()).unwrap()
            )
            .unwrap()
        );
        assert_eq!(exec_output.get_stack_element(1), ZERO, "the rest of the stack is empty");
        assert_eq!(exec_output.get_stack_element(2), ZERO, "the rest of the stack is empty");
        assert_eq!(exec_output.get_stack_element(3), ZERO, "the rest of the stack is empty");
        assert_eq!(
            exec_output.get_stack_word_be(4),
            Word::empty(),
            "the rest of the stack is empty"
        );
        assert_eq!(
            exec_output.get_stack_word_be(8),
            Word::empty(),
            "the rest of the stack is empty"
        );
        assert_eq!(
            exec_output.get_stack_word_be(12),
            Word::empty(),
            "the rest of the stack is empty"
        );
    }

    Ok(())
}

/// Tests that accessing an unknown slot fails with the expected error message.
///
/// This tests both accounts with empty storage and non-empty storage.
#[tokio::test]
async fn test_account_get_item_fails_on_unknown_slot() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let account_empty_storage = builder.add_existing_mock_account(Auth::IncrNonce)?;
    assert_eq!(account_empty_storage.storage().num_slots(), 0);

    let account_non_empty_storage = builder.add_existing_mock_account(Auth::BasicAuth)?;
    assert_eq!(account_non_empty_storage.storage().num_slots(), 1);

    let chain = builder.build()?;

    let code = r#"
            use mock::account

            const UNKNOWN_SLOT_NAME = word("unknown::slot::name")

            begin
                push.UNKNOWN_SLOT_NAME[0..2]
                call.account::get_item
            end
            "#;
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(code)?;

    let result = chain
        .build_tx_context(account_empty_storage, &[], &[])?
        .tx_script(tx_script.clone())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_UNKNOWN_STORAGE_SLOT_NAME);

    let result = chain
        .build_tx_context(account_non_empty_storage, &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_UNKNOWN_STORAGE_SLOT_NAME);

    Ok(())
}

#[tokio::test]
async fn test_is_slot_id_lt() -> anyhow::Result<()> {
    // Note that the slot IDs derived from the names are essentially randomly sorted, so these cover
    // "less than" and "greater than" outcomes.
    let mut test_cases = (0..100)
        .map(|i| {
            let prev_slot = StorageSlotName::mock(i).id();
            let curr_slot = StorageSlotName::mock(i + 1).id();
            (prev_slot, curr_slot)
        })
        .collect::<Vec<_>>();

    // Extend with special case where prefix matches and suffix determines the outcome.
    let prefix = Felt::from(100u32);
    test_cases.extend([
        // prev_slot == curr_slot
        (
            StorageSlotId::new(Felt::from(50u32), prefix),
            StorageSlotId::new(Felt::from(50u32), prefix),
        ),
        // prev_slot < curr_slot
        (
            StorageSlotId::new(Felt::from(50u32), prefix),
            StorageSlotId::new(Felt::from(51u32), prefix),
        ),
        // prev_slot > curr_slot
        (
            StorageSlotId::new(Felt::from(51u32), prefix),
            StorageSlotId::new(Felt::from(50u32), prefix),
        ),
    ]);

    for (prev_slot, curr_slot) in test_cases {
        let code = format!(
            r#"
            use $kernel::account

            begin
                push.{curr_suffix}.{curr_prefix}.{prev_suffix}.{prev_prefix}
                # => [prev_slot_id_prefix, prev_slot_id_suffix, curr_slot_id_prefix, curr_slot_id_suffix]

                exec.account::is_slot_id_lt
                # => [is_slot_id_lt]

                push.{is_lt}
                assert_eq.err="is_slot_id_lt was not {is_lt}"
                # => []
            end
            "#,
            prev_prefix = prev_slot.prefix(),
            prev_suffix = prev_slot.suffix(),
            curr_prefix = curr_slot.prefix(),
            curr_suffix = curr_slot.suffix(),
            is_lt = u8::from(prev_slot < curr_slot)
        );

        CodeExecutor::with_default_host().run(&code).await?;
    }

    Ok(())
}

#[tokio::test]
async fn test_set_item() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build().unwrap();

    let slot_name = &*MOCK_VALUE_SLOT0;
    let new_value = Word::from([91, 92, 93, 94u32]);
    let old_value = tx_context.account().storage().get_item(slot_name)?;

    let code = format!(
        r#"
        use $kernel::account
        use $kernel::prologue

        const MOCK_VALUE_SLOT0 = word("{slot_name}")

        begin
            exec.prologue::prepare_transaction

            # set the storage item
            push.{new_value}
            push.MOCK_VALUE_SLOT0[0..2]
            # => [slot_id_prefix, slot_id_suffix, NEW_VALUE]

            exec.account::set_item

            # assert old value was correctly returned
            push.{old_value}
            assert_eqw.err="old value did not match"

            # assert new value has been correctly set
            push.MOCK_VALUE_SLOT0[0..2]
            # => [slot_id_prefix, slot_id_suffix]

            exec.account::get_item
            push.{new_value}
            assert_eqw.err="new value did not match"
        end
        "#,
    );

    tx_context.execute_code(&code).await?;

    Ok(())
}

#[tokio::test]
async fn test_set_map_item() -> anyhow::Result<()> {
    let (new_key, new_value) =
        (Word::from([109, 110, 111, 112u32]), Word::from([9, 10, 11, 12u32]));

    let slot = AccountStorage::mock_map_slot();
    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(vec![slot.clone()]))
        .build_existing()
        .unwrap();

    let tx_context = TransactionContextBuilder::new(account).build().unwrap();

    let code = format!(
        r#"
        use miden::core::sys

        use $kernel::prologue
        use mock::account->mock_account

        const SLOT_NAME=word("{slot_name}")

        begin
            exec.prologue::prepare_transaction

            # set the map item
            push.{new_value}
            push.{new_key}
            push.SLOT_NAME[0..2]
            call.mock_account::set_map_item

            # double check that the storage slot is indeed the new map
            push.SLOT_NAME[0..2]
            # => [slot_id_prefix, slot_id_suffix, OLD_VALUE]

            # pad the stack
            repeat.14 push.0 movdn.2 end
            # => [slot_id_prefix, slot_id_suffix, pad(14), OLD_VALUE]

            call.mock_account::get_item
            # => [MAP_ROOT, pad(12), OLD_VALUE]

            # truncate the stack
            repeat.3 swapw dropw end
            # => [MAP_ROOT, OLD_VALUE]

            exec.sys::truncate_stack
        end
        "#,
        slot_name = slot.name(),
        new_key = &new_key,
        new_value = &new_value,
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    let mut new_storage_map = AccountStorage::mock_map();
    new_storage_map.insert(new_key, new_value).unwrap();

    assert_eq!(
        new_storage_map.root(),
        exec_output.get_stack_word_be(0),
        "get_item should return the updated root",
    );

    let old_value_for_key = match slot.content() {
        StorageSlotContent::Map(original_map) => original_map.get(&new_key),
        _ => panic!("expected map"),
    };
    assert_eq!(
        old_value_for_key,
        exec_output.get_stack_word_be(4),
        "set_map_item must return the old value for the key (empty word for new key)",
    );

    Ok(())
}

/// Tests that we can successfully create regular and faucet accounts with empty storage.
#[tokio::test]
async fn create_account_with_empty_storage_slots() -> anyhow::Result<()> {
    for account_type in [AccountType::FungibleFaucet, AccountType::RegularAccountUpdatableCode] {
        let account = AccountBuilder::new([5; 32])
            .account_type(account_type)
            .with_auth_component(Auth::IncrNonce)
            .with_component(MockAccountComponent::with_empty_slots())
            .build()
            .context("failed to build account")?;

        TransactionContextBuilder::new(account).build()?.execute().await?;
    }

    Ok(())
}

#[tokio::test]
async fn test_get_initial_storage_commitment() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let code = format!(
        r#"
        use miden::protocol::active_account
        use $kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # get the initial storage commitment
            exec.active_account::get_initial_storage_commitment
            push.{expected_storage_commitment}
            assert_eqw.err="actual storage commitment is not equal to the expected one"
        end
        "#,
        expected_storage_commitment = &tx_context.account().storage().to_commitment(),
    );
    tx_context.execute_code(&code).await?;

    Ok(())
}

/// This test creates an account with mock storage slots and calls the
/// `compute_storage_commitment` procedure each time the storage is updated.
///
/// Namely, we invoke the `mock_account::compute_storage_commitment` procedure:
/// - Right after the account creation.
/// - After updating the 0th storage slot (value slot).
/// - Right after the previous call to make sure it returns the same commitment from the cached
///   data.
/// - After updating the 2nd storage slot (map slot).
#[tokio::test]
async fn test_compute_storage_commitment() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build().unwrap();
    let mut account_clone = tx_context.account().clone();
    let account_storage = account_clone.storage_mut();

    let init_storage_commitment = account_storage.to_commitment();

    let mock_value_slot0 = &*MOCK_VALUE_SLOT0;
    let mock_map_slot = &*MOCK_MAP_SLOT;

    account_storage.set_item(mock_value_slot0, [9, 10, 11, 12].map(Felt::new).into())?;
    let storage_commitment_value = account_storage.to_commitment();

    account_storage.set_map_item(
        mock_map_slot,
        [101, 102, 103, 104].map(Felt::new).into(),
        [5, 6, 7, 8].map(Felt::new).into(),
    )?;
    let storage_commitment_map = account_storage.to_commitment();

    let code = format!(
        r#"
        use $kernel::prologue
        use mock::account->mock_account

        const MOCK_VALUE_SLOT0=word("{mock_value_slot0}")
        const MOCK_MAP_SLOT=word("{mock_map_slot}")

        begin
            exec.prologue::prepare_transaction

            # assert the correctness of the initial storage commitment
            call.mock_account::compute_storage_commitment
            push.{init_storage_commitment}
            assert_eqw.err="storage commitment at the beginning of the transaction is not equal to the expected one"

            # update the value storage slot
            push.9.10.11.12
            push.MOCK_VALUE_SLOT0[0..2]
            call.mock_account::set_item dropw drop
            # => []

            # assert the correctness of the storage commitment after the value slot was updated
            call.mock_account::compute_storage_commitment
            push.{storage_commitment_value}
            assert_eqw.err="storage commitment after the value slot was updated is not equal to the expected one"

            # get the storage commitment once more to get the cached data and assert that this data
            # didn't change
            call.mock_account::compute_storage_commitment
            push.{storage_commitment_value}
            assert_eqw.err="storage commitment should remain the same"

            # update the map storage slot
            push.5.6.7.8.101.102.103.104
            push.MOCK_MAP_SLOT[0..2]
            # => [slot_id_prefix, slot_id_suffix, KEY, VALUE]

            call.mock_account::set_map_item dropw dropw
            # => []

            # assert the correctness of the storage commitment after the map slot was updated
            call.mock_account::compute_storage_commitment
            push.{storage_commitment_map}
            assert_eqw.err="storage commitment after the map slot was updated is not equal to the expected one"
        end
        "#,
    );

    tx_context.execute_code(&code).await?;

    Ok(())
}

/// Tests that an account with a non-empty map can be created.
///
/// In particular, this tests the account delta logic for (non-empty) storage slots for _new_
/// accounts.
#[tokio::test]
async fn prove_account_creation_with_non_empty_storage() -> anyhow::Result<()> {
    let slot_name0 = StorageSlotName::mock(0);
    let slot_name1 = StorageSlotName::mock(1);
    let slot_name2 = StorageSlotName::mock(2);

    let slot0 = StorageSlot::with_value(slot_name0.clone(), Word::from([1, 2, 3, 4u32]));
    let slot1 = StorageSlot::with_value(slot_name1.clone(), Word::from([10, 20, 30, 40u32]));
    let mut map_entries = Vec::new();
    for _ in 0..10 {
        map_entries.push((rand_value::<Word>(), rand_value::<Word>()));
    }
    let map_slot =
        StorageSlot::with_map(slot_name2.clone(), StorageMap::with_entries(map_entries.clone())?);

    let account = AccountBuilder::new([6; 32])
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(vec![
            slot0.clone(),
            slot1.clone(),
            map_slot,
        ]))
        .build()?;

    let tx = TransactionContextBuilder::new(account)
        .build()?
        .execute()
        .await
        .context("failed to execute account-creating transaction")?;

    assert_eq!(tx.account_delta().nonce_delta(), Felt::new(1));

    assert_matches!(
        tx.account_delta().storage().get(&slot_name0).unwrap(),
        StorageSlotDelta::Value(value) => {
            assert_eq!(*value, slot0.value())
        }
    );
    assert_matches!(
        tx.account_delta().storage().get(&slot_name1).unwrap(),
        StorageSlotDelta::Value(value) => {
            assert_eq!(*value, slot1.value())
        }
    );
    assert_matches!(
        tx.account_delta().storage().get(&slot_name2).unwrap(),
        StorageSlotDelta::Map(map_delta) => {
            let expected = &BTreeMap::from_iter(
            map_entries
                .into_iter()
                .map(|(key, value)| { (LexicographicWord::new(key), value) })
            );
            assert_eq!(expected, map_delta.entries())
        }
    );

    assert!(tx.account_delta().vault().is_empty());
    assert_eq!(tx.final_account().nonce(), Felt::new(1));

    let proven_tx = LocalTransactionProver::default().prove(tx.clone())?;

    // The delta should be present on the proven tx.
    let AccountUpdateDetails::Delta(delta) = proven_tx.account_update().details() else {
        panic!("expected delta");
    };
    assert_eq!(delta, tx.account_delta());

    Ok(())
}

// ACCOUNT VAULT TESTS
// ================================================================================================

#[tokio::test]
async fn test_get_vault_root() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let mut account = tx_context.account().clone();

    let fungible_asset = Asset::Fungible(
        FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).context("id should be valid")?,
            5,
        )
        .context("fungible_asset_0 is invalid")?,
    );

    // get the initial vault root
    let code = format!(
        r#"
        use miden::protocol::active_account
        use $kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # get the initial vault root
            exec.active_account::get_initial_vault_root
            push.{expected_vault_root}
            assert_eqw.err="initial vault root mismatch"
        end
        "#,
        expected_vault_root = &account.vault().root(),
    );
    tx_context.execute_code(&code).await?;

    // get the current vault root
    account.vault_mut().add_asset(fungible_asset)?;

    let code = format!(
        r#"
        use miden::protocol::active_account
        use $kernel::prologue
        use mock::account->mock_account

        begin
            exec.prologue::prepare_transaction

            # add an asset to the account
            push.{fungible_asset}
            call.mock_account::add_asset dropw
            # => []

            # get the current vault root
            exec.active_account::get_vault_root
            push.{expected_vault_root}
            assert_eqw.err="vault root mismatch"
        end
        "#,
        fungible_asset = Word::from(&fungible_asset),
        expected_vault_root = &account.vault().root(),
    );
    tx_context.execute_code(&code).await?;

    Ok(())
}

/// This test checks the correctness of the `miden::protocol::active_account::get_initial_balance`
/// procedure in two cases:
/// - when a note adds the asset which already exists in the account vault.
/// - when a note adds the asset which doesn't exist in the account vault.
///
/// As part of the test pipeline it also checks the correctness of the
/// `miden::protocol::active_account::get_balance` procedure.
#[tokio::test]
async fn test_get_init_balance_addition() -> anyhow::Result<()> {
    // prepare the testing data
    // ------------------------------------------
    let mut builder = MockChain::builder();

    let faucet_existing_asset =
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).context("id should be valid")?;
    let faucet_new_asset =
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).context("id should be valid")?;

    let fungible_asset_for_account = Asset::Fungible(
        FungibleAsset::new(faucet_existing_asset, 10).context("fungible_asset_0 is invalid")?,
    );
    let account = builder
        .add_existing_wallet_with_assets(crate::Auth::BasicAuth, [fungible_asset_for_account])?;

    let fungible_asset_for_note_existing = Asset::Fungible(
        FungibleAsset::new(faucet_existing_asset, 7).context("fungible_asset_0 is invalid")?,
    );

    let fungible_asset_for_note_new = Asset::Fungible(
        FungibleAsset::new(faucet_new_asset, 20).context("fungible_asset_1 is invalid")?,
    );

    let p2id_note_existing_asset = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[fungible_asset_for_note_existing],
        NoteType::Public,
    )?;
    let p2id_note_new_asset = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[fungible_asset_for_note_new],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // case 1: existing asset was added to the account
    // ------------------------------------------

    let initial_balance = account
        .vault()
        .get_balance(faucet_existing_asset)
        .expect("faucet_id should be a fungible faucet ID");

    let add_existing_source = format!(
        r#"
        use miden::protocol::active_account

        begin
            # push faucet ID prefix and suffix
            push.{suffix}.{prefix}
            # => [faucet_id_prefix, faucet_id_suffix]

            # get the current asset balance
            dup.1 dup.1 exec.active_account::get_balance
            # => [final_balance, faucet_id_prefix, faucet_id_suffix]

            # assert final balance is correct
            push.{final_balance}
            assert_eq.err="final balance is incorrect"
            # => [faucet_id_prefix, faucet_id_suffix]

            # get the initial asset balance
            exec.active_account::get_initial_balance
            # => [init_balance]

            # assert initial balance is correct
            push.{initial_balance}
            assert_eq.err="initial balance is incorrect"
        end
    "#,
        suffix = faucet_existing_asset.suffix(),
        prefix = faucet_existing_asset.prefix().as_felt(),
        final_balance =
            initial_balance + fungible_asset_for_note_existing.unwrap_fungible().amount(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(add_existing_source)?;

    let tx_context = mock_chain
        .build_tx_context(
            TxContextInput::AccountId(account.id()),
            &[],
            &[p2id_note_existing_asset],
        )?
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    // case 2: new asset was added to the account
    // ------------------------------------------

    let initial_balance = account
        .vault()
        .get_balance(faucet_new_asset)
        .expect("faucet_id should be a fungible faucet ID");

    let add_new_source = format!(
        r#"
        use miden::protocol::active_account

        begin
            # push faucet ID prefix and suffix
            push.{suffix}.{prefix}
            # => [faucet_id_prefix, faucet_id_suffix]

            # get the current asset balance
            dup.1 dup.1 exec.active_account::get_balance
            # => [final_balance, faucet_id_prefix, faucet_id_suffix]

            # assert final balance is correct
            push.{final_balance}
            assert_eq.err="final balance is incorrect"
            # => [faucet_id_prefix, faucet_id_suffix]

            # get the initial asset balance
            exec.active_account::get_initial_balance
            # => [init_balance]

            # assert initial balance is correct
            push.{initial_balance}
            assert_eq.err="initial balance is incorrect"
        end
    "#,
        suffix = faucet_new_asset.suffix(),
        prefix = faucet_new_asset.prefix().as_felt(),
        final_balance = initial_balance + fungible_asset_for_note_new.unwrap_fungible().amount(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(add_new_source)?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[p2id_note_new_asset])?
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// This test checks the correctness of the `miden::protocol::active_account::get_initial_balance`
/// procedure in case when we create a note which removes an asset from the account vault.
///  
/// As part of the test pipeline it also checks the correctness of the
/// `miden::protocol::active_account::get_balance` procedure.
#[tokio::test]
async fn test_get_init_balance_subtraction() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let faucet_existing_asset =
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).context("id should be valid")?;

    let fungible_asset_for_account = Asset::Fungible(
        FungibleAsset::new(faucet_existing_asset, 10).context("fungible_asset_0 is invalid")?,
    );
    let account = builder
        .add_existing_wallet_with_assets(crate::Auth::BasicAuth, [fungible_asset_for_account])?;

    let fungible_asset_for_note_existing = Asset::Fungible(
        FungibleAsset::new(faucet_existing_asset, 7).context("fungible_asset_0 is invalid")?,
    );

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let initial_balance = account
        .vault()
        .get_balance(faucet_existing_asset)
        .expect("faucet_id should be a fungible faucet ID");

    let expected_output_note =
        create_public_p2any_note(ACCOUNT_ID_SENDER.try_into()?, [fungible_asset_for_note_existing]);

    let remove_existing_source = format!(
        r#"
        use miden::protocol::active_account
        use miden::standards::wallets::basic->wallet
        use mock::util

        # Inputs:  [ASSET, note_idx]
        # Outputs: [ASSET, note_idx]
        proc move_asset_to_note
            # pad the stack before call
            push.0.0.0 movdn.7 movdn.7 movdn.7 padw padw swapdw
            # => [ASSET, note_idx, pad(11)]

            call.wallet::move_asset_to_note
            # => [ASSET, note_idx, pad(11)]

            # remove excess PADs from the stack
            swapdw dropw dropw swapw movdn.7 drop drop drop
            # => [ASSET, note_idx]
        end

        begin
            # create random note and move the asset into it
            exec.util::create_default_note
            # => [note_idx]

            push.{REMOVED_ASSET}
            exec.move_asset_to_note dropw drop
            # => []

            # push faucet ID prefix and suffix
            push.{suffix}.{prefix}
            # => [faucet_id_prefix, faucet_id_suffix]

            # get the current asset balance
            dup.1 dup.1 exec.active_account::get_balance
            # => [final_balance, faucet_id_prefix, faucet_id_suffix]

            # assert final balance is correct
            push.{final_balance}
            assert_eq.err="final balance is incorrect"
            # => [faucet_id_prefix, faucet_id_suffix]

            # get the initial asset balance
            exec.active_account::get_initial_balance
            # => [init_balance]

            # assert initial balance is correct
            push.{initial_balance}
            assert_eq.err="initial balance is incorrect"
        end
    "#,
        REMOVED_ASSET = Word::from(fungible_asset_for_note_existing),
        suffix = faucet_existing_asset.suffix(),
        prefix = faucet_existing_asset.prefix().as_felt(),
        final_balance =
            initial_balance - fungible_asset_for_note_existing.unwrap_fungible().amount(),
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(remove_existing_source)?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[])?
        .tx_script(tx_script)
        .extend_expected_output_notes(vec![OutputNote::Full(expected_output_note)])
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// This test checks the correctness of the `miden::protocol::active_account::get_initial_asset`
/// procedure creating a note which removes an asset from the account vault.
///
/// As part of the test pipeline it also checks the correctness of the
/// `miden::protocol::active_account::get_asset` procedure.
#[tokio::test]
async fn test_get_init_asset() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let faucet_existing_asset =
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).context("id should be valid")?;

    let fungible_asset_for_account = Asset::Fungible(
        FungibleAsset::new(faucet_existing_asset, 10).context("fungible_asset_0 is invalid")?,
    );
    let account = builder
        .add_existing_wallet_with_assets(crate::Auth::BasicAuth, [fungible_asset_for_account])?;

    let fungible_asset_for_note_existing = Asset::Fungible(
        FungibleAsset::new(faucet_existing_asset, 7).context("fungible_asset_0 is invalid")?,
    );

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let final_asset = fungible_asset_for_account
        .unwrap_fungible()
        .sub(fungible_asset_for_note_existing.unwrap_fungible())?;

    let expected_output_note =
        create_public_p2any_note(ACCOUNT_ID_SENDER.try_into()?, [fungible_asset_for_note_existing]);

    let remove_existing_source = format!(
        r#"
        use miden::protocol::active_account
        use miden::standards::wallets::basic->wallet
        use mock::util

        begin
            # create default note and move the asset into it
            exec.util::create_default_note
            # => [note_idx]

            push.{REMOVED_ASSET}
            call.wallet::move_asset_to_note dropw drop
            # => []

            # get the current asset
            push.{ASSET_KEY} exec.active_account::get_asset
            # => [ASSET]

            push.{FINAL_ASSET}
            assert_eqw.err="final asset is incorrect"
            # => []

            # get the initial asset
            push.{ASSET_KEY} exec.active_account::get_initial_asset
            # => [INITIAL_ASSET]

            push.{INITIAL_ASSET}
            assert_eqw.err="initial asset is incorrect"
        end
    "#,
        ASSET_KEY = fungible_asset_for_note_existing.vault_key(),
        REMOVED_ASSET = Word::from(fungible_asset_for_note_existing),
        INITIAL_ASSET = Word::from(fungible_asset_for_account),
        FINAL_ASSET = Word::from(final_asset),
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(remove_existing_source)?;

    mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[])?
        .tx_script(tx_script)
        .extend_expected_output_notes(vec![OutputNote::Full(expected_output_note)])
        .build()?
        .execute()
        .await?;

    Ok(())
}

// PROCEDURE AUTHENTICATION TESTS
// ================================================================================================

#[tokio::test]
async fn test_authenticate_and_track_procedure() -> anyhow::Result<()> {
    let mock_component = MockAccountComponent::with_empty_slots();

    let account_code = AccountCode::from_components(
        &[Auth::IncrNonce.into(), mock_component.into()],
        AccountType::RegularAccountUpdatableCode,
    )
    .unwrap();

    let tc_0 = *account_code.procedures()[1].mast_root();
    let tc_1 = *account_code.procedures()[2].mast_root();
    let tc_2 = *account_code.procedures()[3].mast_root();

    let test_cases =
        vec![(tc_0, true), (tc_1, true), (tc_2, true), (Word::from([1, 0, 1, 0u32]), false)];

    for (root, valid) in test_cases.into_iter() {
        let tx_context = TransactionContextBuilder::with_existing_mock_account().build().unwrap();

        let code = format!(
            "
            use $kernel::account
            use $kernel::prologue

            begin
                exec.prologue::prepare_transaction

                # authenticate procedure
                push.{root}
                exec.account::authenticate_and_track_procedure

                # truncate the stack
                dropw
            end
            ",
            root = &root,
        );

        // Execution of this code will return an EventError(UnknownAccountProcedure) for procs
        // that are not in the advice provider.
        let exec_output = tx_context.execute_code(&code).await;

        match valid {
            true => {
                assert!(exec_output.is_ok(), "A valid procedure must successfully authenticate")
            },
            false => {
                assert!(exec_output.is_err(), "An invalid procedure should fail to authenticate")
            },
        }
    }

    Ok(())
}

// PROCEDURE INTROSPECTION TESTS
// ================================================================================================

#[tokio::test]
async fn test_was_procedure_called() -> anyhow::Result<()> {
    // Create a standard account using the mock component
    let mock_component = MockAccountComponent::with_slots(AccountStorage::mock_storage_slots());
    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(mock_component)
        .build_existing()
        .unwrap();
    let mock_value_slot1 = &*MOCK_VALUE_SLOT1;

    // Create a transaction script that:
    // 1. Checks that get_item hasn't been called yet
    // 2. Calls get_item from the mock account
    // 3. Checks that get_item has been called
    // 4. Calls get_item **again**
    // 5. Checks that `was_procedure_called` returns `true`
    let tx_script_code = format!(
        r#"
        use mock::account->mock_account
        use miden::protocol::native_account

        const MOCK_VALUE_SLOT1 = word("{mock_value_slot1}")

        begin
            # First check that get_item procedure hasn't been called yet
            procref.mock_account::get_item
            exec.native_account::was_procedure_called
            assertz.err="procedure should not have been called"

            # Call the procedure first time
            push.MOCK_VALUE_SLOT1[0..2]
            call.mock_account::get_item dropw
            # => []

            procref.mock_account::get_item
            exec.native_account::was_procedure_called
            assert.err="procedure should have been called"

            # Call the procedure second time
            push.MOCK_VALUE_SLOT1[0..2]
            call.mock_account::get_item dropw

            procref.mock_account::get_item
            exec.native_account::was_procedure_called
            assert.err="2nd call should not change the was_called flag"
        end
        "#
    );

    // Compile the transaction script using the testing assembler with mock account
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_code)?;

    // Create transaction context and execute
    let tx_context = TransactionContextBuilder::new(account).tx_script(tx_script).build().unwrap();

    tx_context
        .execute()
        .await
        .map_err(|err| anyhow::anyhow!("Failed to execute transaction: {err}"))?;

    Ok(())
}

/// Tests that an account can call code in a custom library when loading that library into the
/// executor.
///
/// The call chain and dependency graph in this test is:
/// `tx script -> account code -> external library`
#[tokio::test]
async fn transaction_executor_account_code_using_custom_library() -> anyhow::Result<()> {
    let external_library_code = format!(
        r#"
      use miden::protocol::native_account

      const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

      pub proc external_setter
        push.2.3.4.5
        push.MOCK_VALUE_SLOT0[0..2]
        exec.native_account::set_item
        dropw dropw
      end"#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
    );

    const ACCOUNT_COMPONENT_CODE: &str = "
      use external_library::external_module

      pub proc custom_setter
        exec.external_module::external_setter
      end";

    let external_library_source =
        NamedSource::new("external_library::external_module", external_library_code);
    let external_library = TransactionKernel::assembler()
        .assemble_library([external_library_source])
        .map_err(|err| {
            anyhow::anyhow!("failed to assemble library: {}", PrintDiagnostic::new(&err))
        })?;

    let mut assembler: miden_protocol::assembly::Assembler =
        CodeBuilder::with_mock_libraries_with_source_manager(Arc::new(
            DefaultSourceManager::default(),
        ))
        .into();
    assembler.link_static_library(&external_library).map_err(|err| {
        anyhow::anyhow!("failed to link static library: {}", PrintDiagnostic::new(&err))
    })?;

    let account_component_source =
        NamedSource::new("account_component::account_module", ACCOUNT_COMPONENT_CODE);
    let account_component_lib =
        assembler.clone().assemble_library([account_component_source]).unwrap();

    let tx_script_src = "\
          use account_component::account_module

          begin
            call.account_module::custom_setter
          end";

    let account_component =
        AccountComponent::new(account_component_lib.clone(), AccountStorage::mock_storage_slots())?
            .with_supports_all_types();

    // Build an existing account with nonce 1.
    let native_account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(account_component)
        .build_existing()?;

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(&account_component_lib)?
        .compile_tx_script(tx_script_src)?;

    let tx_context = TransactionContextBuilder::new(native_account.clone())
        .tx_script(tx_script)
        .build()
        .unwrap();

    let executed_tx = tx_context.execute().await?;

    // Account's initial nonce of 1 should have been incremented by 1.
    assert_eq!(executed_tx.account_delta().nonce_delta(), Felt::new(1));

    // Make sure that account storage has been updated as per the tx script call.
    assert_eq!(executed_tx.account_delta().storage().values().count(), 1);
    assert_eq!(
        executed_tx.account_delta().storage().get(&MOCK_VALUE_SLOT0).unwrap(),
        &StorageSlotDelta::Value(Word::from([2, 3, 4, 5u32])),
    );
    Ok(())
}

/// Tests that incrementing the account nonce twice fails.
#[tokio::test]
async fn incrementing_nonce_twice_fails() -> anyhow::Result<()> {
    let source_code = "
        use miden::protocol::native_account

        pub proc auth_incr_nonce_twice
            exec.native_account::incr_nonce drop
            exec.native_account::incr_nonce drop
        end
    ";

    let faulty_auth_code =
        CodeBuilder::default().compile_component_code("test::faulty_auth", source_code)?;
    let faulty_auth_component =
        AccountComponent::new(faulty_auth_code, vec![])?.with_supports_all_types();
    let account = AccountBuilder::new([5; 32])
        .with_auth_component(faulty_auth_component)
        .with_component(MockAccountComponent::with_empty_slots())
        .build()
        .context("failed to build account")?;

    let result = TransactionContextBuilder::new(account).build()?.execute().await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_NONCE_CAN_ONLY_BE_INCREMENTED_ONCE);

    Ok(())
}

#[tokio::test]
async fn test_has_procedure() -> anyhow::Result<()> {
    // Create a standard account using the mock component
    let mock_component = MockAccountComponent::with_slots(AccountStorage::mock_storage_slots());
    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(mock_component)
        .build_existing()
        .unwrap();

    let tx_script_code = r#"
        use mock::account->mock_account
        use miden::protocol::active_account

        begin
            # check that get_item procedure is available on the mock account
            procref.mock_account::get_item
            # => [GET_ITEM_ROOT]

            exec.active_account::has_procedure
            # => [is_procedure_available]

            # assert that the get_item is exposed
            assert.err="get_item procedure should be exposed by the mock account"

            # get some random word and assert that it is not exposed
            push.5.3.15.686

            exec.active_account::has_procedure
            # => [is_procedure_available]

            # assert that the procedure with some random root is not exposed
            assertz.err="procedure with some random root should not be exposed by the mock account"
        end
        "#;

    // Compile the transaction script using the testing assembler with mock account
    let tx_script = CodeBuilder::with_mock_libraries()
        .compile_tx_script(tx_script_code)
        .map_err(|err| anyhow::anyhow!("{err}"))?;

    // Create transaction context and execute
    let tx_context = TransactionContextBuilder::new(account).tx_script(tx_script).build().unwrap();

    tx_context
        .execute()
        .await
        .map_err(|err| anyhow::anyhow!("Failed to execute transaction: {err}"))?;

    Ok(())
}

// ACCOUNT INITIAL STORAGE TESTS
// ================================================================================================

#[tokio::test]
async fn test_get_initial_item() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build().unwrap();

    // Test that get_initial_item returns the initial value before any changes
    let code = format!(
        r#"
        use $kernel::account
        use $kernel::prologue
        use mock::account->mock_account

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        begin
            exec.prologue::prepare_transaction

            # get initial value of the storage slot
            push.MOCK_VALUE_SLOT0[0..2]
            exec.account::get_initial_item

            push.{expected_initial_value}
            assert_eqw.err="initial value should match expected"

            # modify the storage slot
            push.9.10.11.12
            push.MOCK_VALUE_SLOT0[0..2]
            call.mock_account::set_item dropw drop drop

            # get_item should return the new value
            push.MOCK_VALUE_SLOT0[0..2]
            exec.account::get_item
            push.9.10.11.12
            assert_eqw.err="current value should be updated"

            # get_initial_item should still return the initial value
            push.MOCK_VALUE_SLOT0[0..2]
            exec.account::get_initial_item
            push.{expected_initial_value}
            assert_eqw.err="initial value should remain unchanged"
        end
        "#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
        expected_initial_value = &AccountStorage::mock_value_slot0().content().value(),
    );

    tx_context.execute_code(&code).await?;

    Ok(())
}

#[tokio::test]
async fn test_get_initial_map_item() -> anyhow::Result<()> {
    let map_slot = AccountStorage::mock_map_slot();
    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(vec![map_slot.clone()]))
        .build_existing()
        .unwrap();

    let tx_context = TransactionContextBuilder::new(account).build().unwrap();

    // Use the first key-value pair from the mock storage
    let StorageSlotContent::Map(map) = map_slot.content() else {
        panic!("expected map");
    };

    let (initial_key, initial_value) = map.entries().next().unwrap();
    let new_key = Word::from([201, 202, 203, 204u32]);
    let new_value = Word::from([301, 302, 303, 304u32]);
    let mock_map_slot = map_slot.name();

    let code = format!(
        r#"
        use $kernel::prologue
        use mock::account->mock_account

        const MOCK_MAP_SLOT = word("{mock_map_slot}")

        begin
            exec.prologue::prepare_transaction

            # get initial value from map
            push.{initial_key}
            push.MOCK_MAP_SLOT[0..2]
            call.mock_account::get_initial_map_item
            push.{initial_value}
            assert_eqw.err="initial map value should match expected"

            # add a new key-value pair to the map
            push.{new_value}
            push.{new_key}
            push.MOCK_MAP_SLOT[0..2]
            call.mock_account::set_map_item dropw dropw

            # get_map_item should return the new value
            push.{new_key}
            push.MOCK_MAP_SLOT[0..2]
            call.mock_account::get_map_item
            push.{new_value}
            assert_eqw.err="current map value should be updated"

            # get_initial_map_item should still return the initial value for the initial key
            push.{initial_key}
            push.MOCK_MAP_SLOT[0..2]
            call.mock_account::get_initial_map_item
            push.{initial_value}
            assert_eqw.err="initial map value should remain unchanged"

            # get_initial_map_item for the new key should return empty word (default)
            push.{new_key}
            push.MOCK_MAP_SLOT[0..2]
            call.mock_account::get_initial_map_item
            padw
            assert_eqw.err="new key should have empty initial value"

            dropw dropw dropw
        end
        "#,
        initial_key = &initial_key,
        initial_value = &initial_value,
        new_key = &new_key,
        new_value = &new_value,
    );

    tx_context.execute_code(&code).await.unwrap();

    Ok(())
}

/// Tests that incrementing the account nonce fails if it would overflow the field.
#[tokio::test]
async fn incrementing_nonce_overflow_fails() -> anyhow::Result<()> {
    let mut account = AccountBuilder::new([42; 32])
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .build_existing()
        .context("failed to build account")?;
    // Increment the nonce to the maximum felt value. The nonce is already 1, so we increment by
    // modulus - 2.
    account.increment_nonce(Felt::new(Felt::MODULUS - 2))?;

    let result = TransactionContextBuilder::new(account).build()?.execute().await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_NONCE_AT_MAX);

    Ok(())
}

/// Tests that merging two components that have a procedure with the same mast root
/// (`get_slot_content`) works.
///
/// Asserts that the procedure is callable via both names.
#[tokio::test]
async fn merging_components_with_same_mast_root_succeeds() -> anyhow::Result<()> {
    static TEST_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
        StorageSlotName::new("miden::slot::test").expect("storage slot name should be valid")
    });

    static COMPONENT_1_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
        let code = format!(
            r#"
              use miden::protocol::active_account

              const TEST_SLOT_NAME = word("{test_slot_name}")

              pub proc get_slot_content
                  push.TEST_SLOT_NAME[0..2]
                  exec.active_account::get_item
                  swapw dropw
              end
            "#,
            test_slot_name = &*TEST_SLOT_NAME
        );

        let source = NamedSource::new("component1::interface", code);
        TransactionKernel::assembler()
            .assemble_library([source])
            .expect("mock account code should be valid")
    });

    static COMPONENT_2_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
        let code = format!(
            r#"
              use miden::protocol::active_account
              use miden::protocol::native_account

              const TEST_SLOT_NAME = word("{test_slot_name}")

              pub proc get_slot_content
                  push.TEST_SLOT_NAME[0..2]
                  exec.active_account::get_item
                  swapw dropw
              end

              pub proc set_slot_content
                  push.5.6.7.8
                  push.TEST_SLOT_NAME[0..2]
                  exec.native_account::set_item
                  swapw dropw
              end
            "#,
            test_slot_name = &*TEST_SLOT_NAME
        );

        let source = NamedSource::new("component2::interface", code);
        TransactionKernel::assembler()
            .assemble_library([source])
            .expect("mock account code should be valid")
    });

    struct CustomComponent1 {
        slot: StorageSlot,
    }

    impl From<CustomComponent1> for AccountComponent {
        fn from(component: CustomComponent1) -> AccountComponent {
            AccountComponent::new(COMPONENT_1_LIBRARY.clone(), vec![component.slot])
                .expect("should be valid")
                .with_supports_all_types()
        }
    }

    struct CustomComponent2;

    impl From<CustomComponent2> for AccountComponent {
        fn from(_component: CustomComponent2) -> AccountComponent {
            AccountComponent::new(COMPONENT_2_LIBRARY.clone(), vec![])
                .expect("should be valid")
                .with_supports_all_types()
        }
    }

    let slot = StorageSlot::with_value(TEST_SLOT_NAME.clone(), Word::from([1, 2, 3, 4u32]));

    let account = AccountBuilder::new([42; 32])
        .with_auth_component(Auth::IncrNonce)
        .with_component(CustomComponent1 { slot: slot.clone() })
        .with_component(CustomComponent2)
        .build()
        .context("failed to build account")?;

    let tx_script = r#"
      use component1::interface->comp1_interface
      use component2::interface->comp2_interface

      begin
          call.comp1_interface::get_slot_content
          push.1.2.3.4
          assert_eqw.err="failed to get slot content1"

          call.comp2_interface::set_slot_content

          call.comp2_interface::get_slot_content
          push.5.6.7.8
          assert_eqw.err="failed to get slot content2"
      end
    "#;

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(COMPONENT_1_LIBRARY.clone())?
        .with_dynamically_linked_library(COMPONENT_2_LIBRARY.clone())?
        .compile_tx_script(tx_script)?;

    TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}
