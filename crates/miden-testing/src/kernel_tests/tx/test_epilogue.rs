use alloc::string::ToString;
use alloc::vec::Vec;
use std::borrow::ToOwned;

use miden_processor::crypto::RpoRandomCoin;
use miden_processor::{Felt, ONE};
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountDelta, AccountStorageDelta, AccountVaultDelta};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::errors::tx_kernel::{
    ERR_ACCOUNT_DELTA_NONCE_MUST_BE_INCREMENTED_IF_VAULT_OR_STORAGE_CHANGED,
    ERR_EPILOGUE_EXECUTED_TRANSACTION_IS_EMPTY,
    ERR_EPILOGUE_NONCE_CANNOT_BE_0,
    ERR_EPILOGUE_TOTAL_NUMBER_OF_ASSETS_MUST_STAY_THE_SAME,
    ERR_TX_INVALID_EXPIRATION_DELTA,
};
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::testing::storage::MOCK_VALUE_SLOT0;
use miden_protocol::transaction::memory::{
    NOTE_MEM_SIZE,
    OUTPUT_NOTE_ASSET_COMMITMENT_OFFSET,
    OUTPUT_NOTE_SECTION_OFFSET,
};
use miden_protocol::transaction::{OutputNote, OutputNotes, TransactionOutputs};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::testing::note::NoteBuilder;

use super::ZERO;
use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::utils::{create_p2any_note, create_public_p2any_note};
use crate::{
    Auth,
    MockChain,
    TransactionContextBuilder,
    TxContextInput,
    assert_execution_error,
    assert_transaction_executor_error,
};

/// Tests that the return values from the tx kernel main.masm program match the expected values.
#[tokio::test]
async fn test_transaction_epilogue() -> anyhow::Result<()> {
    let account = Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
    let asset = FungibleAsset::mock(100);
    let output_note_1 = create_public_p2any_note(account.id(), [asset]);
    // input_note_1 is needed for maintaining cohesion of involved assets
    let input_note_1 =
        create_public_p2any_note(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(), [asset]);

    let tx_context = TransactionContextBuilder::new(account.clone())
        .extend_input_notes(vec![input_note_1])
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_1.clone())])
        .build()?;

    let code = format!(
        "
        use $kernel::prologue
        use $kernel::epilogue
        use miden::protocol::output_note
        use miden::core::sys

        begin
            exec.prologue::prepare_transaction

            push.{recipient}
            push.{note_type}
            push.{tag}
            exec.output_note::create
            # => [note_idx]

            push.{asset}
            exec.output_note::add_asset
            # => []

            exec.epilogue::finalize_transaction

            # truncate the stack
            exec.sys::truncate_stack
        end
        ",
        recipient = output_note_1.recipient().digest(),
        note_type = Felt::from(output_note_1.metadata().note_type()),
        tag = Felt::from(output_note_1.metadata().tag()),
        asset = Word::from(asset)
    );

    let exec_output = tx_context.execute_code(&code).await?;

    // The final account is the initial account with the nonce incremented by one.
    let mut final_account = account.clone();
    final_account.increment_nonce(ONE)?;

    let output_notes = OutputNotes::new(
        tx_context
            .expected_output_notes()
            .iter()
            .cloned()
            .map(OutputNote::Full)
            .collect(),
    )?;

    let account_delta_commitment = AccountDelta::new(
        tx_context.account().id(),
        AccountStorageDelta::default(),
        AccountVaultDelta::default(),
        ONE,
    )?
    .to_commitment();

    let account_update_commitment =
        miden_protocol::Hasher::merge(&[final_account.commitment(), account_delta_commitment]);

    let mut expected_stack = Vec::with_capacity(16);
    expected_stack.extend(output_notes.commitment().as_elements().iter().rev());
    expected_stack.extend(account_update_commitment.as_elements().iter().rev());
    expected_stack.extend(
        Word::from(
            FungibleAsset::new(
                tx_context.tx_inputs().block_header().fee_parameters().native_asset_id(),
                0,
            )
            .unwrap(),
        )
        .iter()
        .rev(),
    );
    expected_stack.push(Felt::from(u32::MAX)); // Value for tx expiration block number
    expected_stack.extend((13..16).map(|_| ZERO));

    assert_eq!(
        exec_output.stack.as_slice(),
        expected_stack.as_slice(),
        "Stack state after finalize_transaction does not contain the expected values"
    );

    assert_eq!(
        exec_output.stack.len(),
        16,
        "The stack must be truncated to 16 elements after finalize_transaction"
    );
    Ok(())
}

/// Tests that the output note memory section is correctly populated during finalize_transaction.
#[tokio::test]
async fn test_compute_output_note_id() -> anyhow::Result<()> {
    let mut rng = RpoRandomCoin::new(Word::from([3, 4, 5, 6u32]));
    let account = Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
    let mut assets = account.vault().assets();
    let asset0 = assets.next().unwrap();
    let asset1 = assets.next().unwrap();

    let output_note0 = create_p2any_note(account.id(), NoteType::Private, [asset0], &mut rng);
    let output_note1 = create_p2any_note(account.id(), NoteType::Private, [asset1], &mut rng);

    let tx_context = TransactionContextBuilder::new(account.clone())
        .extend_expected_output_notes(vec![
            OutputNote::Full(output_note0.clone()),
            OutputNote::Full(output_note1.clone()),
        ])
        .build()?;

    let mut code = "
            use $kernel::prologue
            use $kernel::epilogue
            use miden::protocol::output_note
            use miden::core::sys

            begin
                exec.prologue::prepare_transaction"
        .to_owned();

    for note in tx_context.expected_output_notes() {
        let asset = note.assets().iter().next().unwrap();

        code.push_str(&format!(
            "
        push.{recipient}
        push.{note_type}
        push.{tag}
        exec.output_note::create
        # => [note_idx]

        push.{asset}
        call.::miden::standards::wallets::basic::move_asset_to_note
        # => []
        ",
            recipient = note.recipient().digest(),
            note_type = Felt::from(note.metadata().note_type()),
            tag = Felt::from(note.metadata().tag()),
            asset = Word::from(asset)
        ));
    }

    code.push_str(
        "
            exec.epilogue::finalize_transaction

            # truncate the stack
            exec.sys::truncate_stack
        end",
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    for (i, note) in tx_context.expected_output_notes().iter().enumerate() {
        let i = i as u32;
        assert_eq!(
            note.assets().commitment(),
            exec_output.get_kernel_mem_word(
                OUTPUT_NOTE_SECTION_OFFSET
                    + i * NOTE_MEM_SIZE
                    + OUTPUT_NOTE_ASSET_COMMITMENT_OFFSET
            ),
            "ASSET_COMMITMENT didn't match expected value",
        );

        assert_eq!(
            note.id().as_word(),
            exec_output.get_kernel_mem_word(OUTPUT_NOTE_SECTION_OFFSET + i * NOTE_MEM_SIZE),
            "NOTE_ID didn't match expected value",
        );
    }

    Ok(())
}

/// Tests that a transaction fails due to the asset preservation rules when the input note has an
/// asset with amount 100 and the output note has the same asset with amount 200.
#[tokio::test]
async fn epilogue_fails_when_num_output_assets_exceed_num_input_assets() -> anyhow::Result<()> {
    // Create an input asset with amount 100 and an output asset with amount 200.
    let input_asset = FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?, 100)?;
    let output_asset = input_asset.add(input_asset)?;

    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    // Add an input note that (automatically) adds its assets to the transaction's input vault, but
    // _does not_ add the asset to the account. This is just to keep the test conceptually simple -
    // there is no account involved.
    let input_note = NoteBuilder::new(account.id(), *builder.rng_mut())
        .add_assets([Asset::from(input_asset)])
        .build()?;
    builder.add_output_note(OutputNote::Full(input_note.clone()));
    let mock_chain = builder.build()?;

    let code = format!(
        "
      use mock::account
      use mock::util

      begin
          # create a note with the output asset
          push.{OUTPUT_ASSET}
          exec.util::create_default_note_with_asset
          # => []
      end
      ",
        OUTPUT_ASSET = Word::from(output_asset),
    );

    let builder = CodeBuilder::with_mock_libraries();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[input_note])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    let exec_output = tx_context.execute().await;
    assert_transaction_executor_error!(
        exec_output,
        ERR_EPILOGUE_TOTAL_NUMBER_OF_ASSETS_MUST_STAY_THE_SAME
    );

    Ok(())
}

/// Tests that a transaction fails due to the asset preservation rules when the input note has an
/// asset with amount 200 and the output note has the same asset with amount 100.
#[tokio::test]
async fn epilogue_fails_when_num_input_assets_exceed_num_output_assets() -> anyhow::Result<()> {
    // Create an input asset with amount 200 and an output asset with amount 100.
    let output_asset = FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?, 100)?;
    let input_asset = output_asset.add(output_asset)?;

    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    // Add an input note that (automatically) adds its assets to the transaction's input vault, but
    // _does not_ add the asset to the account. This is just to keep the test conceptually simple -
    // there is no account involved.
    let input_note = NoteBuilder::new(account.id(), *builder.rng_mut())
        .add_assets([Asset::from(output_asset)])
        .build()?;
    builder.add_output_note(OutputNote::Full(input_note.clone()));
    let mock_chain = builder.build()?;

    let code = format!(
        "
      use mock::account
      use mock::util

      begin
          # create a note with the output asset
          push.{OUTPUT_ASSET}
          exec.util::create_default_note_with_asset
          # => []
      end
      ",
        OUTPUT_ASSET = Word::from(input_asset),
    );

    let builder = CodeBuilder::with_mock_libraries();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[input_note])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    let exec_output = tx_context.execute().await;
    assert_transaction_executor_error!(
        exec_output,
        ERR_EPILOGUE_TOTAL_NUMBER_OF_ASSETS_MUST_STAY_THE_SAME
    );

    Ok(())
}

#[tokio::test]
async fn test_block_expiration_height_monotonically_decreases() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let test_pairs: [(u64, u64); 3] = [(9, 12), (18, 3), (20, 20)];
    let code_template = "
        use $kernel::prologue
        use $kernel::tx
        use $kernel::epilogue
        use $kernel::account

        begin
            exec.prologue::prepare_transaction
            push.{value_1}
            exec.tx::update_expiration_block_delta
            push.{value_2}
            exec.tx::update_expiration_block_delta

            push.{min_value} exec.tx::get_expiration_delta assert_eq.err=\"expiration delta mismatch\"

            exec.epilogue::finalize_transaction

            # truncate the stack
            repeat.13 movup.13 drop end
        end
        ";

    for (v1, v2) in test_pairs {
        let code = &code_template
            .replace("{value_1}", &v1.to_string())
            .replace("{value_2}", &v2.to_string())
            .replace("{min_value}", &v2.min(v1).to_string());

        let exec_output = &tx_context.execute_code(code).await?;

        // Expiry block should be set to transaction's block + the stored expiration delta
        // (which can only decrease, not increase)
        let expected_expiry =
            v1.min(v2) + tx_context.tx_inputs().block_header().block_num().as_u64();
        assert_eq!(
            exec_output
                .get_stack_element(TransactionOutputs::EXPIRATION_BLOCK_ELEMENT_IDX)
                .as_int(),
            expected_expiry
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_invalid_expiration_deltas() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let test_values = [0u64, u16::MAX as u64 + 1, u32::MAX as u64];
    let code_template = "
        use $kernel::tx

        begin
            push.{value_1}
            exec.tx::update_expiration_block_delta
        end
        ";

    for value in test_values {
        let code = &code_template.replace("{value_1}", &value.to_string());
        let exec_output = tx_context.execute_code(code).await;

        assert_execution_error!(exec_output, ERR_TX_INVALID_EXPIRATION_DELTA);
    }

    Ok(())
}

#[tokio::test]
async fn test_no_expiration_delta_set() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let code_template = "
    use $kernel::prologue
    use $kernel::epilogue
    use $kernel::tx
    use $kernel::account

    begin
        exec.prologue::prepare_transaction

        exec.tx::get_expiration_delta assertz.err=\"expiration delta should be unset\"

        exec.epilogue::finalize_transaction

        # truncate the stack
        repeat.13 movup.13 drop end
    end
    ";

    let exec_output = &tx_context.execute_code(code_template).await?;

    // Default value should be equal to u32::MAX, set in the prologue
    assert_eq!(
        exec_output
            .get_stack_element(TransactionOutputs::EXPIRATION_BLOCK_ELEMENT_IDX)
            .as_int() as u32,
        u32::MAX
    );

    Ok(())
}

#[tokio::test]
async fn test_epilogue_increment_nonce_success() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let expected_nonce = ONE + ONE;

    let code = format!(
        r#"
        use $kernel::prologue
        use mock::account
        use $kernel::epilogue
        use $kernel::memory

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        begin
            exec.prologue::prepare_transaction

            push.1.2.3.4
            push.MOCK_VALUE_SLOT0[0..2]
            call.account::set_item
            dropw

            exec.epilogue::finalize_transaction

            # clean the stack
            dropw dropw dropw dropw

            exec.memory::get_account_nonce
            push.{expected_nonce} assert_eq.err="nonce mismatch"
        end
        "#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
    );

    tx_context.execute_code(code.as_str()).await?;
    Ok(())
}

/// Tests that changing the account state without incrementing the nonce results in an error.
#[tokio::test]
async fn epilogue_fails_on_account_state_change_without_nonce_increment() -> anyhow::Result<()> {
    let code = format!(
        r#"
        use mock::account

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        begin
            push.91.92.93.94
            push.MOCK_VALUE_SLOT0[0..2]
            repeat.5 movup.5 drop end
            # => [slot_id_prefix, slot_id_suffix, VALUE]
            call.account::set_item
            # => [PREV_VALUE]
            dropw
        end
        "#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(code)?;

    let result = TransactionContextBuilder::with_noop_auth_account()
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_ACCOUNT_DELTA_NONCE_MUST_BE_INCREMENTED_IF_VAULT_OR_STORAGE_CHANGED
    );

    Ok(())
}

#[tokio::test]
async fn epilogue_fails_when_nonce_not_incremented() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.create_new_mock_account(Auth::Noop)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(TxContextInput::Account(account), &[], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_EPILOGUE_NONCE_CANNOT_BE_0);

    Ok(())
}

#[tokio::test]
async fn test_epilogue_execute_empty_transaction() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_noop_auth_account().build()?;

    let result = tx_context.execute().await;

    assert_transaction_executor_error!(result, ERR_EPILOGUE_EXECUTED_TRANSACTION_IS_EMPTY);

    Ok(())
}

#[tokio::test]
async fn test_epilogue_empty_transaction_with_empty_output_note() -> anyhow::Result<()> {
    let tag =
        NoteTag::with_account_target(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?);
    let note_type = NoteType::Private;

    // create an empty output note
    let code = format!(
        r#"
        use miden::core::word
        use miden::protocol::output_note
        use $kernel::prologue
        use $kernel::epilogue
        use $kernel::note

        begin
            exec.prologue::prepare_transaction

            # prepare the values for note creation
            push.1.2.3.4      # recipient
            push.{note_type}  # note_type
            push.{tag}        # tag
            # => [tag, note_type, RECIPIENT]

            # create the note
            exec.output_note::create
            # => [note_idx]

            # make sure that output note was created: compare the output note hash with an empty
            # word
            exec.note::compute_output_notes_commitment
            exec.word::eqz assertz.err="output note was created, but the output notes hash remains to be zeros"
            # => [note_idx]

            # clean the stack
            dropw dropw dropw dropw
            # => []

            exec.epilogue::finalize_transaction
        end
    "#,
        note_type = note_type as u8,
    );

    let tx_context = TransactionContextBuilder::with_noop_auth_account().build()?;

    let result = tx_context.execute_code(&code).await.map(|_| ());

    // assert that even if the output note was created, the transaction is considered empty
    assert_execution_error!(result, ERR_EPILOGUE_EXECUTED_TRANSACTION_IS_EMPTY);

    Ok(())
}
