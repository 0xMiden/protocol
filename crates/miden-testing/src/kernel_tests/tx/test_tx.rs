use alloc::string::{String, ToString};
use alloc::sync::Arc;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_processor::ExecutionError;
use miden_processor::crypto::random::RandomCoin;
use miden_processor::operation::OperationError;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountCode,
    AccountComponent,
    AccountDelta,
    AccountStorage,
    AccountStoragePatch,
    AccountType,
    AccountVaultDelta,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::assembly::{DefaultSourceManager, ModuleKind, ModuleParser, Package, Path};
use miden_protocol::asset::{Asset, AssetVault, FungibleAsset, NonFungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::ProvenTransactionError;
use miden_protocol::errors::tx_kernel::{
    ERR_KERNEL_PROCEDURE_OFFSET_OUT_OF_BOUNDS,
    ERR_TX_BLOCK_NUMBER_EXCEEDS_REFERENCE_BLOCK_NUMBER,
    ERR_TX_BLOCK_NUMBER_NOT_U32,
};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentScheme,
    NoteAttachments,
    NoteDetailsCommitment,
    NoteId,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNote,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::testing::constants::{FUNGIBLE_ASSET_AMOUNT, NON_FUNGIBLE_ASSET_DATA};
use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    RawOutputNote,
    RawOutputNotes,
    TransactionArgs,
    TransactionKernel,
    TransactionSummary,
    TransactionSummaryUserParams,
};
use miden_protocol::{Felt, Hasher, ONE, Word};
use miden_standards::account::interface::{
    AccountComponentInterface,
    AccountInterface,
    AccountInterfaceExt,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::IncrNonceAuthComponent;
use miden_standards::testing::account_interface::get_public_keys_from_account;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_tx::auth::UnreachableAuth;
use miden_tx::{
    LocalTransactionProver,
    TransactionExecutor,
    TransactionExecutorError,
    TransactionKernelError,
    TransactionProverError,
};
use rstest::rstest;

use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::utils::{create_p2any_note, create_public_p2any_note, create_spawn_note};
use crate::{
    Auth,
    MockChain,
    TestTransactionBuilder,
    assert_execution_error,
    assert_transaction_executor_error,
};

/// Tests that consuming a note created in a block that is newer than the reference block of the
/// transaction fails.
#[tokio::test]
async fn consuming_note_created_in_future_block_fails() -> anyhow::Result<()> {
    // Create a chain with an account
    let mut builder = MockChain::builder();
    let asset = FungibleAsset::mock(400);
    let account1 = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [asset],
    )?;
    let account2 = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [asset],
    )?;
    let output_note = create_public_p2any_note(account1.id(), [asset]);
    let spawn_note = builder.add_spawn_note([&output_note])?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_until_block(10u32)?;

    // Consume the spawn note which creates a note for account 2 to consume. It will be contained in
    // block 11. We use account 1 for this, so that account 2 remains unchanged and is still valid
    // against reference block 1 which we'll use for the later transaction.
    let tx = mock_chain
        .build_transaction(account1.id())
        .authenticated_input_note(spawn_note.id())
        .expected_output_note(RawOutputNote::Full(output_note.clone()))
        .build()?
        .execute()
        .await?;

    // Add the transaction to the mock chain's mempool so it will be included in the next block.
    mock_chain.add_pending_executed_transaction(&tx)?;
    // Create block 11.
    mock_chain.prove_next_block()?;

    // Get the input note and assert that the note was created after block 11.
    let input_note = mock_chain.get_public_note(&output_note.id()).expect("note not found");
    assert_eq!(input_note.location().unwrap().block_num().as_u32(), 11);

    mock_chain.prove_next_block()?;
    mock_chain.prove_next_block()?;

    // Attempt to execute a transaction against reference block 1 with the note created in block 11
    // - which should fail.
    let mock_tx = mock_chain.build_transaction(account2.id()).build()?;

    let tx_executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&mock_tx)
        .with_source_manager(mock_tx.source_manager());

    // Try to execute with block_ref==1
    let error = tx_executor
        .execute_transaction(
            account2.id(),
            BlockNumber::from(1),
            InputNotes::new(vec![input_note]).unwrap(),
            TransactionArgs::default(),
        )
        .await;

    assert_matches::assert_matches!(
        error,
        Err(TransactionExecutorError::NoteBlockPastReferenceBlock(..))
    );

    Ok(())
}

// BLOCK TESTS
// ================================================================================================

#[tokio::test]
async fn test_block_procedures() -> anyhow::Result<()> {
    let mock_tx = TestTransactionBuilder::with_existing_mock_account().build()?;

    let code = "
        use miden::protocol::tx
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction

            # get the block data
            exec.tx::get_reference_block_number
            exec.tx::get_block_timestamp
            exec.tx::get_reference_block_commitment
            # => [BLOCK_COMMITMENT, block_timestamp, block_number]

            # truncate the stack
            swapdw dropw dropw
        end
        ";

    let exec_output = &mock_tx.execute_code(code).await?;

    assert_eq!(
        exec_output.get_stack_word(0),
        mock_tx.tx_inputs().block_header().commitment(),
        "top word on the stack should be equal to the block header commitment"
    );

    assert_eq!(
        exec_output.get_stack_element(4).as_canonical_u64(),
        mock_tx.tx_inputs().block_header().timestamp() as u64,
        "fifth element on the stack should be equal to the timestamp of the last block creation"
    );

    assert_eq!(
        exec_output.get_stack_element(5).as_canonical_u64(),
        mock_tx.tx_inputs().block_header().block_num().as_u64(),
        "sixth element on the stack should be equal to the block number"
    );
    Ok(())
}

/// Builds the code reading the commitment of the block with the provided number.
fn get_block_commitment_code(block_number: &str) -> String {
    format!(
        "
        use miden::tx_kernel_core::prologue
        use miden::protocol::tx
        use miden::core::sys

        begin
            exec.prologue::prepare_transaction

            push.{block_number}
            exec.tx::get_block_commitment
            # => [BLOCK_COMMITMENT]

            exec.sys::truncate_stack
        end
        "
    )
}

/// Tests that `tx::get_block_commitment` returns the commitment of the transaction reference block
/// as well as of an older block tracked by the partial blockchain.
///
/// The reference block commitment is served from kernel memory while older blocks are read from the
/// partial blockchain, so both paths are covered.
#[tokio::test]
async fn tx_get_block_commitment_returns_tracked_block() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let note = builder.add_p2any_note(account.id(), NoteType::Private, [])?;
    let mut chain = builder.build()?;
    // Move the chain forward so that the note's block is older than the reference block.
    chain.prove_next_block()?;

    // Authenticating the note makes the partial blockchain track the block that created it.
    let mock_tx = chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()?;

    let ref_block_header = mock_tx.tx_inputs().block_header().clone();
    let older_block_header = mock_tx
        .tx_inputs()
        .blockchain()
        .block_headers()
        .find(|header| header.block_num() != ref_block_header.block_num())
        .context("partial blockchain should track a block other than the reference block")?
        .clone();

    for block_header in [ref_block_header, older_block_header] {
        let code = get_block_commitment_code(&block_header.block_num().to_string());
        let exec_output = mock_tx.execute_code(&code).await?;

        assert_eq!(exec_output.get_stack_word(0), block_header.commitment());
    }

    Ok(())
}

/// Tests that `tx::get_block_commitment` rejects block numbers beyond the transaction reference
/// block and non-u32 block numbers.
#[tokio::test]
async fn tx_get_block_commitment_rejects_invalid_block_numbers() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let mut chain = builder.build()?;
    chain.prove_next_block()?;

    let mock_tx = chain.build_transaction(account.id()).build()?;
    let ref_block_number = mock_tx.tx_inputs().block_header().block_num();

    let beyond_reference = (ref_block_number + 1).to_string();
    let exec_output = mock_tx.execute_code(&get_block_commitment_code(&beyond_reference)).await;
    assert_execution_error!(exec_output, ERR_TX_BLOCK_NUMBER_EXCEEDS_REFERENCE_BLOCK_NUMBER);

    let non_u32 = (u64::from(u32::MAX) + 1).to_string();
    let exec_output = mock_tx.execute_code(&get_block_commitment_code(&non_u32)).await;

    // `u32assert` raises a `U32AssertionFailed` (not a plain `FailedAssertion`), so match the
    // variant explicitly and assert on its error code.
    assert_execution_error!(
        exec_output,
        matches ExecutionError::OperationError {
            err: OperationError::U32AssertionFailed { err_code, .. },
            ..
        } if err_code == ERR_TX_BLOCK_NUMBER_NOT_U32.code()
    );

    Ok(())
}

#[tokio::test]
async fn executed_transaction_output_notes() -> anyhow::Result<()> {
    let executor_account =
        Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, [IncrNonceAuthComponent]);
    let account_id = executor_account.id();

    // removed assets
    let removed_asset_1 = FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT / 2);
    let removed_asset_2 = FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT / 2);

    let combined_asset = Asset::from(
        FungibleAsset::new(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().expect("id is valid"),
            FUNGIBLE_ASSET_AMOUNT,
        )
        .expect("asset is valid"),
    );
    let removed_asset_3 = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA);
    let removed_asset_4 = Asset::from(
        FungibleAsset::new(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().expect("id is valid"),
            FUNGIBLE_ASSET_AMOUNT / 2,
        )
        .expect("asset is valid"),
    );

    let tag1 = NoteTag::with_account_target(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
    );
    let tag2 = NoteTag::default();
    let tag3 = NoteTag::default();

    let attachment2 =
        NoteAttachment::with_word(NoteAttachmentScheme::new(28)?, Word::from([2, 3, 4, 5u32]));
    let attachment3 = NoteAttachment::with_words(
        NoteAttachmentScheme::new(29)?,
        vec![Word::from([6, 7, 8, 9u32]), Word::from([10, 11, 12, 13u32])],
    )?;

    let note_type1 = NoteType::Private;
    let note_type2 = NoteType::Public;
    let note_type3 = NoteType::Public;

    // In this test we create 3 notes. Note 1 is private, Note 2 is public and Note 3 is public
    // without assets.

    let recipient_1 = Word::from([0, 1, 2, 3u32]);

    // Create the expected output note for Note 2 which is public
    let serial_num_2 = Word::from([1, 2, 3, 4u32]);
    let note_script_2 = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT)?;
    let inputs_2 = NoteStorage::new(vec![ONE])?;
    let metadata_2 = PartialNoteMetadata::new(account_id, note_type2).with_tag(tag2);
    let vault_2 = NoteAssets::new(vec![removed_asset_3, removed_asset_4])?;
    let recipient_2 = NoteRecipient::new(serial_num_2, note_script_2, inputs_2);
    let attachments_2 = NoteAttachments::from(attachment2.clone());
    let expected_output_note_2 =
        Note::with_attachments(vault_2, metadata_2, recipient_2, attachments_2);

    // Create the expected output note for Note 3 which is public
    let serial_num_3 =
        Word::from([Felt::from(5_u32), Felt::from(6_u32), Felt::from(7_u32), Felt::from(8_u32)]);
    let note_script_3 = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT)?;
    let inputs_3 = NoteStorage::new(vec![ONE, Felt::from(2_u32)])?;
    let metadata_3 = PartialNoteMetadata::new(account_id, note_type3).with_tag(tag3);
    let vault_3 = NoteAssets::new(vec![])?;
    let recipient_3 = NoteRecipient::new(serial_num_3, note_script_3, inputs_3);
    let attachments_3 = NoteAttachments::from(attachment3.clone());
    let expected_output_note_3 =
        Note::with_attachments(vault_3, metadata_3, recipient_3, attachments_3);

    let tx_script_src = format!(
        "\
        use miden::core::sys
        use miden::protocol::output_note
        use mock::util

        ## TRANSACTION SCRIPT
        ## ========================================================================================
        @transaction_script
        pub proc main
            ## Send some assets from the account vault
            ## ------------------------------------------------------------------------------------
            # partially deplete fungible asset balance
            push.{recipient_1}                  # recipient
            push.{NOTETYPE1}                    # note_type
            push.{tag1}                         # tag
            call.::mock::account::create_note
            # => [note_idx = 0]

            dup
            push.{REMOVED_ASSET_VALUE_1}
            push.{REMOVED_ASSET_ID_1}
            # => [ASSET_ID, ASSET_VALUE, note_idx, note_idx]

            exec.util::move_asset_to_note
            # => [note_idx]

            push.{REMOVED_ASSET_VALUE_2}
            push.{REMOVED_ASSET_ID_2}
            exec.util::move_asset_to_note
            # => []

            # send non-fungible asset
            push.{RECIPIENT2}                   # recipient
            push.{NOTETYPE2}                    # note_type
            push.{tag2}                         # tag
            call.::mock::account::create_note
            # => [note_idx = 1]

            dup
            push.{REMOVED_ASSET_VALUE_3}
            push.{REMOVED_ASSET_ID_3}
            exec.util::move_asset_to_note
            # => [note_idx]

            dup
            push.{REMOVED_ASSET_VALUE_4}
            push.{REMOVED_ASSET_ID_4}
            exec.util::move_asset_to_note
            # => [note_idx]

            push.{ATTACHMENT2}
            push.{attachment_scheme2}
            # => [attachment_scheme, ATTACHMENT, note_idx]
            exec.output_note::add_word_attachment
            # => []

            # create a public note without assets
            push.{RECIPIENT3}                   # recipient
            push.{NOTETYPE3}                    # note_type
            push.{tag3}                         # tag
            call.::mock::account::create_note
            # => [note_idx = 2]

            # Store attachment3 words to memory at address 1024
            push.{attachment3_word0} mem_storew_le.1024 dropw
            push.{attachment3_word1} mem_storew_le.1028 dropw

            push.1024
            push.{num_attachment3_words}
            push.{attachment_scheme3}
            # => [attachment_scheme, num_words, ptr, note_idx]
            exec.output_note::add_attachment_from_memory
            # => []

            exec.sys::truncate_stack
        end
    ",
        REMOVED_ASSET_ID_1 = removed_asset_1.to_id_word(),
        REMOVED_ASSET_VALUE_1 = removed_asset_1.to_value_word(),
        REMOVED_ASSET_ID_2 = removed_asset_2.to_id_word(),
        REMOVED_ASSET_VALUE_2 = removed_asset_2.to_value_word(),
        REMOVED_ASSET_ID_3 = removed_asset_3.to_id_word(),
        REMOVED_ASSET_VALUE_3 = removed_asset_3.to_value_word(),
        REMOVED_ASSET_ID_4 = removed_asset_4.to_id_word(),
        REMOVED_ASSET_VALUE_4 = removed_asset_4.to_value_word(),
        RECIPIENT2 = expected_output_note_2.recipient().digest(),
        RECIPIENT3 = expected_output_note_3.recipient().digest(),
        NOTETYPE1 = note_type1 as u8,
        NOTETYPE2 = note_type2 as u8,
        NOTETYPE3 = note_type3 as u8,
        attachment_scheme2 = attachment2.attachment_scheme().as_u16(),
        ATTACHMENT2 = Word::from([2, 3, 4, 5u32]),
        attachment_scheme3 = attachment3.attachment_scheme().as_u16(),
        attachment3_word0 = attachment3.content().as_words()[0],
        attachment3_word1 = attachment3.content().as_words()[1],
        num_attachment3_words = attachment3.content().num_words(),
    );

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(tx_script_src)?;

    // expected delta
    // --------------------------------------------------------------------------------------------
    // execute the transaction and get the witness

    assert!(attachment3.content().num_words() > 1, "expected multi-word attachment");

    let mock_tx = TestTransactionBuilder::new(executor_account)
        .tx_script(tx_script)
        .expected_output_notes(vec![
            RawOutputNote::Full(expected_output_note_2.clone()),
            RawOutputNote::Full(expected_output_note_3.clone()),
        ])
        .build()?;

    let executed_transaction = mock_tx.execute().await?;

    // output notes
    // --------------------------------------------------------------------------------------------
    let output_notes = executed_transaction.output_notes();

    // check the total number of notes
    assert_eq!(output_notes.num_notes(), 3);

    // assert that the expected output note 1 is present
    let resulting_output_note_1 = executed_transaction.output_notes().get_note(0);

    let expected_note_assets_1 = NoteAssets::new(vec![combined_asset])?;
    let details_commitment_1 = NoteDetailsCommitment::from_raw_commitments(
        recipient_1,
        expected_note_assets_1.commitment(),
    );
    let expected_note_id_1 = NoteId::new(details_commitment_1, resulting_output_note_1.metadata());
    assert_eq!(resulting_output_note_1.id(), expected_note_id_1);

    // assert that the expected output note 2 is present
    let resulting_output_note_2 = executed_transaction.output_notes().get_note(1);

    assert_eq!(*resulting_output_note_2.header(), *expected_output_note_2.header());

    // assert that the expected output note 3 is present and has no assets
    let resulting_output_note_3 = executed_transaction.output_notes().get_note(2);

    assert_eq!(expected_output_note_3.id(), resulting_output_note_3.id());
    assert_eq!(expected_output_note_3.assets(), resulting_output_note_3.assets());

    // make sure that the number of note storage items remains the same
    let resulting_note_2_recipient =
        resulting_output_note_2.recipient().expect("output note 2 is not full");
    assert_eq!(
        resulting_note_2_recipient.storage().num_items(),
        expected_output_note_2.storage().num_items()
    );

    let resulting_note_3_recipient =
        resulting_output_note_3.recipient().expect("output note 3 is not full");
    assert_eq!(
        resulting_note_3_recipient.storage().num_items(),
        expected_output_note_3.storage().num_items()
    );

    Ok(())
}

/// Tests that a transaction consuming and creating one note can emit an abort event in its auth
/// component to result in a [`TransactionExecutorError::Unauthorized`] error.
#[tokio::test]
async fn user_code_can_abort_transaction_with_summary() -> anyhow::Result<()> {
    let source_code = r#"
      use miden::standards::auth
      const AUTH_UNAUTHORIZED_EVENT=event("miden::protocol::auth::unauthorized")
      #! Inputs:  [AUTH_ARGS, pad(12)]
      #! Outputs: [pad(16)]
      @auth_script
      pub proc auth_abort_tx
          dropw
          # => [pad(16)]

          exec.::miden::protocol::native_account::incr_nonce
          # => [final_nonce, pad(16)]

          # pass the final nonce as the last user param and zero the remaining ones
          push.0.0.0.0.0.0
          # => [user_params(7), pad(16)]

          exec.auth::create_tx_summary_with_ref_block
          # => [PARAMS_HEAD, PARAMS_TAIL, ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, BLOCK_COMMITMENT, pad(16)]

          exec.auth::hash_and_insert_tx_summary
          # => [MESSAGE, pad(16)]

          emit.AUTH_UNAUTHORIZED_EVENT
      end
    "#;

    let auth_code = CodeBuilder::default()
        .compile_component_code("test::auth_component", source_code)
        .context("failed to parse auth component")?;
    let auth_component = AccountComponent::new(
        auth_code,
        vec![],
        AccountComponentMetadata::mock("test::auth_component"),
    )
    .context("failed to parse auth component")?;

    let account = AccountBuilder::new([42; 32])
        .account_type(AccountType::Private)
        .with_component(auth_component)
        .with_component(BasicWallet)
        .build_existing()
        .context("failed to build account")?;

    // Consume and create a note so the input and outputs notes commitment is not the empty word.
    let mut rng = RandomCoin::new(Word::empty());
    let output_note = create_p2any_note(account.id(), NoteType::Private, [], &mut rng);
    let input_note = create_spawn_note(vec![&output_note])?;

    let mut builder = MockChain::builder();
    builder.add_output_note(RawOutputNote::Full(input_note.clone()));
    let mock_chain = builder.build()?;

    let mock_tx = mock_chain
        .build_transaction(account)
        .authenticated_input_note(input_note.id())
        .build()?;
    let ref_block_number = mock_tx.tx_inputs().block_header().block_num();
    let ref_block_commitment = mock_tx.tx_inputs().block_header().commitment();
    let final_nonce = mock_tx.account().nonce().as_canonical_u64() as u32 + 1;
    let input_notes = mock_tx.input_notes().clone();
    let output_notes = RawOutputNotes::new(vec![RawOutputNote::Partial(output_note.into())])?;

    let error = mock_tx.execute().await.unwrap_err();

    assert_matches!(error, TransactionExecutorError::Unauthorized(tx_summary) => {
        assert!(tx_summary.account_delta().vault().is_empty());
        assert!(tx_summary.account_delta().storage().is_empty());
        assert_eq!(tx_summary.account_delta().nonce_delta().as_canonical_u64(), 1);
        assert_eq!(tx_summary.input_notes(), &input_notes);
        assert_eq!(tx_summary.output_notes(), &output_notes);
        assert_eq!(tx_summary.block_number(), ref_block_number);
        assert_eq!(tx_summary.block_commitment(), ref_block_commitment);
        assert_eq!(tx_summary.expiration_delta(), 0);
        assert_eq!(
            tx_summary.user_params(),
            TransactionSummaryUserParams::new([0, 0, 0, 0, 0, 0, final_nonce].map(Felt::from))
        );
    });

    Ok(())
}

/// Tests that the transaction summary binds the expiration block delta set during the transaction
/// and the user-defined parameters passed to `create_tx_summary_with_ref_block`.
///
/// The host verifies that the reconstructed summary commits to the message hashed in the kernel,
/// so the assertions on the extracted summary prove that these values are part of the signed
/// message.
#[tokio::test]
async fn tx_summary_binds_expiration_delta_and_user_params() -> anyhow::Result<()> {
    let source_code = r#"
      use miden::standards::auth
      use miden::protocol::tx
      const AUTH_UNAUTHORIZED_EVENT=event("miden::protocol::auth::unauthorized")
      #! Inputs:  [AUTH_ARGS, pad(12)]
      #! Outputs: [pad(16)]
      @auth_script
      pub proc auth_abort_tx
          dropw
          # => [pad(16)]

          push.42 exec.tx::update_expiration_block_delta
          # => [pad(16)]

          exec.::miden::protocol::native_account::incr_nonce
          # => [final_nonce, pad(16)]

          # pass [7, 8, 9] as the leading user params and the final nonce as the last one
          push.0.0.0.9.8.7
          # => [user_params(7), pad(16)]

          exec.auth::create_tx_summary_with_ref_block
          # => [PARAMS_HEAD, PARAMS_TAIL, ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, BLOCK_COMMITMENT, pad(16)]

          exec.auth::hash_and_insert_tx_summary
          # => [MESSAGE, pad(16)]

          emit.AUTH_UNAUTHORIZED_EVENT
      end
    "#;

    let auth_code = CodeBuilder::default()
        .compile_component_code("test::auth_component", source_code)
        .context("failed to parse auth component")?;
    let auth_component = AccountComponent::new(
        auth_code,
        vec![],
        AccountComponentMetadata::mock("test::auth_component"),
    )
    .context("failed to parse auth component")?;

    let account = AccountBuilder::new([43; 32])
        .account_type(AccountType::Private)
        .with_component(auth_component)
        .with_component(BasicWallet)
        .build_existing()
        .context("failed to build account")?;

    let mock_chain = MockChain::builder().build()?;
    let mock_tx = mock_chain.build_transaction(account).build()?;
    let ref_block_commitment = mock_tx.tx_inputs().block_header().commitment();
    let final_nonce = mock_tx.account().nonce().as_canonical_u64() as u32 + 1;

    let error = mock_tx.execute().await.unwrap_err();

    assert_matches!(error, TransactionExecutorError::Unauthorized(tx_summary) => {
        assert_eq!(tx_summary.expiration_delta(), 42);
        assert_eq!(
            tx_summary.user_params(),
            TransactionSummaryUserParams::new([7, 8, 9, 0, 0, 0, final_nonce].map(Felt::from))
        );
        assert_eq!(tx_summary.block_commitment(), ref_block_commitment);
    });

    Ok(())
}

/// Tests that the host rejects a transaction summary whose block commitment does not match the
/// reference block of the transaction.
#[tokio::test]
async fn tx_summary_with_wrong_block_commitment_is_rejected() -> anyhow::Result<()> {
    let source_code = r#"
      use miden::standards::auth
      use miden::protocol::tx
      const AUTH_UNAUTHORIZED_EVENT=event("miden::protocol::auth::unauthorized")
      #! Inputs:  [AUTH_ARGS, pad(12)]
      #! Outputs: [pad(16)]
      @auth_script
      pub proc auth_abort_tx
          dropw
          # => [pad(16)]

          exec.::miden::protocol::native_account::incr_nonce drop
          # => [pad(16)]

          # Assemble the summary preimage manually with a bogus BLOCK_COMMITMENT. The commitment is
          # the deepest word of the preimage, so it cannot be patched in after create_tx_summary.
          push.1.2.3.4
          # => [FAKE_BLOCK_COMMITMENT, pad(16)]

          exec.tx::get_output_notes_commitment
          exec.tx::get_input_notes_commitment
          exec.::miden::protocol::native_account::compute_delta_commitment
          # => [ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, FAKE_BLOCK_COMMITMENT, pad(16)]

          # the seven user params are all zero here
          padw push.0.0.0
          # => [user_params(7), ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, FAKE_BLOCK_COMMITMENT, pad(16)]

          # metadata for version 1, the reference block number and an unset expiration delta
          exec.tx::get_reference_block_number mul.0x100 add.1
          # => [PARAMS_HEAD, PARAMS_TAIL, ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, FAKE_BLOCK_COMMITMENT, pad(16)]

          exec.auth::hash_and_insert_tx_summary
          # => [MESSAGE, pad(16)]

          emit.AUTH_UNAUTHORIZED_EVENT
      end
    "#;

    let auth_code = CodeBuilder::default()
        .compile_component_code("test::auth_component", source_code)
        .context("failed to parse auth component")?;
    let auth_component = AccountComponent::new(
        auth_code,
        vec![],
        AccountComponentMetadata::mock("test::auth_component"),
    )
    .context("failed to parse auth component")?;

    let account = AccountBuilder::new([44; 32])
        .account_type(AccountType::Private)
        .with_component(auth_component)
        .with_component(BasicWallet)
        .build_existing()
        .context("failed to build account")?;

    let mock_chain = MockChain::builder().build()?;
    let mock_tx = mock_chain.build_transaction(account).build()?;

    let error = mock_tx.execute().await.unwrap_err();

    assert_matches!(
        error,
        TransactionExecutorError::TransactionProgramExecutionFailed(
            ExecutionError::EventError { error: ref event_err, .. }
        ) if matches!(
            event_err.downcast_ref::<TransactionKernelError>(),
            Some(TransactionKernelError::TransactionSummaryCommitmentMismatch(inner))
                if inner.to_string().contains("block commitment")
        )
    );

    Ok(())
}

/// Tests that the host rejects a transaction summary whose expiration delta does not match the
/// kernel state of the transaction.
#[tokio::test]
async fn tx_summary_with_forged_expiration_delta_is_rejected() -> anyhow::Result<()> {
    let source_code = r#"
      use miden::standards::auth
      use miden::protocol::tx
      const AUTH_UNAUTHORIZED_EVENT=event("miden::protocol::auth::unauthorized")
      #! Inputs:  [AUTH_ARGS, pad(12)]
      #! Outputs: [pad(16)]
      @auth_script
      pub proc auth_abort_tx
          dropw
          # => [pad(16)]

          exec.::miden::protocol::native_account::incr_nonce drop
          # => [pad(16)]

          # Assemble the summary preimage manually with a forged metadata felt claiming an
          # expiration delta of 777 while the transaction never set one.
          exec.tx::get_reference_block_commitment
          exec.tx::get_output_notes_commitment
          exec.tx::get_input_notes_commitment
          exec.::miden::protocol::native_account::compute_delta_commitment
          # => [ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, BLOCK_COMMITMENT, pad(16)]

          # the seven user params are all zero here
          padw push.0.0.0
          # => [user_params(7), ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, BLOCK_COMMITMENT, pad(16)]

          push.777 mul.0x10000000000
          exec.tx::get_reference_block_number mul.0x100 add add.1
          # => [PARAMS_HEAD, PARAMS_TAIL, ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, BLOCK_COMMITMENT, pad(16)]

          exec.auth::hash_and_insert_tx_summary
          # => [MESSAGE, pad(16)]

          emit.AUTH_UNAUTHORIZED_EVENT
      end
    "#;

    let auth_code = CodeBuilder::default()
        .compile_component_code("test::auth_component", source_code)
        .context("failed to parse auth component")?;
    let auth_component = AccountComponent::new(
        auth_code,
        vec![],
        AccountComponentMetadata::mock("test::auth_component"),
    )
    .context("failed to parse auth component")?;

    let account = AccountBuilder::new([45; 32])
        .account_type(AccountType::Private)
        .with_component(auth_component)
        .with_component(BasicWallet)
        .build_existing()
        .context("failed to build account")?;

    let mock_chain = MockChain::builder().build()?;
    let mock_tx = mock_chain.build_transaction(account).build()?;

    let error = mock_tx.execute().await.unwrap_err();

    assert_matches!(
        error,
        TransactionExecutorError::TransactionProgramExecutionFailed(
            ExecutionError::EventError { error: ref event_err, .. }
        ) if matches!(
            event_err.downcast_ref::<TransactionKernelError>(),
            Some(TransactionKernelError::TransactionSummaryExpirationDeltaMismatch {
                expected: 0,
                actual: 777,
            })
        )
    );

    Ok(())
}

/// Tests that a transaction consuming and creating one note with basic authentication correctly
/// signs the transaction summary.
#[rstest]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn tx_summary_commitment_is_signed_by_auth_singlesig(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::BasicAuth { auth_scheme })?;
    let mut rng = RandomCoin::new(Word::empty());
    let p2any_note = create_p2any_note(account.id(), NoteType::Private, [], &mut rng);
    let spawn_note = builder.add_spawn_note([&p2any_note])?;
    let chain = builder.build()?;

    let tx_builder = chain
        .build_transaction(account.id())
        .unauthenticated_input_note(spawn_note.clone());

    let tx = tx_builder.clone().build()?;
    let ref_block_number = tx.tx_inputs().block_header().block_num();
    let ref_block_commitment = tx.tx_inputs().block_header().commitment();
    let tx = tx.execute().await?;

    let nonce_delta = Felt::ONE;
    let final_nonce = account.nonce() + nonce_delta;
    let account_delta = AccountDelta::new(
        account.id(),
        AccountStoragePatch::default(),
        AccountVaultDelta::default(),
        None,
        nonce_delta,
    )?;
    let expected_summary = TransactionSummary::new(
        account_delta,
        InputNotes::new(vec![InputNote::unauthenticated(spawn_note)])?,
        RawOutputNotes::new(vec![RawOutputNote::Partial(PartialNote::from(p2any_note))])?,
        ref_block_number,
        ref_block_commitment,
        0,
        TransactionSummaryUserParams::new(
            [final_nonce.as_canonical_u64() as u32, 0, 0, 0, 0, 0, 0].map(Felt::from),
        ),
    );

    let summary_commitment = expected_summary.to_commitment();

    let account_interface = AccountInterface::from_account(&account);
    assert!(matches!(
        account_interface.auth_component(),
        AccountComponentInterface::AuthSingleSig
    ));
    let pub_keys = get_public_keys_from_account(&account);
    let pub_key = pub_keys.first().expect("expected at least one public key");

    // This is in an internal detail of the tx executor host, but this is the easiest way to check
    // for the presence of the signature in the advice map.
    let signature_key = Hasher::merge(&[*pub_key, summary_commitment]);

    // The summary commitment should have been signed as part of transaction execution and inserted
    // into the advice map.
    tx.advice_witness().map.get(&signature_key).unwrap();

    Ok(())
}

/// Tests that execute_tx_view_script returns the expected stack outputs.
#[tokio::test]
async fn execute_tx_view_script() -> anyhow::Result<()> {
    let test_module_source = "
        pub proc foo
            push.3.4
            add
            swapw dropw
        end
    ";

    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = compile_test_package(
        source_manager.clone(),
        "test-tx-view-script",
        "test::module_1",
        test_module_source,
    );

    let source = "
    use test::module_1
    use miden::core::sys

    @transaction_script
    pub proc main
        push.1.2
        call.module_1::foo
        exec.sys::truncate_stack
    end
    ";

    let tx_script = CodeBuilder::new()
        .with_statically_linked_package(&package)?
        .compile_tx_script(source)?;
    let mock_tx = TestTransactionBuilder::with_existing_mock_account()
        .with_source_manager(source_manager.clone())
        .tx_script(tx_script.clone())
        .build()?;
    let account_id = mock_tx.account().id();
    let block_ref = mock_tx.tx_inputs().block_header().block_num();
    let advice_inputs = mock_tx.tx_args().advice_inputs().clone();

    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&mock_tx)
        .with_source_manager(source_manager);

    let stack_outputs = executor
        .execute_tx_view_script(account_id, block_ref, tx_script, advice_inputs)
        .await?;

    assert_eq!(stack_outputs[..3], [Felt::new_unchecked(7), Felt::new_unchecked(2), ONE]);

    Ok(())
}

fn compile_test_package(
    source_manager: Arc<DefaultSourceManager>,
    name: &str,
    path: &str,
    source: &str,
) -> Package {
    let assembler = TransactionKernel::assembler_with_source_manager(source_manager.clone());
    let source = ModuleParser::new(Some(ModuleKind::Library))
        .parse_str(Some(Path::new(path)), source, source_manager)
        .unwrap();

    *assembler.assemble_library(name, source, None::<&str>).unwrap()
}

#[tokio::test]
async fn failed_tx_script_reports_package_debug_message() -> anyhow::Result<()> {
    const ERROR_MESSAGE: &str = "transaction script debug message should survive execution";

    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        @transaction_script
        pub proc main
            push.0 assert.err="{ERROR_MESSAGE}"
        end
        "#
    ))?;

    let mock_tx = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .build()?;
    let error = mock_tx.execute().await.expect_err("transaction script should fail");

    assert_transaction_error_contains_debug_message(&error, ERROR_MESSAGE);

    Ok(())
}

#[tokio::test]
async fn failed_tx_view_script_reports_package_debug_message() -> anyhow::Result<()> {
    const ERROR_MESSAGE: &str = "view script debug message should survive execution";

    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        @transaction_script
        pub proc main
            push.0 assert.err="{ERROR_MESSAGE}"
        end
        "#
    ))?;

    let mock_tx = TestTransactionBuilder::with_existing_mock_account().build()?;
    let account_id = mock_tx.account().id();
    let block_ref = mock_tx.tx_inputs().block_header().block_num();
    let advice_inputs = mock_tx.tx_args().advice_inputs().clone();

    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&mock_tx);
    let error = executor
        .execute_tx_view_script(account_id, block_ref, tx_script, advice_inputs)
        .await
        .expect_err("transaction view script should fail");

    assert_transaction_error_contains_debug_message(&error, ERROR_MESSAGE);

    Ok(())
}

fn assert_transaction_error_contains_debug_message(
    error: &TransactionExecutorError,
    expected_message: &str,
) {
    let diagnostic = error.to_string();

    assert!(
        diagnostic.contains(expected_message),
        "expected package debug info to recover the assertion message:\n{diagnostic}"
    );
}

// TEST TRANSACTION SCRIPT
// ================================================================================================

/// Tests transaction script inputs.
#[tokio::test]
async fn test_tx_script_inputs() -> anyhow::Result<()> {
    let tx_script_input_key = Word::from([9999, 8888, 9999, 8888u32]);
    let tx_script_input_value = Word::from([9, 8, 7, 6u32]);
    let tx_script_src = format!(
        r#"
        @transaction_script
        pub proc main
            # push the tx script input key onto the stack
            push.{tx_script_input_key}

            # load the tx script input value from the map and read it onto the stack
            adv.push_mapval adv_loadw

            # assert that the value is correct
            push.{tx_script_input_value} assert_eqw.err="tx script input value mismatch"
        end
        "#,
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_src)?;

    let mock_tx = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .add_advice_map_entry(tx_script_input_key, tx_script_input_value.to_vec())
        .build()?;

    mock_tx.execute().await.context("failed to execute transaction")?;

    Ok(())
}

/// Tests transaction script arguments.
#[tokio::test]
async fn test_tx_script_args() -> anyhow::Result<()> {
    let tx_script_args = Word::from([1, 2, 3, 4u32]);
    let advice_entry = Word::from([5, 6, 7, 8u32]);

    let tx_script_src = format!(
        r#"
        @transaction_script
        pub proc main
            # => [TX_SCRIPT_ARGS]
            # `TX_SCRIPT_ARGS` value is a user provided word, which could be used during the
            # transaction execution. In this example it is a `[1, 2, 3, 4]` word.

            # assert the correctness of the argument
            dupw push.{tx_script_args} assert_eqw.err="provided transaction arguments don't match the expected ones"
            # => [TX_SCRIPT_ARGS]

            # since we provided an advice map entry with the transaction script arguments as a key,
            # we can obtain the value of this entry
            adv.push_mapval padw adv_loadw
            # => [[map_entry_values], TX_SCRIPT_ARGS]

            # assert the correctness of the map entry values
            push.{advice_entry} assert_eqw.err="obtained advice map value doesn't match the expected one"
        end"#
    );

    let tx_script = CodeBuilder::default()
        .compile_tx_script(tx_script_src)
        .context("failed to parse transaction script")?;

    // extend the advice map with the entry that is accessed using the provided transaction script
    // argument
    let mock_tx = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .add_advice_map_entry(tx_script_args, advice_entry.as_elements().to_vec())
        .tx_script_args(tx_script_args)
        .build()?;

    mock_tx.execute().await?;

    Ok(())
}

/// Tests that `tx::get_tx_script_root` returns the root of the executed transaction script.
#[tokio::test]
async fn test_get_script_root_with_script() -> anyhow::Result<()> {
    let tx_script =
        CodeBuilder::default().compile_tx_script("@transaction_script pub proc main nop end")?;
    let expected_root = tx_script.root();

    let code = format!(
        r#"
        use miden::protocol::tx
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction

            exec.tx::get_tx_script_root
            # => [TX_SCRIPT_ROOT]

            push.{expected_root} assert_eqw.err="tx script root mismatch"
        end
        "#
    );

    let mock_tx = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .build()?;

    mock_tx.execute_code(&code).await?;

    Ok(())
}

/// Tests that `tx::get_tx_script_root` returns the empty word when no transaction script is
/// executed.
#[tokio::test]
async fn test_get_script_root_without_script() -> anyhow::Result<()> {
    let code = r#"
        use miden::protocol::tx
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction

            exec.tx::get_tx_script_root
            # => [TX_SCRIPT_ROOT]

            padw assert_eqw.err="tx script root must be zero when no script is executed"
        end
        "#;

    let mock_tx = TestTransactionBuilder::with_existing_mock_account().build()?;

    mock_tx.execute_code(code).await?;

    Ok(())
}

// Tests that advice map from the account code and transaction script gets correctly passed as
// part of the transaction advice inputs
#[tokio::test]
async fn inputs_created_correctly() -> anyhow::Result<()> {
    let account_component_masm = r#"
            adv_map A([6,7,8,9]) = [10,11,12,13]

            @account_procedure
            pub proc assert_adv_map
                # test tx script advice map
                push.[1,2,3,4]
                adv.push_mapval adv_loadw
                push.[5,6,7,8]
                assert_eqw.err="script adv map not found"
            end
        "#;
    let component_code = CodeBuilder::default()
        .compile_component_code("test::adv_map_component", account_component_masm)?;

    let component = AccountComponent::new(
        component_code.clone(),
        vec![StorageSlot::with_value(StorageSlotName::mock(0), Word::default())],
        AccountComponentMetadata::mock("test::adv_map_component"),
    )?;

    let account_code =
        AccountCode::from_components(&[IncrNonceAuthComponent.into(), component.clone()])?;

    let script = r#"
            adv_map A([1,2,3,4]) = [5,6,7,8]

            @transaction_script
            pub proc main
                call.::test::adv_map_component::assert_adv_map

                # test account code advice map
                push.[6,7,8,9]
                adv.push_mapval adv_loadw
                push.[10,11,12,13]
                assert_eqw.err="account code adv map not found"
            end
        "#;

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(component_code)?
        .compile_tx_script(script)?;

    assert!(tx_script.mast().advice_map().get(&Word::try_from([1u64, 2, 3, 4])?).is_some());
    assert!(
        account_code
            .mast()
            .advice_map()
            .get(&Word::try_from([6u64, 7, 8, 9])?)
            .is_some()
    );

    let account = Account::new_existing(
        ACCOUNT_ID_PRIVATE_SENDER.try_into()?,
        AssetVault::mock(),
        AccountStorage::mock(),
        account_code,
        Felt::new_unchecked(1u64),
    );
    let mock_tx = crate::TestTransactionBuilder::new(account).tx_script(tx_script).build()?;
    _ = mock_tx.execute().await?;

    Ok(())
}

/// Test that reexecuting a transaction with no authenticator and the advice witness from a first
/// successful execution is possible. This ensures that the signature generated in the first
/// execution is present during re-execution.
#[tokio::test]
async fn tx_can_be_reexecuted() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    // Use basic auth so the tx requires a signature for successful execution.
    let account = builder.add_existing_mock_account(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into()?,
        account.id(),
        &[FungibleAsset::mock(3)],
        NoteType::Public,
    )?;
    let chain = builder.build()?;

    let tx = chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;

    // The advice witness of the executed transaction carries the signature generated during the
    // first execution, so feeding it back in lets the re-execution authenticate without an
    // authenticator.
    let _reexecuted_tx = chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .authenticator(None)
        .extend_advice_inputs(tx.advice_witness().clone())
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Tests that creating and consuming the same note in a transaction fails.
///
/// TX: Inputs [X] -> Outputs [X]
#[tokio::test]
async fn tx_circular_note_dependency_is_rejected() -> anyhow::Result<()> {
    let asset = NonFungibleAsset::mock(&[42]);

    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet_with_assets(Auth::IncrNonce, [])?;
    let chain = builder.build()?;

    let mut rng = RandomCoin::new(Word::from([1u32; 4]));
    let note_x = create_p2any_note(account.id(), NoteType::Public, [asset], &mut rng);

    let script = SendNotesTransactionScript::new(
        &account.code_interface(),
        &[PartialNote::from(note_x.clone())],
    )?;

    // The tx script reconstructs note_x as an output note (same recipient + same asset).
    let executed_tx = chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note_x.clone())
        .send_notes_script(&script)
        .expected_output_note(RawOutputNote::Full(note_x.clone()))
        .build()?
        .execute()
        .await?;
    let error = LocalTransactionProver::default().prove_dummy(executed_tx).unwrap_err();

    assert_matches!(error, TransactionProverError::ProvenTransactionBuildFailed(
      ProvenTransactionError::NoteCreatedAndConsumed(note_id)) => {
        assert_eq!(note_id, note_x.id());
    });

    Ok(())
}

// Tests that dynamic kernel procedures cannot be invoked directly with syscall but need to be
// invoked using exec_kernel_proc.
#[tokio::test]
async fn kernel_procedures_are_not_directly_syscallable() -> anyhow::Result<()> {
    // The kernel's root module holds exec_kernel_proc only, so a syscall to a kernel procedure by
    // name does not resolve.
    let script_source = "@transaction_script pub proc main syscall.account_get_id end";
    let Err(error) = CodeBuilder::default().compile_tx_script(script_source) else {
        anyhow::bail!("syscall to a kernel procedure by name should be rejected");
    };
    assert!(error.to_string().contains("undefined item '::$kernel::account_get_id'"));

    // The kernel procedures are exported from the kernel package, but they are not part of the
    // kernel interface, so a syscall to their MAST root is rejected as well.
    let procedure_root = TransactionKernel::PROCEDURES[0];
    let script_source = format!("@transaction_script pub proc main syscall.{procedure_root} end");
    let Err(error) = CodeBuilder::default().compile_tx_script(script_source) else {
        anyhow::bail!("syscall to kernel procedure {procedure_root} should be rejected");
    };
    assert!(error.to_string().contains("is not an exported kernel procedure"));

    Ok(())
}

/// Tests that `exec_kernel_proc` rejects the first procedure offset which is out of bounds.
#[tokio::test]
async fn exec_kernel_proc_rejects_out_of_bounds_offset() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let chain = builder.build()?;

    // Procedure offsets are zero-based, so the number of kernel procedures is the smallest offset
    // which no longer refers to a kernel procedure.
    let out_of_bounds_offset = TransactionKernel::PROCEDURES.len();
    let tx_script_source = format!(
        "
        @transaction_script
        pub proc main
            # pad the stack the way the protocol library does before a syscall
            padw padw padw push.0.0.0

            push.{out_of_bounds_offset}
            syscall.exec_kernel_proc
        end
        "
    );
    let tx_script = CodeBuilder::new().compile_tx_script(&tx_script_source)?;

    let result = chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_KERNEL_PROCEDURE_OFFSET_OUT_OF_BOUNDS);

    Ok(())
}
