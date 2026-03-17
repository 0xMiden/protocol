use alloc::sync::Arc;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountCode,
    AccountComponent,
    AccountStorage,
    AccountStorageMode,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::assembly::diagnostics::NamedSource;
use miden_protocol::asset::{Asset, AssetVault, FungibleAsset, NonFungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentContent,
    NoteAttachmentScheme,
    NoteHeader,
    NoteId,
    NoteMetadata,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
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
use miden_protocol::testing::note::DEFAULT_NOTE_CODE;
use miden_protocol::transaction::{
    InputNotes,
    RawOutputNote,
    RawOutputNotes,
    TransactionArgs,
    TransactionKernel,
    TransactionSummary,
};
use miden_protocol::{Felt, Hasher, ONE, Word};
use miden_standards::AuthMethod;
use miden_standards::account::interface::{AccountInterface, AccountInterfaceExt};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_standards::testing::account_component::IncrNonceAuthComponent;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_tx::auth::UnreachableAuth;
use miden_tx::{TransactionExecutor, TransactionExecutorError};

use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::utils::{create_public_p2any_note, create_spawn_note};
use crate::{Auth, MockChain, TransactionContextBuilder};

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
        .build_tx_context(account1.id(), &[spawn_note.id()], &[])?
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
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
    let tx_context = mock_chain.build_tx_context(account2.id(), &[], &[])?.build()?;

    let tx_executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&tx_context)
        .with_source_manager(tx_context.source_manager());

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
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let code = "
        use miden::protocol::tx
        use $kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # get the block data
            exec.tx::get_block_number
            exec.tx::get_block_timestamp
            exec.tx::get_block_commitment
            # => [BLOCK_COMMITMENT, block_timestamp, block_number]

            # truncate the stack
            swapdw dropw dropw
        end
        ";

    let exec_output = &tx_context.execute_code(code).await?;

    assert_eq!(
        exec_output.get_stack_word(0),
        tx_context.tx_inputs().block_header().commitment(),
        "top word on the stack should be equal to the block header commitment"
    );

    assert_eq!(
        exec_output.get_stack_element(4).as_canonical_u64(),
        tx_context.tx_inputs().block_header().timestamp() as u64,
        "fifth element on the stack should be equal to the timestamp of the last block creation"
    );

    assert_eq!(
        exec_output.get_stack_element(5).as_canonical_u64(),
        tx_context.tx_inputs().block_header().block_num().as_u64(),
        "sixth element on the stack should be equal to the block number"
    );
    Ok(())
}

#[tokio::test]
async fn executed_transaction_output_notes() -> anyhow::Result<()> {
    let executor_account =
        Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, IncrNonceAuthComponent);
    let account_id = executor_account.id();

    // removed assets
    let removed_asset_1 = FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT / 2);
    let removed_asset_2 = FungibleAsset::mock(FUNGIBLE_ASSET_AMOUNT / 2);

    let combined_asset = Asset::Fungible(
        FungibleAsset::new(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().expect("id is valid"),
            FUNGIBLE_ASSET_AMOUNT,
        )
        .expect("asset is valid"),
    );
    let removed_asset_3 = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA);
    let removed_asset_4 = Asset::Fungible(
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
        NoteAttachment::new_word(NoteAttachmentScheme::new(28), Word::from([2, 3, 4, 5u32]));
    let attachment3 = NoteAttachment::new_array(
        NoteAttachmentScheme::new(29),
        [6, 7, 8, 9u32].map(Felt::from).to_vec(),
    )?;

    let note_type1 = NoteType::Private;
    let note_type2 = NoteType::Public;
    let note_type3 = NoteType::Public;

    // In this test we create 3 notes. Note 1 is private, Note 2 is public and Note 3 is public
    // without assets.

    let recipient_1 = Word::from([0, 1, 2, 3u32]);

    // Create the expected output note for Note 2 which is public
    let serial_num_2 = Word::from([1, 2, 3, 4u32]);
    let note_script_2 = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_CODE)?;
    let inputs_2 = NoteStorage::new(vec![ONE])?;
    let metadata_2 = NoteMetadata::new(account_id, note_type2)
        .with_tag(tag2)
        .with_attachment(attachment2.clone());
    let vault_2 = NoteAssets::new(vec![removed_asset_3, removed_asset_4])?;
    let recipient_2 = NoteRecipient::new(serial_num_2, note_script_2, inputs_2);
    let expected_output_note_2 = Note::new(vault_2, metadata_2, recipient_2);

    // Create the expected output note for Note 3 which is public
    let serial_num_3 = Word::from([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);
    let note_script_3 = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_CODE)?;
    let inputs_3 = NoteStorage::new(vec![ONE, Felt::new(2)])?;
    let metadata_3 = NoteMetadata::new(account_id, note_type3)
        .with_tag(tag3)
        .with_attachment(attachment3.clone());
    let vault_3 = NoteAssets::new(vec![])?;
    let recipient_3 = NoteRecipient::new(serial_num_3, note_script_3, inputs_3);
    let expected_output_note_3 = Note::new(vault_3, metadata_3, recipient_3);

    let tx_script_src = format!(
        "\
        use miden::standards::wallets::basic->wallet
        use miden::protocol::output_note
        use mock::util

        ## TRANSACTION SCRIPT
        ## ========================================================================================
        begin
            ## Send some assets from the account vault
            ## ------------------------------------------------------------------------------------
            # partially deplete fungible asset balance
            push.{recipient_1}                  # recipient
            push.{NOTETYPE1}                    # note_type
            push.{tag1}                         # tag
            exec.output_note::create
            # => [note_idx = 0]

            dup
            push.{REMOVED_ASSET_VALUE_1}
            push.{REMOVED_ASSET_KEY_1}
            # => [ASSET_KEY, ASSET_VALUE, note_idx, note_idx]

            exec.util::move_asset_to_note
            # => [note_idx]

            push.{REMOVED_ASSET_VALUE_2}
            push.{REMOVED_ASSET_KEY_2}
            exec.util::move_asset_to_note
            # => []

            # send non-fungible asset
            push.{RECIPIENT2}                   # recipient
            push.{NOTETYPE2}                    # note_type
            push.{tag2}                         # tag
            exec.output_note::create
            # => [note_idx = 1]

            dup
            push.{REMOVED_ASSET_VALUE_3}
            push.{REMOVED_ASSET_KEY_3}
            exec.util::move_asset_to_note
            # => [note_idx]

            dup
            push.{REMOVED_ASSET_VALUE_4}
            push.{REMOVED_ASSET_KEY_4}
            exec.util::move_asset_to_note
            # => [note_idx]

            push.{ATTACHMENT2}
            push.{attachment_scheme2}
            movup.5
            exec.output_note::set_word_attachment
            # => []

            # create a public note without assets
            push.{RECIPIENT3}                   # recipient
            push.{NOTETYPE3}                    # note_type
            push.{tag3}                         # tag
            exec.output_note::create
            # => [note_idx = 2]

            push.{ATTACHMENT3}
            push.{attachment_scheme3}
            movup.5
            exec.output_note::set_array_attachment
            # => []
        end
    ",
        REMOVED_ASSET_KEY_1 = removed_asset_1.to_key_word(),
        REMOVED_ASSET_VALUE_1 = removed_asset_1.to_value_word(),
        REMOVED_ASSET_KEY_2 = removed_asset_2.to_key_word(),
        REMOVED_ASSET_VALUE_2 = removed_asset_2.to_value_word(),
        REMOVED_ASSET_KEY_3 = removed_asset_3.to_key_word(),
        REMOVED_ASSET_VALUE_3 = removed_asset_3.to_value_word(),
        REMOVED_ASSET_KEY_4 = removed_asset_4.to_key_word(),
        REMOVED_ASSET_VALUE_4 = removed_asset_4.to_value_word(),
        RECIPIENT2 = expected_output_note_2.recipient().digest(),
        RECIPIENT3 = expected_output_note_3.recipient().digest(),
        NOTETYPE1 = note_type1 as u8,
        NOTETYPE2 = note_type2 as u8,
        NOTETYPE3 = note_type3 as u8,
        attachment_scheme2 = attachment2.attachment_scheme().as_u32(),
        ATTACHMENT2 = attachment2.content().to_word(),
        attachment_scheme3 = attachment3.attachment_scheme().as_u32(),
        ATTACHMENT3 = attachment3.content().to_word(),
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_src)?;

    // expected delta
    // --------------------------------------------------------------------------------------------
    // execute the transaction and get the witness

    let NoteAttachmentContent::Array(array) = attachment3.content() else {
        panic!("expected array attachment");
    };

    let tx_context = TransactionContextBuilder::new(executor_account)
        .tx_script(tx_script)
        .extend_advice_map(vec![(attachment3.content().to_word(), array.as_slice().to_vec())])
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(expected_output_note_2.clone()),
            RawOutputNote::Full(expected_output_note_3.clone()),
        ])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // output notes
    // --------------------------------------------------------------------------------------------
    let output_notes = executed_transaction.output_notes();

    // check the total number of notes
    assert_eq!(output_notes.num_notes(), 3);

    // assert that the expected output note 1 is present
    let resulting_output_note_1 = executed_transaction.output_notes().get_note(0);

    let expected_note_assets_1 = NoteAssets::new(vec![combined_asset])?;
    let expected_note_id_1 = NoteId::new(recipient_1, expected_note_assets_1.commitment());
    assert_eq!(resulting_output_note_1.id(), expected_note_id_1);

    // assert that the expected output note 2 is present
    let resulting_output_note_2 = executed_transaction.output_notes().get_note(1);

    let expected_note_id_2 = expected_output_note_2.id();
    let expected_note_metadata_2 = expected_output_note_2.metadata().clone();
    assert_eq!(
        *resulting_output_note_2.header(),
        NoteHeader::new(expected_note_id_2, expected_note_metadata_2)
    );

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
      use miden::protocol::tx
      const AUTH_UNAUTHORIZED_EVENT=event("miden::protocol::auth::unauthorized")
      #! Inputs:  [AUTH_ARGS, pad(12)]
      #! Outputs: [pad(16)]
      @auth_script
      pub proc auth_abort_tx
          dropw
          # => [pad(16)]

          exec.::miden::protocol::native_account::incr_nonce
          exec.tx::get_block_number
          push.0.0
          # => [[0, 0, block_num, final_nonce], pad(16)]
          # => [SALT, pad(16)]

          exec.auth::create_tx_summary
          # => [ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, SALT]

          # insert tx summary into advice provider for extraction by the host
          adv.insert_hqword
          # => [ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, SALT]

          exec.auth::hash_tx_summary
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
        .storage_mode(AccountStorageMode::Private)
        .with_auth_component(auth_component)
        .with_component(BasicWallet)
        .build_existing()
        .context("failed to build account")?;

    // Consume and create a note so the input and outputs notes commitment is not the empty word.
    let mut rng = RandomCoin::new(Word::empty());
    let output_note = P2idNote::create(
        account.id(),
        account.id(),
        vec![],
        NoteType::Private,
        NoteAttachment::default(),
        &mut rng,
    )?;
    let input_note = create_spawn_note(vec![&output_note])?;

    let mut builder = MockChain::builder();
    builder.add_output_note(RawOutputNote::Full(input_note.clone()));
    let mock_chain = builder.build()?;

    let tx_context = mock_chain.build_tx_context(account, &[input_note.id()], &[])?.build()?;
    let ref_block_num = tx_context.tx_inputs().block_header().block_num().as_u32();
    let final_nonce = tx_context.account().nonce().as_canonical_u64() as u32 + 1;
    let input_notes = tx_context.input_notes().clone();
    let output_notes = RawOutputNotes::new(vec![RawOutputNote::Partial(output_note.into())])?;

    let error = tx_context.execute().await.unwrap_err();

    assert_matches!(error, TransactionExecutorError::Unauthorized(tx_summary) => {
        assert!(tx_summary.account_delta().vault().is_empty());
        assert!(tx_summary.account_delta().storage().is_empty());
        assert_eq!(tx_summary.account_delta().nonce_delta().as_canonical_u64(), 1);
        assert_eq!(tx_summary.input_notes(), &input_notes);
        assert_eq!(tx_summary.output_notes(), &output_notes);
        assert_eq!(tx_summary.salt(), Word::from(
          [0, 0, ref_block_num, final_nonce]
        ));
    });

    Ok(())
}

/// Tests that a transaction consuming and creating one note with basic authentication correctly
/// signs the transaction summary.
#[tokio::test]
async fn tx_summary_commitment_is_signed_by_falcon_auth() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mut rng = RandomCoin::new(Word::empty());
    let p2id_note = P2idNote::create(
        account.id(),
        account.id(),
        vec![],
        NoteType::Private,
        NoteAttachment::default(),
        &mut rng,
    )?;
    let spawn_note = builder.add_spawn_note([&p2id_note])?;
    let chain = builder.build()?;

    let tx = chain
        .build_tx_context(account.id(), &[spawn_note.id()], &[])?
        .build()?
        .execute()
        .await?;

    let summary = TransactionSummary::new(
        tx.account_delta().clone(),
        tx.input_notes().clone(),
        tx.output_notes().clone(),
        Word::from([
            0,
            0,
            tx.block_header().block_num().as_u32(),
            tx.final_account().nonce().as_canonical_u64() as u32,
        ]),
    );
    let summary_commitment = summary.to_commitment();

    let account_interface = AccountInterface::from_account(&account);
    let pub_key = match account_interface.auth().first().unwrap() {
        AuthMethod::SingleSig { approver: (pub_key, _) } => pub_key,
        AuthMethod::NoAuth => panic!("Expected SingleSig auth scheme, got NoAuth"),
        AuthMethod::Multisig { .. } => {
            panic!("Expected SingleSig auth scheme, got Multisig")
        },
        AuthMethod::Unknown => panic!("Expected SingleSig auth scheme, got Unknown"),
    };

    // This is in an internal detail of the tx executor host, but this is the easiest way to check
    // for the presence of the signature in the advice map.
    let signature_key = Hasher::merge(&[Word::from(*pub_key), summary_commitment]);

    // The summary commitment should have been signed as part of transaction execution and inserted
    // into the advice map.
    tx.advice_witness().map.get(&signature_key).unwrap();

    Ok(())
}

/// Tests that a transaction consuming and creating one note with EcdsaK256Keccak authentication
/// correctly signs the transaction summary.
#[tokio::test]
async fn tx_summary_commitment_is_signed_by_ecdsa_auth() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_mock_account(Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak })?;
    let mut rng = RandomCoin::new(Word::empty());
    let p2id_note = P2idNote::create(
        account.id(),
        account.id(),
        vec![],
        NoteType::Private,
        NoteAttachment::default(),
        &mut rng,
    )?;
    let spawn_note = builder.add_spawn_note([&p2id_note])?;
    let chain = builder.build()?;

    let tx = chain
        .build_tx_context(account.id(), &[spawn_note.id()], &[])?
        .build()?
        .execute()
        .await?;

    let summary = TransactionSummary::new(
        tx.account_delta().clone(),
        tx.input_notes().clone(),
        tx.output_notes().clone(),
        Word::from([
            0,
            0,
            tx.block_header().block_num().as_u32(),
            tx.final_account().nonce().as_canonical_u64() as u32,
        ]),
    );
    let summary_commitment = summary.to_commitment();

    let account_interface = AccountInterface::from_account(&account);
    let pub_key = match account_interface.auth().first().unwrap() {
        AuthMethod::SingleSig { approver: (pub_key, _) } => pub_key,
        AuthMethod::NoAuth => panic!("Expected SingleSig auth scheme, got NoAuth"),
        AuthMethod::Multisig { .. } => {
            panic!("Expected SingleSig auth scheme, got Multisig")
        },
        AuthMethod::Unknown => panic!("Expected SingleSig auth scheme, got Unknown"),
    };

    // This is in an internal detail of the tx executor host, but this is the easiest way to check
    // for the presence of the signature in the advice map.
    let signature_key = Hasher::merge(&[Word::from(*pub_key), summary_commitment]);

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

    let source = NamedSource::new("test::module_1", test_module_source);
    let source_manager = Arc::new(DefaultSourceManager::default());
    let assembler = TransactionKernel::assembler_with_source_manager(source_manager.clone());

    let library = assembler.assemble_library([source]).unwrap();

    let source = "
    use test::module_1
    use miden::core::sys

    begin
        push.1.2
        call.module_1::foo
        exec.sys::truncate_stack
    end
    ";

    let tx_script = CodeBuilder::new()
        .with_statically_linked_library(&library)?
        .compile_tx_script(source)?;
    let tx_context = TransactionContextBuilder::with_existing_mock_account()
        .with_source_manager(source_manager.clone())
        .tx_script(tx_script.clone())
        .build()?;
    let account_id = tx_context.account().id();
    let block_ref = tx_context.tx_inputs().block_header().block_num();
    let advice_inputs = tx_context.tx_args().advice_inputs().clone();

    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&tx_context)
        .with_source_manager(source_manager);

    let stack_outputs = executor
        .execute_tx_view_script(account_id, block_ref, tx_script, advice_inputs)
        .await?;

    assert_eq!(stack_outputs[..3], [Felt::new(7), Felt::new(2), ONE]);

    Ok(())
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
        begin
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

    let tx_context = TransactionContextBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .extend_advice_map([(tx_script_input_key, tx_script_input_value.to_vec())])
        .build()?;

    tx_context.execute().await.context("failed to execute transaction")?;

    Ok(())
}

/// Tests transaction script arguments.
#[tokio::test]
async fn test_tx_script_args() -> anyhow::Result<()> {
    let tx_script_args = Word::from([1, 2, 3, 4u32]);
    let advice_entry = Word::from([5, 6, 7, 8u32]);

    let tx_script_src = format!(
        r#"
        begin
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
    let tx_context = TransactionContextBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .extend_advice_map([(tx_script_args, advice_entry.as_elements().to_vec())])
        .tx_script_args(tx_script_args)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

// Tests that advice map from the account code and transaction script gets correctly passed as
// part of the transaction advice inputs
#[tokio::test]
async fn inputs_created_correctly() -> anyhow::Result<()> {
    let account_component_masm = r#"
            adv_map A([6,7,8,9]) = [10,11,12,13]

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

    let account_code = AccountCode::from_components(
        &[IncrNonceAuthComponent.into(), component.clone()],
        AccountType::RegularAccountUpdatableCode,
    )?;

    let script = r#"
            adv_map A([1,2,3,4]) = [5,6,7,8]

            begin
                call.::test::adv_map_component::assert_adv_map

                # test account code advice map
                push.[6,7,8,9]
                adv.push_mapval adv_loadw
                push.[10,11,12,13]
                assert_eqw.err="account code adv map not found"
            end
        "#;

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(component_code.as_library())?
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
        Felt::new(1u64),
    );
    let tx_context = crate::TransactionContextBuilder::new(account).tx_script(tx_script).build()?;
    _ = tx_context.execute().await?;

    Ok(())
}

/// Test that reexecuting a transaction with no authenticator and the tx inputs from a first
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
        .build_tx_context(account.id(), &[note.id()], &[])?
        .build()?
        .execute()
        .await?;

    let _reexecuted_tx = chain
        .build_tx_context(account.id(), &[note.id()], &[])?
        .authenticator(None)
        .tx_inputs(tx.tx_inputs().clone())
        .build()?
        .execute()
        .await?;

    Ok(())
}
