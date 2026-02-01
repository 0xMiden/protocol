use alloc::string::String;

use anyhow::Context;
use miden_protocol::account::Account;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::{FeltRng, RpoRandomCoin};
use miden_protocol::errors::tx_kernel::ERR_NOTE_ATTEMPT_TO_ACCESS_NOTE_METADATA_WHILE_NO_NOTE_BEING_PROCESSED;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteMetadata,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::{EMPTY_WORD, Felt, ONE, WORD_SIZE, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::mock_account::MockAccountExt;

use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::utils::create_public_p2any_note;
use crate::{
    Auth,
    MockChain,
    TransactionContextBuilder,
    TxContextInput,
    assert_transaction_executor_error,
};

#[tokio::test]
async fn test_active_note_get_sender_fails_from_tx_script() -> anyhow::Result<()> {
    // Creates a mockchain with an account and a note
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::BasicAuth)?;
    let p2id_note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[FungibleAsset::mock(150)],
        NoteType::Public,
    )?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let code = "
        use miden::protocol::active_note

        begin
            # try to get the sender from transaction script
            exec.active_note::get_sender
        end
        ";
    let tx_script = CodeBuilder::default()
        .compile_tx_script(code)
        .context("failed to parse tx script")?;

    let tx_context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[p2id_note.id()], &[])?
        .tx_script(tx_script)
        .build()?;

    let result = tx_context.execute().await;
    assert_transaction_executor_error!(
        result,
        ERR_NOTE_ATTEMPT_TO_ACCESS_NOTE_METADATA_WHILE_NO_NOTE_BEING_PROCESSED
    );

    Ok(())
}

#[tokio::test]
async fn test_active_note_get_metadata() -> anyhow::Result<()> {
    let tx_context = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let input_note = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(100)],
        );
        TransactionContextBuilder::new(account)
            .extend_input_notes(vec![input_note])
            .build()?
    };

    let code = format!(
        r#"
        use $kernel::prologue
        use $kernel::note->note_internal
        use miden::protocol::active_note

        begin
            exec.prologue::prepare_transaction
            exec.note_internal::prepare_note
            dropw dropw dropw dropw

            # get the metadata of the active note
            exec.active_note::get_metadata
            # => [NOTE_ATTACHMENT, METADATA_HEADER]

            push.{NOTE_ATTACHMENT}
            assert_eqw.err="note 0 has incorrect note attachment"
            # => [METADATA_HEADER]

            push.{METADATA_HEADER}
            assert_eqw.err="note 0 has incorrect metadata"
            # => []

            # truncate the stack
            swapw dropw
        end
        "#,
        METADATA_HEADER = tx_context.input_notes().get_note(0).note().metadata().to_header_word(),
        NOTE_ATTACHMENT =
            tx_context.input_notes().get_note(0).note().metadata().to_attachment_word()
    );

    tx_context.execute_code(&code).await?;

    Ok(())
}

#[tokio::test]
async fn test_active_note_get_sender() -> anyhow::Result<()> {
    let tx_context = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let input_note = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(100)],
        );
        TransactionContextBuilder::new(account)
            .extend_input_notes(vec![input_note])
            .build()?
    };

    // calling get_sender should return sender of the active note
    let code = "
        use $kernel::prologue
        use $kernel::note->note_internal
        use miden::protocol::active_note

        begin
            exec.prologue::prepare_transaction
            exec.note_internal::prepare_note
            dropw dropw dropw dropw
            exec.active_note::get_sender

            # truncate the stack
            swapw dropw
        end
        ";

    let exec_output = tx_context.execute_code(code).await?;

    let sender = tx_context.input_notes().get_note(0).note().metadata().sender();
    assert_eq!(exec_output.stack[0], sender.prefix().as_felt());
    assert_eq!(exec_output.stack[1], sender.suffix());

    Ok(())
}

#[tokio::test]
async fn test_active_note_get_assets() -> anyhow::Result<()> {
    // Creates a mockchain with an account and a note that it can consume
    let tx_context = {
        let mut builder = MockChain::builder();
        let account = builder.add_existing_wallet(Auth::BasicAuth)?;
        let p2id_note_1 = builder.add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[FungibleAsset::mock(150)],
            NoteType::Public,
        )?;
        let p2id_note_2 = builder.add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[FungibleAsset::mock(300)],
            NoteType::Public,
        )?;
        let mut mock_chain = builder.build()?;
        mock_chain.prove_next_block()?;

        mock_chain
            .build_tx_context(
                TxContextInput::AccountId(account.id()),
                &[],
                &[p2id_note_1, p2id_note_2],
            )?
            .build()?
    };

    let notes = tx_context.input_notes();

    const DEST_POINTER_NOTE_0: u32 = 100000000;
    const DEST_POINTER_NOTE_1: u32 = 200000000;

    fn construct_asset_assertions(note: &Note) -> String {
        let mut code = String::new();
        for asset in note.assets().iter() {
            code += &format!(
                r#"
                # assert the asset is correct
                dup padw movup.4 mem_loadw_be push.{asset} assert_eqw.err="asset mismatch" push.4 add
                "#,
                asset = Word::from(asset)
            );
        }
        code
    }

    // calling get_assets should return assets at the specified address
    let code = format!(
        r#"
        use miden::core::sys

        use $kernel::prologue
        use $kernel::note->note_internal
        use miden::protocol::active_note

        proc process_note_0
            # drop the note storage
            dropw dropw dropw dropw

            # set the destination pointer for note 0 assets
            push.{DEST_POINTER_NOTE_0}

            # get the assets
            exec.active_note::get_assets

            # assert the number of assets is correct
            eq.{note_0_num_assets} assert.err="unexpected num assets for note 0"

            # assert the pointer is returned
            dup eq.{DEST_POINTER_NOTE_0} assert.err="unexpected dest ptr for note 0"

            # asset memory assertions
            {NOTE_0_ASSET_ASSERTIONS}

            # clean pointer
            drop
        end

        proc process_note_1
            # drop the note storage
            dropw dropw dropw dropw

            # set the destination pointer for note 1 assets
            push.{DEST_POINTER_NOTE_1}

            # get the assets
            exec.active_note::get_assets

            # assert the number of assets is correct
            eq.{note_1_num_assets} assert.err="unexpected num assets for note 1"

            # assert the pointer is returned
            dup eq.{DEST_POINTER_NOTE_1} assert.err="unexpected dest ptr for note 1"

            # asset memory assertions
            {NOTE_1_ASSET_ASSERTIONS}

            # clean pointer
            drop
        end

        begin
            # prepare tx
            exec.prologue::prepare_transaction

            # prepare note 0
            exec.note_internal::prepare_note

            # process note 0
            call.process_note_0

            # increment active input note pointer
            exec.note_internal::increment_active_input_note_ptr

            # prepare note 1
            exec.note_internal::prepare_note

            # process note 1
            call.process_note_1

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#,
        note_0_num_assets = notes.get_note(0).note().assets().num_assets(),
        note_1_num_assets = notes.get_note(1).note().assets().num_assets(),
        NOTE_0_ASSET_ASSERTIONS = construct_asset_assertions(notes.get_note(0).note()),
        NOTE_1_ASSET_ASSERTIONS = construct_asset_assertions(notes.get_note(1).note()),
    );

    tx_context.execute_code(&code).await?;
    Ok(())
}

#[tokio::test]
async fn test_active_note_get_inputs() -> anyhow::Result<()> {
    // Creates a mockchain with an account and a note that it can consume
    let tx_context = {
        let mut builder = MockChain::builder();
        let account = builder.add_existing_wallet(Auth::BasicAuth)?;
        let p2id_note = builder.add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[FungibleAsset::mock(100)],
            NoteType::Public,
        )?;
        let mut mock_chain = builder.build()?;
        mock_chain.prove_next_block()?;

        mock_chain
            .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[p2id_note])?
            .build()?
    };

    fn construct_storage_assertions(note: &Note) -> String {
        let mut code = String::new();
        for storage_chunk in note.storage().items().chunks(WORD_SIZE) {
            let mut storage_word = EMPTY_WORD;
            storage_word.as_mut_slice()[..storage_chunk.len()].copy_from_slice(storage_chunk);

            code += &format!(
                r#"
                # assert the storage items are correct
                # => [dest_ptr]
                dup padw movup.4 mem_loadw_be push.{storage_word} assert_eqw.err="storage items are incorrect"
                # => [dest_ptr]

                push.4 add
                # => [dest_ptr+4]
                "#
            );
        }
        code
    }

    let note0 = tx_context.input_notes().get_note(0).note();

    let code = format!(
        r#"
        use $kernel::prologue
        use $kernel::note->note_internal
        use miden::protocol::active_note

        begin
            # => [BH, acct_id, IAH, NC]
            exec.prologue::prepare_transaction
            # => []

            exec.note_internal::prepare_note
            # => [note_script_root_ptr, NOTE_ARGS, pad(11)]

            # clean the stack
            dropw dropw dropw dropw
            # => []

            push.{NOTE_0_PTR} exec.active_note::get_storage
            # => [num_storage_items, dest_ptr]

            eq.{num_storage_items} assert.err="unexpected num_storage_items"
            # => [dest_ptr]

            dup eq.{NOTE_0_PTR} assert.err="unexpected dest ptr"
            # => [dest_ptr]

            # apply note 1 storage assertions
            {storage_assertions}
            # => [dest_ptr]

            # clear the stack
            drop
            # => []
        end
        "#,
        num_storage_items = note0.storage().num_items(),
        storage_assertions = construct_storage_assertions(note0),
        NOTE_0_PTR = 100000000,
    );

    tx_context.execute_code(&code).await?;
    Ok(())
}

/// This test checks the scenario when an input note has exactly 8 storage items, and the
/// transaction script attempts to load the storage to memory using the
/// `miden::protocol::active_note::get_inputs` procedure.
///
/// Previously this setup was leading to the incorrect number of note storage items computed during
/// the `get_inputs` procedure, see the [issue #1363](https://github.com/0xMiden/miden-base/issues/1363)
/// for more details.
#[tokio::test]
async fn test_active_note_get_exactly_8_inputs() -> anyhow::Result<()> {
    let sender_id = ACCOUNT_ID_SENDER
        .try_into()
        .context("failed to convert ACCOUNT_ID_SENDER to account ID")?;
    let target_id = ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into().context(
        "failed to convert ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE to account ID",
    )?;

    // prepare note data
    let serial_num = RpoRandomCoin::new(Word::from([4u32; 4])).draw_word();
    let tag = NoteTag::with_account_target(target_id);
    let metadata = NoteMetadata::new(sender_id, NoteType::Public, tag);
    let vault = NoteAssets::new(vec![]).context("failed to create input note assets")?;
    let note_script = CodeBuilder::default()
        .compile_note_script("begin nop end")
        .context("failed to parse note script")?;

    // create a recipient with note storage, which number divides by 8. For simplicity create 8
    // storage values
    let recipient = NoteRecipient::new(
        serial_num,
        note_script,
        NoteStorage::new(vec![
            ONE,
            Felt::new(2),
            Felt::new(3),
            Felt::new(4),
            Felt::new(5),
            Felt::new(6),
            Felt::new(7),
            Felt::new(8),
        ])
        .context("failed to create note storage")?,
    );
    let input_note = Note::new(vault.clone(), metadata, recipient);

    // provide this input note to the transaction context
    let tx_context = TransactionContextBuilder::with_existing_mock_account()
        .extend_input_notes(vec![input_note])
        .build()?;

    let tx_code = "
            use $kernel::prologue
            use miden::protocol::active_note

            begin
                exec.prologue::prepare_transaction

                # execute the `get_storage` procedure to trigger note number of storage items assertion
                push.0 exec.active_note::get_storage
                # => [num_storage_items, 0]

                # assert that the number of storage items is 8
                push.8 assert_eq.err=\"number of storage values should be equal to 8\"

                # clean the stack
                drop
            end
        ";

    tx_context.execute_code(tx_code).await.context("transaction execution failed")?;

    Ok(())
}

#[tokio::test]
async fn test_active_note_get_serial_number() -> anyhow::Result<()> {
    let tx_context = {
        let mut builder = MockChain::builder();
        let account = builder.add_existing_wallet(Auth::BasicAuth)?;
        let p2id_note_1 = builder.add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[FungibleAsset::mock(150)],
            NoteType::Public,
        )?;
        let mock_chain = builder.build()?;

        mock_chain
            .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[p2id_note_1])?
            .build()?
    };

    // calling get_serial_number should return the serial number of the active note
    let code = "
        use $kernel::prologue
        use miden::protocol::active_note

        begin
            exec.prologue::prepare_transaction
            exec.active_note::get_serial_number

            # truncate the stack
            swapw dropw
        end
        ";

    let exec_output = tx_context.execute_code(code).await?;

    let serial_number = tx_context.input_notes().get_note(0).note().serial_num();
    assert_eq!(exec_output.get_stack_word_be(0), serial_number);
    Ok(())
}

#[tokio::test]
async fn test_active_note_get_script_root() -> anyhow::Result<()> {
    let tx_context = {
        let mut builder = MockChain::builder();
        let account = builder.add_existing_wallet(Auth::BasicAuth)?;
        let p2id_note_1 = builder.add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[FungibleAsset::mock(150)],
            NoteType::Public,
        )?;
        let mock_chain = builder.build()?;

        mock_chain
            .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[p2id_note_1])?
            .build()?
    };

    // calling get_script_root should return script root of the active note
    let code = "
    use $kernel::prologue
    use miden::protocol::active_note

    begin
        exec.prologue::prepare_transaction
        exec.active_note::get_script_root

        # truncate the stack
        swapw dropw
    end
    ";

    let exec_output = tx_context.execute_code(code).await?;

    let script_root = tx_context.input_notes().get_note(0).note().script().root();
    assert_eq!(exec_output.get_stack_word_be(0), script_root);
    Ok(())
}
