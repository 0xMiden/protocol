use alloc::string::String;

use anyhow::Context;
use miden_protocol::account::Account;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::errors::tx_kernel::ERR_NOTE_ATTEMPT_TO_ACCESS_NOTE_METADATA_WHILE_NO_NOTE_BEING_PROCESSED;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentScheme,
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
use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;
use miden_protocol::transaction::memory::{ASSET_SIZE, ASSET_VALUE_OFFSET};
use miden_protocol::{EMPTY_WORD, Felt, ONE, WORD_SIZE, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::testing::note::NoteBuilder;
use rstest::rstest;

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
    let account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
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
            # => [METADATA_HEADER]

            push.{METADATA_HEADER}
            assert_eqw.err="note 0 has incorrect metadata"
            # => []

            # truncate the stack
            swapw dropw
        end
        "#,
        METADATA_HEADER =
            tx_context.input_notes().get_note(0).note().metadata_header().to_metadata_word(),
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
    assert_eq!(exec_output.get_stack_element(0), sender.suffix());
    assert_eq!(exec_output.get_stack_element(1), sender.prefix().as_felt());

    Ok(())
}

#[rstest::rstest]
#[case(NoteType::Public)]
#[case(NoteType::Private)]
#[tokio::test]
async fn test_active_note_get_note_type(#[case] note_type: NoteType) -> anyhow::Result<()> {
    let tx_context = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let mut rng = miden_protocol::crypto::rand::RandomCoin::new(Word::default());
        let input_note = crate::utils::create_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            note_type,
            [FungibleAsset::mock(100)],
            &mut rng,
        );
        TransactionContextBuilder::new(account)
            .extend_input_notes(vec![input_note])
            .build()?
    };

    let code = "
        use $kernel::prologue
        use $kernel::note->note_internal
        use miden::protocol::active_note
        use miden::protocol::note

        begin
            exec.prologue::prepare_transaction
            exec.note_internal::prepare_note
            dropw dropw dropw dropw

            exec.active_note::get_metadata
            # => [METADATA_HEADER]

            exec.note::metadata_into_note_type
            # => [note_type]

            # truncate the stack
            swapw dropw
        end
        ";

    let exec_output = tx_context.execute_code(code).await?;

    let actual_note_type = NoteType::try_from(exec_output.get_stack_element(0))
        .expect("stack element should be a valid note type");
    assert_eq!(actual_note_type, note_type);

    Ok(())
}

#[tokio::test]
async fn test_active_note_get_assets() -> anyhow::Result<()> {
    // Creates a mockchain with an account and a note that it can consume
    let tx_context = {
        let mut builder = MockChain::builder();
        let account = builder.add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })?;
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
                dup padw movup.4 mem_loadw_le push.{ASSET_KEY}
                assert_eqw.err="asset key mismatch"

                dup padw movup.4 add.{ASSET_VALUE_OFFSET} mem_loadw_le push.{ASSET_VALUE}
                assert_eqw.err="asset value mismatch"

                add.{ASSET_SIZE}
                "#,
                ASSET_KEY = asset.to_key_word(),
                ASSET_VALUE = asset.to_value_word(),
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

            # push the dest pointer for asset assertions
            push.{DEST_POINTER_NOTE_0}

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

            # push the dest pointer for asset assertions
            push.{DEST_POINTER_NOTE_1}

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
async fn test_active_note_get_storage() -> anyhow::Result<()> {
    // Creates a mockchain with an account and a note that it can consume
    let tx_context = {
        let mut builder = MockChain::builder();
        let account = builder.add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })?;
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
                dup padw movup.4 mem_loadw_le push.{storage_word} assert_eqw.err="storage items are incorrect"
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
            # => [num_storage_items]

            eq.{num_storage_items} assert.err="unexpected num_storage_items"
            # => []

            # push the dest pointer for storage assertions
            push.{NOTE_0_PTR}
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
/// the `get_inputs` procedure, see the [issue #1363](https://github.com/0xMiden/protocol/issues/1363)
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
    let serial_num = RandomCoin::new(Word::from([4u32; 4])).draw_word();
    let tag = NoteTag::with_account_target(target_id);
    let metadata = NoteMetadata::new(sender_id, NoteType::Public).with_tag(tag);
    let vault = NoteAssets::new(vec![]).context("failed to create input note assets")?;
    let note_script = CodeBuilder::default()
        .compile_note_script(DEFAULT_NOTE_SCRIPT)
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
        let account = builder.add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })?;
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
    assert_eq!(exec_output.get_stack_word(0), serial_number);
    Ok(())
}

#[tokio::test]
async fn test_active_note_get_script_root() -> anyhow::Result<()> {
    let tx_context = {
        let mut builder = MockChain::builder();
        let account = builder.add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })?;
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
    assert_eq!(exec_output.get_stack_word(0), script_root.into());
    Ok(())
}

/// Tests `{input_note, active_note}::find_attachment` for both the found and not-found cases.
///
/// Setup: create an input note with two word attachments (schemes 10 and 20), then call
/// `find_attachment` on the active/input note.
///
/// - `found`:     search for scheme 10 → is_found=1, attachment data is returned.
/// - `not_found`: search for scheme 99 → is_found=0, ptr=0, num_words=0.
#[rstest]
#[case::active_note_scheme_found(None, "active_note", 10, true)]
#[case::active_note_scheme_not_found(None, "active_note", 99, false)]
// uses note index 1
#[case::input_note_scheme_found(Some(1), "input_note", 10, true)]
// uses note index 1
#[case::input_note_scheme_not_found(Some(1), "input_note", 99, false)]
#[tokio::test]
async fn test_note_find_attachment(
    #[case] note_idx: Option<u8>,
    #[case] module_under_test: &str,
    #[case] search_scheme: u16,
    #[case] expected_found: bool,
) -> anyhow::Result<()> {
    let tx_context = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);

        let word_0 = Word::from([3, 4, 5, 6u32]);
        let word_1 = Word::from([7, 8, 9, 10u32]);
        let scheme_0 = NoteAttachmentScheme::new(10)?;
        let scheme_1 = NoteAttachmentScheme::new(20)?;

        let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
        // Add a random first note so we test with note_index != 0.
        let input_note0 = NoteBuilder::new(account.id(), &mut rng).build()?;
        let input_note1 = NoteBuilder::new(account.id(), &mut rng)
            .note_type(NoteType::Public)
            .attachment(NoteAttachment::new_word(scheme_0, word_0))
            .attachment(NoteAttachment::new_word(scheme_1, word_1))
            .build()?;

        TransactionContextBuilder::new(account)
            .extend_input_notes(vec![input_note0, input_note1])
            .build()?
    };
    assert_eq!(tx_context.tx_inputs().input_notes().num_notes(), 2);

    let word_0 = Word::from([3, 4, 5, 6u32]);

    let push_note_index = match note_idx {
        Some(idx) => format!("push.{idx}"),
        // for active_note module, we don't need to push anything
        None => "".into(),
    };

    let code = format!(
        r#"
        use $kernel::prologue
        use $kernel::note->note_internal
        use miden::protocol::active_note
        use miden::protocol::input_note

        begin
            exec.prologue::prepare_transaction
            exec.note_internal::increment_active_input_note_ptr drop
            # prepare note 1
            exec.note_internal::prepare_note
            dropw dropw dropw dropw

            # push note index, if any
            {push_note_index}
            # search for the target scheme on the active note
            push.{search_scheme}
            # => [attachment_scheme]
            exec.{module_under_test}::find_attachment
            # => [is_found, num_words, attachment_ptr]

            # assert is_found matches expectation
            push.{expected_found}
            assert_eq.err="is_found mismatch"
            # => [num_words, attachment_ptr]

            push.{expected_found}
            if.true
                # found path: verify num_words == 1 (word attachment)
                eq.1 assert.err="expected num_words=1"
                # => [attachment_ptr]

                # read the word from memory and assert it matches
                padw movup.4 mem_loadw_le
                # => [ATTACHMENT_WORD]

                push.{EXPECTED_WORD}
                assert_eqw.err="attachment data mismatch"
                # => []
            else
                # not-found path: verify num_words=0 and ptr=0
                eq.0 assert.err="expected num_words=0"
                eq.0 assert.err="expected attachment_ptr=0"
                # => []
            end

            # truncate the stack
            swapw dropw
        end
        "#,
        expected_found = expected_found as u8,
        EXPECTED_WORD = word_0,
    );

    tx_context.execute_code(&code).await?;

    Ok(())
}
