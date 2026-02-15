use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Context;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::crypto::rand::RpoRandomCoin;
use miden_protocol::errors::tx_kernel::{
    ERR_NON_FUNGIBLE_ASSET_ALREADY_EXISTS,
    ERR_TX_NUMBER_OF_OUTPUT_NOTES_EXCEEDS_LIMIT,
};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteExecutionHint,
    NoteExecutionMode,
    NoteInputs,
    NoteMetadata,
    NoteRecipient,
    NoteTag,
    NoteType,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_NETWORK_NON_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::testing::constants::NON_FUNGIBLE_ASSET_DATA_2;
use miden_protocol::transaction::memory::{
    NOTE_MEM_SIZE,
    NUM_OUTPUT_NOTES_PTR,
    OUTPUT_NOTE_ASSETS_OFFSET,
    OUTPUT_NOTE_METADATA_OFFSET,
    OUTPUT_NOTE_RECIPIENT_OFFSET,
    OUTPUT_NOTE_SECTION_OFFSET,
};
use miden_protocol::transaction::{OutputNote, OutputNotes};
use miden_protocol::{Felt, Word, ZERO};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::create_p2id_note;
use miden_standards::testing::mock_account::MockAccountExt;

use super::{TestSetup, setup_test};
use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::utils::create_public_p2any_note;
use crate::{Auth, MockChain, TransactionContextBuilder, assert_execution_error};

#[tokio::test]
async fn test_create_note() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let account_id = tx_context.account().id();

    let recipient = Word::from([0, 1, 2, 3u32]);
    let aux = Felt::new(27);
    let tag = NoteTag::from_account_id(account_id);

    let code = format!(
        "
        use miden::protocol::output_note

        use $kernel::prologue

        begin
            exec.prologue::prepare_transaction

            push.{recipient}
            push.{note_execution_hint}
            push.{PUBLIC_NOTE}
            push.{aux}
            push.{tag}

            call.output_note::create

            # truncate the stack
            swapdw dropw dropw
        end
        ",
        recipient = recipient,
        PUBLIC_NOTE = NoteType::Public as u8,
        note_execution_hint = Felt::from(NoteExecutionHint::after_block(23.into()).unwrap()),
        tag = tag,
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_kernel_mem_word(NUM_OUTPUT_NOTES_PTR),
        Word::from([1, 0, 0, 0u32]),
        "number of output notes must increment by 1",
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(OUTPUT_NOTE_SECTION_OFFSET + OUTPUT_NOTE_RECIPIENT_OFFSET),
        recipient,
        "recipient must be stored at the correct memory location",
    );

    let expected_note_metadata: Word = NoteMetadata::new(
        account_id,
        NoteType::Public,
        tag,
        NoteExecutionHint::after_block(23.into())?,
        Felt::new(27),
    )?
    .into();

    assert_eq!(
        exec_output.get_kernel_mem_word(OUTPUT_NOTE_SECTION_OFFSET + OUTPUT_NOTE_METADATA_OFFSET),
        expected_note_metadata,
        "metadata must be stored at the correct memory location",
    );

    assert_eq!(
        exec_output.get_stack_element(0),
        ZERO,
        "top item on the stack is the index of the output note"
    );
    Ok(())
}

#[tokio::test]
async fn test_create_note_with_invalid_tag() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let invalid_tag = Felt::new((NoteType::Public as u64) << 62);
    let valid_tag: Felt = NoteTag::for_local_use_case(0, 0).unwrap().into();

    // Test invalid tag
    assert!(tx_context.execute_code(&note_creation_script(invalid_tag)).await.is_err());

    // Test valid tag
    assert!(tx_context.execute_code(&note_creation_script(valid_tag)).await.is_ok());

    Ok(())
}

fn note_creation_script(tag: Felt) -> String {
    format!(
        "
            use miden::protocol::output_note
            use $kernel::prologue

            begin
                exec.prologue::prepare_transaction

                push.{recipient}
                push.{execution_hint_always}
                push.{PUBLIC_NOTE}
                push.{aux}
                push.{tag}

                call.output_note::create

                # clean the stack
                dropw dropw
            end
            ",
        recipient = Word::from([0, 1, 2, 3u32]),
        execution_hint_always = Felt::from(NoteExecutionHint::always()),
        PUBLIC_NOTE = NoteType::Public as u8,
        aux = ZERO,
    )
}

#[tokio::test]
async fn test_create_note_too_many_notes() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let code = format!(
        "
        use miden::protocol::output_note
        use $kernel::constants::MAX_OUTPUT_NOTES_PER_TX
        use $kernel::memory
        use $kernel::prologue

        begin
            push.MAX_OUTPUT_NOTES_PER_TX
            exec.memory::set_num_output_notes
            exec.prologue::prepare_transaction

            push.{recipient}
            push.{execution_hint_always}
            push.{PUBLIC_NOTE}
            push.{aux}
            push.{tag}

            call.output_note::create
        end
        ",
        tag = NoteTag::for_local_use_case(1234, 5678).unwrap(),
        recipient = Word::from([0, 1, 2, 3u32]),
        execution_hint_always = Felt::from(NoteExecutionHint::always()),
        PUBLIC_NOTE = NoteType::Public as u8,
        aux = ZERO,
    );

    let exec_output = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_TX_NUMBER_OF_OUTPUT_NOTES_EXCEEDS_LIMIT);
    Ok(())
}

#[tokio::test]
async fn test_get_output_notes_commitment() -> anyhow::Result<()> {
    let tx_context = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);

        let output_note_1 =
            create_public_p2any_note(ACCOUNT_ID_SENDER.try_into()?, [FungibleAsset::mock(100)]);

        let input_note_1 = create_public_p2any_note(
            ACCOUNT_ID_PRIVATE_SENDER.try_into()?,
            [FungibleAsset::mock(100)],
        );

        let input_note_2 = create_public_p2any_note(
            ACCOUNT_ID_PRIVATE_SENDER.try_into()?,
            [FungibleAsset::mock(200)],
        );

        TransactionContextBuilder::new(account)
            .extend_input_notes(vec![input_note_1, input_note_2])
            .extend_expected_output_notes(vec![OutputNote::Full(output_note_1)])
            .build()?
    };

    // extract input note data
    let input_note_1 = tx_context.tx_inputs().input_notes().get_note(0).note();
    let input_asset_1 = **input_note_1
        .assets()
        .iter()
        .take(1)
        .collect::<Vec<_>>()
        .first()
        .context("getting first expected input asset")?;
    let input_note_2 = tx_context.tx_inputs().input_notes().get_note(1).note();
    let input_asset_2 = **input_note_2
        .assets()
        .iter()
        .take(1)
        .collect::<Vec<_>>()
        .first()
        .context("getting second expected input asset")?;

    // Choose random accounts as the target for the note tag.
    let network_account = AccountId::try_from(ACCOUNT_ID_NETWORK_NON_FUNGIBLE_FAUCET)?;
    let local_account = AccountId::try_from(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET)?;

    // create output note 1
    let output_serial_no_1 = Word::from([8u32; 4]);
    let output_tag_1 = NoteTag::from_account_id(network_account);
    let assets = NoteAssets::new(vec![input_asset_1])?;
    let metadata = NoteMetadata::new(
        tx_context.tx_inputs().account().id(),
        NoteType::Public,
        output_tag_1,
        NoteExecutionHint::Always,
        ZERO,
    )?;
    let inputs = NoteInputs::new(vec![])?;
    let recipient = NoteRecipient::new(output_serial_no_1, input_note_1.script().clone(), inputs);
    let output_note_1 = Note::new(assets, metadata, recipient);

    // create output note 2
    let output_serial_no_2 = Word::from([11u32; 4]);
    let output_tag_2 = NoteTag::from_account_id(local_account);
    let assets = NoteAssets::new(vec![input_asset_2])?;
    let metadata = NoteMetadata::new(
        tx_context.tx_inputs().account().id(),
        NoteType::Public,
        output_tag_2,
        NoteExecutionHint::after_block(123.into())?,
        ZERO,
    )?;
    let inputs = NoteInputs::new(vec![])?;
    let recipient = NoteRecipient::new(output_serial_no_2, input_note_2.script().clone(), inputs);
    let output_note_2 = Note::new(assets, metadata, recipient);

    // compute expected output notes commitment
    let expected_output_notes_commitment = OutputNotes::new(vec![
        OutputNote::Full(output_note_1.clone()),
        OutputNote::Full(output_note_2.clone()),
    ])?
    .commitment();

    let code = format!(
        "
        use miden::core::sys

        use miden::protocol::tx
        use miden::protocol::output_note

        use $kernel::prologue

        begin
            # => [BH, acct_id, IAH, NC]
            exec.prologue::prepare_transaction
            # => []

            # create output note 1
            push.{recipient_1}
            push.{NOTE_EXECUTION_HINT_1}
            push.{PUBLIC_NOTE}
            push.{aux_1}
            push.{tag_1}
            call.output_note::create
            # => [note_idx]

            push.{asset_1}
            call.output_note::add_asset
            # => []

            # create output note 2
            push.{recipient_2}
            push.{NOTE_EXECUTION_HINT_2}
            push.{PUBLIC_NOTE}
            push.{aux_2}
            push.{tag_2}
            call.output_note::create
            # => [note_idx]

            push.{asset_2}
            call.output_note::add_asset
            # => []

            # compute the output notes commitment
            exec.tx::get_output_notes_commitment
            # => [OUTPUT_NOTES_COMMITMENT]

            # truncate the stack
            exec.sys::truncate_stack
            # => [OUTPUT_NOTES_COMMITMENT]
        end
        ",
        PUBLIC_NOTE = NoteType::Public as u8,
        NOTE_EXECUTION_HINT_1 = Felt::from(output_note_1.metadata().execution_hint()),
        recipient_1 = output_note_1.recipient().digest(),
        tag_1 = output_note_1.metadata().tag(),
        aux_1 = output_note_1.metadata().aux(),
        asset_1 = Word::from(
            **output_note_1.assets().iter().take(1).collect::<Vec<_>>().first().unwrap()
        ),
        recipient_2 = output_note_2.recipient().digest(),
        NOTE_EXECUTION_HINT_2 = Felt::from(output_note_2.metadata().execution_hint()),
        tag_2 = output_note_2.metadata().tag(),
        aux_2 = output_note_2.metadata().aux(),
        asset_2 = Word::from(
            **output_note_2.assets().iter().take(1).collect::<Vec<_>>().first().unwrap()
        ),
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_kernel_mem_word(NUM_OUTPUT_NOTES_PTR),
        Word::from([2u32, 0, 0, 0]),
        "The test creates two notes",
    );
    assert_eq!(
        NoteMetadata::try_from(
            exec_output
                .get_kernel_mem_word(OUTPUT_NOTE_SECTION_OFFSET + OUTPUT_NOTE_METADATA_OFFSET)
        )
        .unwrap(),
        *output_note_1.metadata(),
        "Validate the output note 1 metadata",
    );
    assert_eq!(
        NoteMetadata::try_from(exec_output.get_kernel_mem_word(
            OUTPUT_NOTE_SECTION_OFFSET + OUTPUT_NOTE_METADATA_OFFSET + NOTE_MEM_SIZE
        ))
        .unwrap(),
        *output_note_2.metadata(),
        "Validate the output note 1 metadata",
    );

    assert_eq!(exec_output.get_stack_word_le(0), expected_output_notes_commitment);
    Ok(())
}

#[tokio::test]
async fn test_create_note_and_add_asset() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
    let recipient = Word::from([0, 1, 2, 3u32]);
    let aux = Felt::new(27);
    let tag = NoteTag::from_account_id(faucet_id);
    let asset = Word::from(FungibleAsset::new(faucet_id, 10)?);

    let code = format!(
        "
        use miden::protocol::output_note

        use $kernel::prologue

        begin
            exec.prologue::prepare_transaction

            push.{recipient}
            push.{NOTE_EXECUTION_HINT}
            push.{PUBLIC_NOTE}
            push.{aux}
            push.{tag}

            call.output_note::create
            # => [note_idx]

            # assert that the index of the created note equals zero
            dup assertz.err=\"index of the created note should be zero\"
            # => [note_idx]

            push.{asset}
            # => [ASSET, note_idx]

            call.output_note::add_asset
            # => []

            # truncate the stack
            dropw dropw dropw
        end
        ",
        recipient = recipient,
        PUBLIC_NOTE = NoteType::Public as u8,
        NOTE_EXECUTION_HINT = Felt::from(NoteExecutionHint::always()),
        tag = tag,
        asset = asset,
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_kernel_mem_word(OUTPUT_NOTE_SECTION_OFFSET + OUTPUT_NOTE_ASSETS_OFFSET),
        asset,
        "asset must be stored at the correct memory location",
    );

    Ok(())
}

#[tokio::test]
async fn test_create_note_and_add_multiple_assets() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
    let faucet_2 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2)?;

    let recipient = Word::from([0, 1, 2, 3u32]);
    let aux = Felt::new(27);
    let tag = NoteTag::from_account_id(faucet_2);

    let asset = Word::from(FungibleAsset::new(faucet, 10)?);
    let asset_2 = Word::from(FungibleAsset::new(faucet_2, 20)?);
    let asset_3 = Word::from(FungibleAsset::new(faucet_2, 30)?);
    let asset_2_and_3 = Word::from(FungibleAsset::new(faucet_2, 50)?);

    let non_fungible_asset = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA_2);
    let non_fungible_asset_encoded = Word::from(non_fungible_asset);

    let code = format!(
        "
        use miden::protocol::output_note
        use $kernel::prologue

        begin
            exec.prologue::prepare_transaction

            push.{recipient}
            push.{PUBLIC_NOTE}
            push.{aux}
            push.{tag}

            call.output_note::create
            # => [note_idx]

            # assert that the index of the created note equals zero
            dup assertz.err=\"index of the created note should be zero\"
            # => [note_idx]

            dup push.{asset}
            call.output_note::add_asset
            # => [note_idx]

            dup push.{asset_2}
            call.output_note::add_asset
            # => [note_idx]

            dup push.{asset_3}
            call.output_note::add_asset
            # => [note_idx]

            push.{nft}
            call.output_note::add_asset
            # => []

            # truncate the stack
            repeat.7 dropw end
        end
        ",
        recipient = recipient,
        PUBLIC_NOTE = NoteType::Public as u8,
        tag = tag,
        asset = asset,
        asset_2 = asset_2,
        asset_3 = asset_3,
        nft = non_fungible_asset_encoded,
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_kernel_mem_word(OUTPUT_NOTE_SECTION_OFFSET + OUTPUT_NOTE_ASSETS_OFFSET),
        asset,
        "asset must be stored at the correct memory location",
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(OUTPUT_NOTE_SECTION_OFFSET + OUTPUT_NOTE_ASSETS_OFFSET + 4),
        asset_2_and_3,
        "asset_2 and asset_3 must be stored at the same correct memory location",
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(OUTPUT_NOTE_SECTION_OFFSET + OUTPUT_NOTE_ASSETS_OFFSET + 8),
        non_fungible_asset_encoded,
        "non_fungible_asset must be stored at the correct memory location",
    );

    Ok(())
}

#[tokio::test]
async fn test_create_note_and_add_same_nft_twice() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let recipient = Word::from([0, 1, 2, 3u32]);
    let tag = NoteTag::for_public_use_case(999, 777, NoteExecutionMode::Local).unwrap();
    let non_fungible_asset = NonFungibleAsset::mock(&[1, 2, 3]);
    let encoded = Word::from(non_fungible_asset);

    let code = format!(
        "
        use $kernel::prologue
        use miden::protocol::output_note

        begin
            exec.prologue::prepare_transaction
            # => []

            padw padw
            push.{recipient}
            push.{execution_hint_always}
            push.{PUBLIC_NOTE}
            push.{aux}
            push.{tag}

            call.output_note::create
            # => [note_idx]

            dup push.{nft}
            # => [NFT, note_idx, note_idx]

            call.output_note::add_asset
            # => [note_idx]

            push.{nft}
            call.output_note::add_asset
            # => []
        end
        ",
        recipient = recipient,
        PUBLIC_NOTE = NoteType::Public as u8,
        execution_hint_always = Felt::from(NoteExecutionHint::always()),
        aux = Felt::new(0),
        tag = tag,
        nft = encoded,
    );

    let exec_output = tx_context.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_NON_FUNGIBLE_ASSET_ALREADY_EXISTS);
    Ok(())
}

/// Tests that creating a note with a fungible asset with amount zero works.
#[tokio::test]
async fn creating_note_with_fungible_asset_amount_zero_works() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let output_note = builder.add_p2id_note(
        account.id(),
        account.id(),
        &[FungibleAsset::mock(0)],
        NoteType::Private,
    )?;
    let input_note = builder.add_spawn_note([&output_note])?;
    let chain = builder.build()?;

    chain
        .build_tx_context(account, &[input_note.id()], &[])?
        .build()?
        .execute()
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_build_recipient_hash() -> anyhow::Result<()> {
    let tx_context = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);

        let input_note_1 = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(100)],
        );
        TransactionContextBuilder::new(account)
            .extend_input_notes(vec![input_note_1])
            .build()?
    };
    let input_note_1 = tx_context.tx_inputs().input_notes().get_note(0).note();

    // create output note
    let output_serial_no = Word::from([0, 1, 2, 3u32]);
    let aux = Felt::new(27);
    let tag = NoteTag::for_public_use_case(42, 42, NoteExecutionMode::Network).unwrap();
    let single_input = 2;
    let inputs = NoteInputs::new(vec![Felt::new(single_input)]).unwrap();
    let input_commitment = inputs.commitment();

    let recipient = NoteRecipient::new(output_serial_no, input_note_1.script().clone(), inputs);
    let code = format!(
        "
        use miden::protocol::output_note
        use miden::protocol::note
        use $kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # pad the stack before call
            padw

            # input
            push.{input_commitment}
            # SCRIPT_ROOT
            push.{script_root}
            # SERIAL_NUM
            push.{output_serial_no}
            # => [SERIAL_NUM, SCRIPT_ROOT, INPUT_COMMITMENT, pad(4)]

            exec.note::build_recipient_hash
            # => [RECIPIENT, pad(12)]

            push.{execution_hint}
            push.{PUBLIC_NOTE}
            push.{aux}
            push.{tag}
            # => [tag, aux, note_type, execution_hint, RECIPIENT, pad(12)]

            call.output_note::create
            # => [note_idx, pad(19)]

            # clean the stack
            dropw dropw dropw dropw dropw
        end
        ",
        script_root = input_note_1.script().clone().root(),
        output_serial_no = output_serial_no,
        PUBLIC_NOTE = NoteType::Public as u8,
        tag = tag,
        execution_hint = Felt::from(NoteExecutionHint::after_block(2.into()).unwrap()),
        aux = aux,
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_kernel_mem_word(NUM_OUTPUT_NOTES_PTR),
        Word::from([1, 0, 0, 0u32]),
        "number of output notes must increment by 1",
    );

    let recipient_digest = recipient.clone().digest();

    assert_eq!(
        exec_output.get_kernel_mem_word(OUTPUT_NOTE_SECTION_OFFSET + OUTPUT_NOTE_RECIPIENT_OFFSET),
        recipient_digest,
        "recipient hash not correct",
    );
    Ok(())
}

/// This test creates an output note and then adds some assets into it checking the assets info on
/// each stage.
///
/// Namely, we invoke the `miden::protocol::output_notes::get_assets_info` procedure:
/// - After adding the first `asset_0` to the note.
/// - Right after the previous check to make sure it returns the same commitment from the cached
///   data.
/// - After adding the second `asset_1` to the note.
#[tokio::test]
async fn test_get_asset_info() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let fungible_asset_0 = Asset::Fungible(
        FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).expect("id should be valid"),
            5,
        )
        .expect("asset is invalid"),
    );

    // create the second asset with the different faucet ID to increase the number of assets in the
    // output note to 2.
    let fungible_asset_1 = Asset::Fungible(
        FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).expect("id should be valid"),
            5,
        )
        .expect("asset is invalid"),
    );

    let account = builder
        .add_existing_wallet_with_assets(Auth::BasicAuth, [fungible_asset_0, fungible_asset_1])?;

    let mock_chain = builder.build()?;

    let output_note_0 = create_p2id_note(
        account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into()?,
        vec![fungible_asset_0],
        NoteType::Public,
        Felt::new(0),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )?;

    let output_note_1 = create_p2id_note(
        account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into()?,
        vec![fungible_asset_0, fungible_asset_1],
        NoteType::Public,
        Felt::new(0),
        &mut RpoRandomCoin::new(Word::from([4, 3, 2, 1u32])),
    )?;

    let tx_script_src = &format!(
        r#"
        use miden::protocol::output_note
        use miden::core::sys

        begin
            # create an output note with fungible asset 0
            push.{RECIPIENT}
            push.{note_execution_hint}
            push.{note_type}
            push.0              # aux
            push.{tag}
            call.output_note::create
            # => [note_idx]

            # move the asset 0 to the note
            push.{asset_0}
            movup.4
            call.::miden::standards::wallets::basic::move_asset_to_note
            dropw
            # => [note_idx]

            # get the assets hash and assets number of the note having only asset_0
            dup exec.output_note::get_assets_info
            # => [ASSETS_COMMITMENT_0, num_assets_0, note_idx]

            # assert the correctness of the assets hash
            push.{COMPUTED_ASSETS_COMMITMENT_0}
            assert_eqw.err="assets commitment of the note having only asset_0 is incorrect"
            # => [num_assets_0, note_idx]

            # assert the number of assets
            push.{assets_number_0}
            assert_eq.err="number of assets in the note having only asset_0 is incorrect"
            # => [note_idx]

            # get the assets info once more to get the cached data and assert that this data didn't
            # change
            dup exec.output_note::get_assets_info
            push.{COMPUTED_ASSETS_COMMITMENT_0}
            assert_eqw.err="assets commitment of the note having only asset_0 is incorrect"
            push.{assets_number_0}
            assert_eq.err="number of assets in the note having only asset_0 is incorrect"
            # => [note_idx]

            # add asset_1 to the note
            push.{asset_1}
            movup.4
            call.::miden::standards::wallets::basic::move_asset_to_note
            dropw
            # => [note_idx]

            # get the assets hash and assets number of the note having asset_0 and asset_1
            dup exec.output_note::get_assets_info
            # => [ASSETS_COMMITMENT_1, num_assets_1, note_idx]

            # assert the correctness of the assets hash
            push.{COMPUTED_ASSETS_COMMITMENT_1}
            assert_eqw.err="assets commitment of the note having asset_0 and asset_1 is incorrect"
            # => [num_assets_1, note_idx]

            # assert the number of assets
            push.{assets_number_1}
            assert_eq.err="number of assets in the note having asset_0 and asset_1 is incorrect"
            # => [note_idx]

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#,
        // output note
        RECIPIENT = output_note_1.recipient().digest(),
        note_execution_hint = Felt::from(output_note_1.metadata().execution_hint()),
        note_type = NoteType::Public as u8,
        tag = output_note_1.metadata().tag(),
        asset_0 = Word::from(fungible_asset_0),
        // first data request
        COMPUTED_ASSETS_COMMITMENT_0 = output_note_0.assets().commitment(),
        assets_number_0 = output_note_0.assets().num_assets(),
        // second data request
        asset_1 = Word::from(fungible_asset_1),
        COMPUTED_ASSETS_COMMITMENT_1 = output_note_1.assets().commitment(),
        assets_number_1 = output_note_1.assets().num_assets(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_src)?;

    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_1)])
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Check that recipient and metadata of a note with one asset obtained from the
/// `output_note::get_recipient` procedure is correct.
#[tokio::test]
async fn test_get_recipient_and_metadata() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let account =
        builder.add_existing_wallet_with_assets(Auth::BasicAuth, [FungibleAsset::mock(2000)])?;

    let mock_chain = builder.build()?;

    let output_note = create_p2id_note(
        account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into()?,
        vec![FungibleAsset::mock(5)],
        NoteType::Public,
        Felt::new(0),
        &mut RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])),
    )?;

    let tx_script_src = &format!(
        r#"
        use miden::protocol::output_note
        use miden::core::sys

        begin
            # create an output note with one asset
            {output_note} drop
            # => []

            # get the recipient (the only existing note has 0'th index)
            push.0
            exec.output_note::get_recipient
            # => [RECIPIENT]

            # assert the correctness of the recipient
            push.{RECIPIENT}
            assert_eqw.err="requested note has incorrect recipient"
            # => []

            # get the metadata (the only existing note has 0'th index)
            push.0
            exec.output_note::get_metadata
            # => [METADATA]

            # assert the correctness of the metadata
            push.{METADATA}
            assert_eqw.err="requested note has incorrect metadata"
            # => []

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#,
        output_note = create_output_note(&output_note),
        RECIPIENT = output_note.recipient().digest(),
        METADATA = Word::from(output_note.metadata()),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_src)?;

    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

/// Check that the assets number and assets data obtained from the `output_note::get_assets`
/// procedure is correct for each note with zero, one and two different assets.
#[tokio::test]
async fn test_get_assets() -> anyhow::Result<()> {
    let TestSetup {
        mock_chain,
        account,
        p2id_note_0_assets,
        p2id_note_1_asset,
        p2id_note_2_assets,
    } = setup_test()?;

    fn check_assets_code(note_index: u8, dest_ptr: u8, note: &Note) -> String {
        let mut check_assets_code = format!(
            r#"
            # push the note index and memory destination pointer
            push.{note_idx} push.{dest_ptr}
            # => [dest_ptr, note_index]

            # write the assets to the memory
            exec.output_note::get_assets
            # => [num_assets, dest_ptr, note_index]

            # assert the number of note assets
            push.{assets_number}
            assert_eq.err="note {note_index} has incorrect assets number"
            # => [dest_ptr, note_index]
        "#,
            note_idx = note_index,
            dest_ptr = dest_ptr,
            assets_number = note.assets().num_assets(),
        );

        // check each asset in the note
        for (asset_index, asset) in note.assets().iter().enumerate() {
            check_assets_code.push_str(&format!(
                r#"
                    # load the asset stored in memory
                    padw dup.4 mem_loadw_le
                    # => [STORED_ASSET, dest_ptr, note_index]

                    # assert the asset
                    push.{NOTE_ASSET}
                    assert_eqw.err="asset {asset_index} of the note {note_index} is incorrect"
                    # => [dest_ptr, note_index]

                    # move the pointer
                    add.4
                    # => [dest_ptr+4, note_index]
                "#,
                NOTE_ASSET = Word::from(*asset),
                asset_index = asset_index,
                note_index = note_index,
            ));
        }

        // drop the final `dest_ptr` and `note_index` from the stack
        check_assets_code.push_str("\ndrop drop");

        check_assets_code
    }

    let tx_script_src = &format!(
        "
        use miden::protocol::output_note
        use miden::core::sys

        begin
            {create_note_0}
            {check_note_0}

            {create_note_1}
            {check_note_1}

            {create_note_2}
            {check_note_2}

            # truncate the stack
            exec.sys::truncate_stack
        end
        ",
        create_note_0 = create_output_note(&p2id_note_0_assets),
        check_note_0 = check_assets_code(0, 0, &p2id_note_0_assets),
        create_note_1 = create_output_note(&p2id_note_1_asset),
        check_note_1 = check_assets_code(1, 4, &p2id_note_1_asset),
        create_note_2 = create_output_note(&p2id_note_2_assets),
        check_note_2 = check_assets_code(2, 8, &p2id_note_2_assets),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_src)?;

    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .extend_expected_output_notes(vec![
            OutputNote::Full(p2id_note_0_assets),
            OutputNote::Full(p2id_note_1_asset),
            OutputNote::Full(p2id_note_2_assets),
        ])
        .tx_script(tx_script)
        .build()?;

    tx_context.execute().await?;

    Ok(())
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a `masm` code which creates an output note and adds some assets to it.
///
/// Data for the created output note and moved assets is obtained from the provided note.
fn create_output_note(note: &Note) -> String {
    let mut create_note_code = format!(
        "
        # create an output note
        push.{RECIPIENT}
        push.{note_execution_hint}
        push.{note_type}
        push.0              # aux
        push.{tag}
        call.output_note::create
        # => [note_idx]
    ",
        RECIPIENT = note.recipient().digest(),
        note_execution_hint = Felt::from(note.metadata().execution_hint()),
        note_type = note.metadata().note_type() as u8,
        tag = Felt::from(note.metadata().tag()),
    );

    for asset in note.assets().iter() {
        create_note_code.push_str(&format!(
            "
            # move the asset to the note
            push.{asset}
            movup.4
            call.::miden::standards::wallets::basic::move_asset_to_note
            dropw
            # => [note_idx]
        ",
            asset = Word::from(*asset)
        ));
    }

    create_note_code
}
