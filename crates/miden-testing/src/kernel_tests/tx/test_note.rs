use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use anyhow::Context;
use miden_core::field::PrimeField64;
use miden_processor::fast::ExecutionOutput;
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::{AccountBuilder, AccountId};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::assembly::diagnostics::miette::{self, miette};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::crypto::rand::{FeltRng, RpoRandomCoin};
use miden_protocol::errors::MasmError;
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
    ACCOUNT_ID_NETWORK_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::memory::ACTIVE_INPUT_NOTE_PTR;
use miden_protocol::transaction::{OutputNote, TransactionArgs};
use miden_protocol::{Felt, Word, ZERO};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::note::NoteBuilder;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::kernel_tests::tx::{ExecutionOutputExt, input_note_data_ptr};
use crate::{
    Auth,
    MockChain,
    TransactionContext,
    TransactionContextBuilder,
    TxContextInput,
    assert_transaction_executor_error,
};

#[tokio::test]
async fn test_note_setup() -> anyhow::Result<()> {
    let tx_context = {
        let mut builder = MockChain::builder();
        let account = builder.add_existing_wallet(Auth::BasicAuth)?;
        let p2id_note_1 = builder.add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[FungibleAsset::mock(150)],
            NoteType::Public,
        )?;
        let mut mock_chain = builder.build()?;
        mock_chain.prove_next_block()?;

        mock_chain
            .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[p2id_note_1])?
            .build()?
    };

    let code = "
        use $kernel::prologue
        use $kernel::note

        begin
            exec.prologue::prepare_transaction
            exec.note::prepare_note
            # => [note_script_root_ptr, NOTE_ARGS, pad(11), pad(16)]
            padw movup.4 mem_loadw_le
            # => [SCRIPT_ROOT, NOTE_ARGS, pad(11), pad(16)]

            # truncate the stack
            repeat.19 movup.8 drop end
        end
        ";

    let exec_output = tx_context.execute_code(code).await?;

    note_setup_stack_assertions(&exec_output, &tx_context);
    note_setup_memory_assertions(&exec_output);
    Ok(())
}

#[tokio::test]
async fn test_note_script_and_note_args() -> miette::Result<()> {
    let mut tx_context = {
        let mut builder = MockChain::builder();
        let account = builder.add_existing_wallet(Auth::BasicAuth).map_err(|err| miette!(err))?;
        let p2id_note_1 = builder
            .add_p2id_note(
                ACCOUNT_ID_SENDER.try_into().unwrap(),
                account.id(),
                &[FungibleAsset::mock(150)],
                NoteType::Public,
            )
            .map_err(|err| miette!(err))?;
        let p2id_note_2 = builder
            .add_p2id_note(
                ACCOUNT_ID_SENDER.try_into().unwrap(),
                account.id(),
                &[FungibleAsset::mock(300)],
                NoteType::Public,
            )
            .map_err(|err| miette!(err))?;
        let mut mock_chain = builder.build().map_err(|err| miette!(err))?;
        mock_chain.prove_next_block().unwrap();

        mock_chain
            .build_tx_context(
                TxContextInput::AccountId(account.id()),
                &[],
                &[p2id_note_1, p2id_note_2],
            )
            .unwrap()
            .build()
            .unwrap()
    };

    let code = "
        use $kernel::prologue
        use $kernel::memory
        use $kernel::note

        begin
            exec.prologue::prepare_transaction
            exec.memory::get_num_input_notes push.2 assert_eq
            exec.note::prepare_note drop
            # => [NOTE_ARGS0, pad(11), pad(16)]
            repeat.11 movup.4 drop end
            # => [NOTE_ARGS0, pad(16)]

            exec.note::increment_active_input_note_ptr drop
            # => [NOTE_ARGS0, pad(16)]

            exec.note::prepare_note drop
            # => [NOTE_ARGS1, pad(11), NOTE_ARGS0, pad(16)]
            repeat.11 movup.4 drop end
            # => [NOTE_ARGS1, NOTE_ARGS0, pad(16)]

            # truncate the stack
            swapdw dropw dropw
        end
        ";

    let note_args = [Word::from([91, 91, 91, 91u32]), Word::from([92, 92, 92, 92u32])];
    let note_args_map = BTreeMap::from([
        (tx_context.input_notes().get_note(0).note().id(), note_args[1]),
        (tx_context.input_notes().get_note(1).note().id(), note_args[0]),
    ]);

    let tx_args = TransactionArgs::new(tx_context.tx_args().advice_inputs().clone().map)
        .with_note_args(note_args_map);

    tx_context.set_tx_args(tx_args);
    let exec_output = tx_context.execute_code(code).await.unwrap();

    assert_eq!(exec_output.get_stack_word_le(0), note_args[0]);
    assert_eq!(exec_output.get_stack_word_le(4), note_args[1]);

    Ok(())
}

fn note_setup_stack_assertions(exec_output: &ExecutionOutput, inputs: &TransactionContext) {
    let mut expected_stack = [ZERO; 16];

    // replace the top four elements with the tx script root
    let mut note_script_root = *inputs.input_notes().get_note(0).note().script().root();
    note_script_root.reverse();
    expected_stack[..4].copy_from_slice(&note_script_root);

    // assert that the stack contains the note inputs at the end of execution
    assert_eq!(exec_output.stack.as_slice(), expected_stack.as_slice())
}

fn note_setup_memory_assertions(exec_output: &ExecutionOutput) {
    // assert that the correct pointer is stored in bookkeeping memory
    assert_eq!(
        exec_output.get_kernel_mem_word(ACTIVE_INPUT_NOTE_PTR)[0],
        Felt::new(u64::from(input_note_data_ptr(0)))
    );
}

#[tokio::test]
async fn test_build_recipient() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    // Create test script and serial number
    let note_script = CodeBuilder::default().compile_note_script("begin nop end")?;
    let serial_num = Word::default();

    // Define test values as Words
    let word_1 = Word::from([1, 2, 3, 4u32]);
    let word_2 = Word::from([5, 6, 7, 8u32]);
    let word_3 = Word::from([9, 10, 11, 12u32]);
    let word_4 = Word::from([13, 14, 15, 16u32]);
    const BASE_ADDR: u32 = 4000;

    let code = format!(
        "
        use miden::core::sys

        use miden::protocol::note

        begin
            # put the values that will be hashed into the memory
            push.{word_1} push.{base_addr} mem_storew_le dropw
            push.{word_2} push.{addr_1} mem_storew_le dropw
            push.{word_3} push.{addr_2} mem_storew_le dropw
            push.{word_4} push.{addr_3} mem_storew_le dropw

            # Test with 4 values
            push.{script_root}  # SCRIPT_ROOT
            push.{serial_num}   # SERIAL_NUM
            push.4.4000         # num_inputs, inputs_ptr
            exec.note::build_recipient
            # => [RECIPIENT_4]

            # Test with 5 values
            push.{script_root}  # SCRIPT_ROOT
            push.{serial_num}   # SERIAL_NUM
            push.5.4000         # num_inputs, inputs_ptr
            exec.note::build_recipient
            # => [RECIPIENT_5, RECIPIENT_4]

            # Test with 13 values
            push.{script_root}  # SCRIPT_ROOT
            push.{serial_num}   # SERIAL_NUM
            push.13.4000        # num_inputs, inputs_ptr
            exec.note::build_recipient
            # => [RECIPIENT_13, RECIPIENT_5, RECIPIENT_4]

            # truncate the stack
            exec.sys::truncate_stack
        end
    ",
        word_1 = word_1,
        word_2 = word_2,
        word_3 = word_3,
        word_4 = word_4,
        base_addr = BASE_ADDR,
        addr_1 = BASE_ADDR + 4,
        addr_2 = BASE_ADDR + 8,
        addr_3 = BASE_ADDR + 12,
        script_root = note_script.root(),
        serial_num = serial_num,
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    // Create expected recipients and get their digests
    let note_inputs_4 = NoteInputs::new(word_1.to_vec())?;
    let recipient_4 = NoteRecipient::new(serial_num, note_script.clone(), note_inputs_4);

    let mut inputs_5 = word_1.to_vec();
    inputs_5.push(word_2[0]);
    let note_inputs_5 = NoteInputs::new(inputs_5)?;
    let recipient_5 = NoteRecipient::new(serial_num, note_script.clone(), note_inputs_5);

    let mut inputs_13 = word_1.to_vec();
    inputs_13.extend_from_slice(&word_2.to_vec());
    inputs_13.extend_from_slice(&word_3.to_vec());
    inputs_13.push(word_4[0]);
    let note_inputs_13 = NoteInputs::new(inputs_13)?;
    let recipient_13 = NoteRecipient::new(serial_num, note_script, note_inputs_13);

    let mut expected_stack = alloc::vec::Vec::new();
    expected_stack.extend_from_slice(recipient_4.digest().as_elements());
    expected_stack.extend_from_slice(recipient_5.digest().as_elements());
    expected_stack.extend_from_slice(recipient_13.digest().as_elements());
    expected_stack.reverse();

    assert_eq!(exec_output.stack[0..12], expected_stack);
    Ok(())
}

#[tokio::test]
async fn test_compute_inputs_commitment() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    // Define test values as Words
    let word_1 = Word::from([1, 2, 3, 4u32]);
    let word_2 = Word::from([5, 6, 7, 8u32]);
    let word_3 = Word::from([9, 10, 11, 12u32]);
    let word_4 = Word::from([13, 14, 15, 16u32]);
    const BASE_ADDR: u32 = 4000;

    let code = format!(
        "
        use miden::core::sys

        use miden::protocol::note

        begin
            # put the values that will be hashed into the memory
            push.{word_1} push.{base_addr} mem_storew_le dropw
            push.{word_2} push.{addr_1} mem_storew_le dropw
            push.{word_3} push.{addr_2} mem_storew_le dropw
            push.{word_4} push.{addr_3} mem_storew_le dropw

            # push the number of values and pointer to the inputs on the stack
            push.5.4000
            # execute the `compute_inputs_commitment` procedure for 5 values
            exec.note::compute_inputs_commitment
            # => [HASH_5]

            push.8.4000
            # execute the `compute_inputs_commitment` procedure for 8 values
            exec.note::compute_inputs_commitment
            # => [HASH_8, HASH_5]

            push.15.4000
            # execute the `compute_inputs_commitment` procedure for 15 values
            exec.note::compute_inputs_commitment
            # => [HASH_15, HASH_8, HASH_5]

            push.0.4000
            # check that calling `compute_inputs_commitment` procedure with 0 elements will result in an
            # empty word
            exec.note::compute_inputs_commitment
            # => [0, 0, 0, 0, HASH_15, HASH_8, HASH_5]

            # truncate the stack
            exec.sys::truncate_stack
        end
    ",
        word_1 = word_1,
        word_2 = word_2,
        word_3 = word_3,
        word_4 = word_4,
        base_addr = BASE_ADDR,
        addr_1 = BASE_ADDR + 4,
        addr_2 = BASE_ADDR + 8,
        addr_3 = BASE_ADDR + 12,
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    let mut inputs_5 = word_1.to_vec();
    inputs_5.push(word_2[0]);
    let note_inputs_5_hash = NoteInputs::new(inputs_5)?.commitment();

    let mut inputs_8 = word_1.to_vec();
    inputs_8.extend_from_slice(&word_2.to_vec());
    let note_inputs_8_hash = NoteInputs::new(inputs_8)?.commitment();

    let mut inputs_15 = word_1.to_vec();
    inputs_15.extend_from_slice(&word_2.to_vec());
    inputs_15.extend_from_slice(&word_3.to_vec());
    inputs_15.extend_from_slice(&word_4[0..3]);
    let note_inputs_15_hash = NoteInputs::new(inputs_15)?.commitment();

    let mut expected_stack = alloc::vec::Vec::new();

    expected_stack.extend_from_slice(note_inputs_5_hash.as_elements());
    expected_stack.extend_from_slice(note_inputs_8_hash.as_elements());
    expected_stack.extend_from_slice(note_inputs_15_hash.as_elements());
    expected_stack.extend_from_slice(Word::empty().as_elements());
    expected_stack.reverse();

    assert_eq!(exec_output.stack[0..16], expected_stack);
    Ok(())
}

#[tokio::test]
async fn test_build_metadata() -> miette::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build().unwrap();

    let sender = tx_context.account().id();
    let receiver = AccountId::try_from(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE)
        .map_err(|e| miette::miette!("Failed to convert account ID: {}", e))?;

    let test_metadata1 = NoteMetadata::new(
        sender,
        NoteType::Private,
        NoteTag::from_account_id(receiver),
        NoteExecutionHint::after_block(500.into())
            .map_err(|e| miette::miette!("Failed to create execution hint: {}", e))?,
        Felt::new(1u64 << 63),
    )
    .map_err(|e| miette::miette!("Failed to create metadata: {}", e))?;
    let test_metadata2 = NoteMetadata::new(
        sender,
        NoteType::Public,
        // Use largest allowed use_case_id.
        NoteTag::for_public_use_case((1 << 14) - 1, u16::MAX, NoteExecutionMode::Local)
            .map_err(|e| miette::miette!("Failed to create note tag: {}", e))?,
        NoteExecutionHint::on_block_slot(u8::MAX, u8::MAX, u8::MAX),
        Felt::new(0),
    )
    .map_err(|e| miette::miette!("Failed to create metadata: {}", e))?;

    for (iteration, test_metadata) in [test_metadata1, test_metadata2].into_iter().enumerate() {
        let code = format!(
            "
        use $kernel::prologue
        use $kernel::output_note

        begin
          exec.prologue::prepare_transaction
          push.{execution_hint} push.{note_type} push.{aux} push.{tag}
          exec.output_note::build_metadata

          # truncate the stack
          swapw dropw
        end
        ",
            execution_hint = Felt::from(test_metadata.execution_hint()),
            note_type = Felt::from(test_metadata.note_type()),
            aux = test_metadata.aux(),
            tag = test_metadata.tag(),
        );

        let exec_output = tx_context.execute_code(&code).await.unwrap();

        let metadata_word = exec_output.get_stack_word_le(0);

        assert_eq!(Word::from(test_metadata), metadata_word, "failed in iteration {iteration}");
    }

    Ok(())
}

/// This serves as a test that setting a custom timestamp on mock chain blocks works.
#[tokio::test]
pub async fn test_timelock() -> anyhow::Result<()> {
    const TIMESTAMP_ERROR: MasmError = MasmError::from_static_str("123");

    let code = format!(
        r#"
      use miden::protocol::active_note
      use miden::protocol::tx

      begin
          # store the note inputs to memory starting at address 0
          push.0 exec.active_note::get_inputs
          # => [num_inputs, inputs_ptr]

          # make sure the number of inputs is 1
          eq.1 assert.err="number of note inputs is not 1"
          # => [inputs_ptr]

          # read the timestamp at which the note can be consumed
          mem_load
          # => [timestamp]

          exec.tx::get_block_timestamp
          # => [block_timestamp, timestamp]
          # ensure block timestamp is newer than timestamp

          lte assert.err="{}"
          # => []
      end"#,
        TIMESTAMP_ERROR.message()
    );

    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let lock_timestamp: u32 = 2_000_000_000;
    let source_manager = Arc::new(DefaultSourceManager::default());
    let timelock_note = NoteBuilder::new(account.id(), &mut ChaCha20Rng::from_os_rng())
        .note_inputs([Felt::new(u64::from(lock_timestamp))])?
        .source_manager(source_manager.clone())
        .code(code.clone())
        .dynamically_linked_libraries(CodeBuilder::mock_libraries())
        .build()?;

    builder.add_output_note(OutputNote::Full(timelock_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain
        .prove_next_block_at(lock_timestamp - 100)
        .context("failed to prove next block at lock timestamp - 100")?;

    // Attempt to consume note too early.
    // ----------------------------------------------------------------------------------------
    let tx_inputs = mock_chain.get_transaction_inputs(&account, &[timelock_note.id()], &[])?;
    let tx_context = TransactionContextBuilder::new(account.clone())
        .with_source_manager(source_manager.clone())
        .tx_inputs(tx_inputs.clone())
        .build()?;
    let result = tx_context.execute().await;
    assert_transaction_executor_error!(result, TIMESTAMP_ERROR);

    // Consume note where lock timestamp matches the block timestamp.
    // ----------------------------------------------------------------------------------------
    mock_chain
        .prove_next_block_at(lock_timestamp)
        .context("failed to prove next block at lock timestamp")?;

    let tx_inputs = mock_chain.get_transaction_inputs(&account, &[timelock_note.id()], &[])?;
    let tx_context = TransactionContextBuilder::new(account).tx_inputs(tx_inputs).build()?;
    tx_context.execute().await?;

    Ok(())
}

/// This test checks the scenario when some public key, which is provided to the RPO component of
/// the target account, is also provided as an input to the input note.
///
/// Previously this setup was leading to the values collision in the advice map, see the
/// [issue #1267](https://github.com/0xMiden/miden-base/issues/1267) for more details.
#[tokio::test]
async fn test_public_key_as_note_input() -> anyhow::Result<()> {
    let mut rng = ChaCha20Rng::from_seed(Default::default());
    let sec_key = SecretKey::with_rng(&mut rng);
    // this value will be used both as public key in the RPO component of the target account and as
    // well as the input of the input note
    let public_key = PublicKeyCommitment::from(sec_key.public_key());
    let public_key_value = Word::from(public_key);

    let (rpo_component, authenticator) = Auth::BasicAuth.build_component();

    let mock_seed_1 = Word::from([1, 2, 3, 4u32]).as_bytes();
    let target_account = AccountBuilder::new(mock_seed_1)
        .with_auth_component(rpo_component.clone())
        .with_component(BasicWallet)
        .build_existing()?;

    let mock_seed_2 = Word::from([5, 6, 7, 8u32]).as_bytes();

    let sender_account = AccountBuilder::new(mock_seed_2)
        .with_auth_component(rpo_component)
        .with_component(BasicWallet)
        .build_existing()?;

    let serial_num = RpoRandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let tag = NoteTag::from_account_id(target_account.id());
    let metadata = NoteMetadata::new(
        sender_account.id(),
        NoteType::Public,
        tag,
        NoteExecutionHint::always(),
        Default::default(),
    )?;
    let vault = NoteAssets::new(vec![])?;
    let note_script = CodeBuilder::default().compile_note_script("begin nop end")?;
    let recipient =
        NoteRecipient::new(serial_num, note_script, NoteInputs::new(public_key_value.to_vec())?);
    let note_with_pub_key = Note::new(vault.clone(), metadata, recipient);

    let tx_context = TransactionContextBuilder::new(target_account)
        .extend_input_notes(vec![note_with_pub_key])
        .authenticator(authenticator)
        .build()?;

    tx_context.execute().await?;
    Ok(())
}

#[tokio::test]
async fn test_build_note_tag_for_network_account() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;

    let account_id = AccountId::try_from(ACCOUNT_ID_NETWORK_FUNGIBLE_FAUCET)?;
    let expected_tag = NoteTag::from_account_id(account_id).as_u32();

    let prefix = account_id.prefix().as_u64();
    let suffix = account_id.suffix().as_canonical_u64();

    let code = format!(
        "
        use miden::core::sys
        use miden::protocol::note

        begin
            push.{suffix}.{prefix} 

            exec.note::build_note_tag_for_network_account
            # => [network_account_tag]

            exec.sys::truncate_stack
        end
        ",
        suffix = suffix,
        prefix = prefix,
    );

    let exec_output = tx_context.execute_code(&code).await?;
    let actual_tag = exec_output.stack[0].as_canonical_u64();

    assert_eq!(
        actual_tag, expected_tag as u64,
        "Expected tag {:#010x}, got {:#010x}",
        expected_tag, actual_tag
    );

    Ok(())
}
