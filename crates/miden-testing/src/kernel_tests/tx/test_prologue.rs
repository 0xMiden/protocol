use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use anyhow::Context;
use miden_crypto::SequentialCommit;
use miden_processor::advice::AdviceInputs;
use miden_processor::{ExecutionOutput, Word};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountProcedureRoot,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{FungibleAsset, NonFungibleAsset};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::errors::tx_kernel::{
    ERR_ACCOUNT_SEED_AND_COMMITMENT_DIGEST_MISMATCH,
    ERR_PROLOGUE_NOTE_STORAGE_ITEMS_COUNT_MISMATCH,
    ERR_PROLOGUE_NUMBER_OF_NOTE_ASSETS_EXCEEDS_LIMIT,
};
use miden_protocol::note::NoteId;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::memory::{
    ACCT_DB_ROOT_PTR,
    ASSET_SIZE,
    ASSET_VALUE_OFFSET,
    BATCH_KERNEL_CONFIG_COMMITMENT_PTR,
    BLOCK_COMMITMENT_PTR,
    BLOCK_KERNEL_CONFIG_COMMITMENT_PTR,
    BLOCK_METADATA_PTR,
    BLOCK_NUMBER_IDX,
    BLOCK_VERSION_IDX,
    CHAIN_COMMITMENT_PTR,
    FEE_ASSET_ID_PTR,
    FEE_PARAMETERS_PTR,
    GLOBAL_ACCOUNT_ID_PREFIX_PTR,
    GLOBAL_ACCOUNT_ID_SUFFIX_PTR,
    INIT_ACCT_COMMITMENT_PTR,
    INIT_NATIVE_ACCT_STORAGE_COMMITMENT_PTR,
    INIT_NATIVE_ACCT_VAULT_ROOT_PTR,
    INIT_NONCE_PTR,
    INPUT_NOTE_ARGS_OFFSET,
    INPUT_NOTE_ASSETS_COMMITMENT_OFFSET,
    INPUT_NOTE_ASSETS_OFFSET,
    INPUT_NOTE_ATTACHMENTS_COMMITMENT_OFFSET,
    INPUT_NOTE_DETAILS_COMMITMENT_OFFSET,
    INPUT_NOTE_ID_OFFSET,
    INPUT_NOTE_METADATA_OFFSET,
    INPUT_NOTE_NULLIFIER_SECTION_PTR,
    INPUT_NOTE_NUM_ASSETS_OFFSET,
    INPUT_NOTE_RECIPIENT_OFFSET,
    INPUT_NOTE_SCRIPT_ROOT_OFFSET,
    INPUT_NOTE_SECTION_PTR,
    INPUT_NOTE_SERIAL_NUM_OFFSET,
    INPUT_NOTE_STORAGE_COMMITMENT_OFFSET,
    INPUT_NOTES_COMMITMENT_PTR,
    KERNEL_PROCEDURES_PTR,
    NATIVE_ACCT_CODE_COMMITMENT_PTR,
    NATIVE_ACCT_METADATA_PTR,
    NATIVE_ACCT_PROCEDURES_SECTION_PTR,
    NATIVE_ACCT_STORAGE_COMMITMENT_PTR,
    NATIVE_ACCT_STORAGE_SLOTS_SECTION_PTR,
    NATIVE_ACCT_VAULT_ROOT_PTR,
    NATIVE_NUM_ACCT_PROCEDURES_PTR,
    NATIVE_NUM_ACCT_STORAGE_SLOTS_PTR,
    NEXT_PROTOCOL_CONFIG_COMMITMENT_PTR,
    NOTE_ROOT_PTR,
    NULLIFIER_DB_ROOT_PTR,
    NUM_KERNEL_PROCEDURES_PTR,
    PARTIAL_BLOCKCHAIN_NUM_LEAVES_PTR,
    PARTIAL_BLOCKCHAIN_PEAKS_PTR,
    PREV_BLOCK_COMMITMENT_PTR,
    PROOF_VERIFICATION_COMMITMENT_PTR,
    PROTOCOL_CONFIG_COMMITMENT_PTR,
    TIMESTAMP_IDX,
    TX_COMMITMENT_PTR,
    TX_KERNEL_CONFIG_COMMITMENT_PTR,
    TX_SCRIPT_ROOT_PTR,
    VALIDATOR_CONFIG_COMMITMENT_PTR,
    VERIFICATION_BASE_FEE_IDX,
};
use miden_protocol::transaction::{ExecutedTransaction, TransactionArgs, TransactionKernel};
use miden_protocol::{EMPTY_WORD, MAX_ASSETS_PER_NOTE, WORD_SIZE};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_tx::TransactionExecutorError;

use super::{Felt, ZERO};
use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::utils::create_public_p2any_note;
use crate::{Auth, MockChain, MockTransaction, TestTransactionBuilder, assert_execution_error};

#[tokio::test]
async fn test_transaction_prologue() -> anyhow::Result<()> {
    let mut mock_tx = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let input_note_1 = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(100)],
        );
        let input_note_2 = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(100), NonFungibleAsset::mock(&[1, 2, 3])],
        );
        let input_note_3 = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(111)],
        );
        TestTransactionBuilder::new(account)
            .input_notes(vec![input_note_1, input_note_2, input_note_3])
            .build()?
    };

    let code = "
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction
        end
        ";

    let mock_tx_script_code = "
        @transaction_script
        pub proc main
            nop
        end
        ";

    let tx_script = CodeBuilder::default().compile_tx_script(mock_tx_script_code).unwrap();

    // Input note 2 does not have any note args.
    let note_args_map = BTreeMap::from([
        (mock_tx.input_notes().get_note(0).note().id(), Word::from([91u32; 4])),
        (mock_tx.input_notes().get_note(1).note().id(), Word::from([92u32; 4])),
    ]);

    let tx_args = TransactionArgs::new(mock_tx.tx_args().advice_inputs().clone().map)
        .with_tx_script(tx_script)
        .with_note_args(note_args_map.clone());

    mock_tx.set_tx_args(tx_args);
    let exec_output = &mock_tx.execute_code(code).await?;

    global_input_memory_assertions(exec_output, &mock_tx);
    block_data_memory_assertions(exec_output, &mock_tx);
    partial_blockchain_memory_assertions(exec_output, &mock_tx);
    protocol_config_memory_assertions(exec_output, &mock_tx);
    kernel_data_memory_assertions(exec_output);
    account_data_memory_assertions(exec_output, &mock_tx);
    input_notes_memory_assertions(exec_output, &mock_tx, &note_args_map);

    Ok(())
}

#[tokio::test]
async fn test_transaction_prologue_rejects_too_many_note_assets() -> anyhow::Result<()> {
    const NOTE_DATA_NUM_ASSETS_IDX: usize = 7 * WORD_SIZE + 1;

    let assets: Vec<_> = (0..MAX_ASSETS_PER_NOTE)
        .map(|i| NonFungibleAsset::mock(&(i as u32).to_le_bytes()))
        .collect();
    let input_note = create_public_p2any_note(ACCOUNT_ID_SENDER.try_into()?, assets);
    let mut mock_tx = TestTransactionBuilder::with_existing_mock_account()
        .input_note(input_note)
        .build()?;

    // Start with the valid input-note advice generated from a note at the protocol limit, then
    // forge one additional asset into it. This bypasses `NoteAssets::new` and exercises the
    // transaction kernel's independent input-note validation.
    let input_notes_commitment = mock_tx.input_notes().commitment();
    let (_, advice_inputs) = TransactionKernel::prepare_inputs(mock_tx.tx_inputs());
    let mut note_data = advice_inputs
        .as_advice_inputs()
        .map
        .get(&input_notes_commitment)
        .context("input-note advice should be present")?
        .as_ref()
        .to_vec();

    note_data[NOTE_DATA_NUM_ASSETS_IDX] = Felt::from((MAX_ASSETS_PER_NOTE + 1) as u32);
    let assets_end_idx = NOTE_DATA_NUM_ASSETS_IDX + 1 + MAX_ASSETS_PER_NOTE * ASSET_SIZE as usize;
    let extra_asset = NonFungibleAsset::mock(&(MAX_ASSETS_PER_NOTE as u32).to_le_bytes());
    note_data.splice(assets_end_idx..assets_end_idx, extra_asset.as_elements());

    mock_tx.set_tx_args(TransactionArgs::new(
        BTreeMap::from([(input_notes_commitment, note_data)]).into(),
    ));

    let code = "
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction
        end
        ";

    let result = mock_tx.execute_code(code).await;
    assert_execution_error!(result, ERR_PROLOGUE_NUMBER_OF_NOTE_ASSETS_EXCEEDS_LIMIT);

    Ok(())
}

#[tokio::test]
async fn test_transaction_prologue_verifies_note_storage_against_commitment() -> anyhow::Result<()>
{
    // The number of storage items sits right after the 7 note-detail words in the note-data blob.
    const NOTE_DATA_NUM_STORAGE_ITEMS_IDX: usize = 7 * WORD_SIZE;

    let assets = vec![NonFungibleAsset::mock(&0u32.to_le_bytes())];
    let input_note = create_public_p2any_note(ACCOUNT_ID_SENDER.try_into()?, assets);
    let mut mock_tx = TestTransactionBuilder::with_existing_mock_account()
        .input_note(input_note)
        .build()?;

    let input_notes_commitment = mock_tx.input_notes().commitment();
    let (_, advice_inputs) = TransactionKernel::prepare_inputs(mock_tx.tx_inputs());
    let note_data = advice_inputs
        .as_advice_inputs()
        .map
        .get(&input_notes_commitment)
        .context("input-note advice should be present")?
        .as_ref()
        .to_vec();

    let code = "
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction
        end
        ";

    // The note has empty storage (count == 0): the prologue accepts it because the empty preimage
    // hashes to the note's storage commitment.
    assert_eq!(note_data[NOTE_DATA_NUM_STORAGE_ITEMS_IDX], ZERO);
    mock_tx
        .execute_code(code)
        .await
        .context("valid empty-storage note should be accepted")?;

    // Forge a non-zero storage-item count that the note's storage commitment does not attest to.
    // The count stays within the limit, so it bypasses the bounds check and must be caught by
    // the commitment verification instead.
    let mut note_data = note_data;
    note_data[NOTE_DATA_NUM_STORAGE_ITEMS_IDX] = Felt::from(1u32);
    mock_tx.set_tx_args(TransactionArgs::new(
        BTreeMap::from([(input_notes_commitment, note_data)]).into(),
    ));

    let result = mock_tx.execute_code(code).await;
    assert_execution_error!(result, ERR_PROLOGUE_NOTE_STORAGE_ITEMS_COUNT_MISMATCH);

    Ok(())
}

fn global_input_memory_assertions(exec_output: &ExecutionOutput, inputs: &MockTransaction) {
    assert_eq!(
        exec_output.get_kernel_mem_word(BLOCK_COMMITMENT_PTR),
        inputs.tx_inputs().block_header().commitment(),
        "The block commitment should be stored at the BLOCK_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_element(GLOBAL_ACCOUNT_ID_SUFFIX_PTR),
        inputs.account().id().suffix(),
        "The account ID prefix should be stored at the GLOBAL_ACCOUNT_ID_SUFFIX_PTR"
    );
    assert_eq!(
        exec_output.get_kernel_mem_element(GLOBAL_ACCOUNT_ID_PREFIX_PTR),
        inputs.account().id().prefix().as_felt(),
        "The account ID suffix should be stored at the GLOBAL_ACCOUNT_ID_PREFIX_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(INIT_ACCT_COMMITMENT_PTR),
        inputs.account().to_commitment(),
        "The account commitment should be stored at the INIT_ACCT_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(INIT_NATIVE_ACCT_VAULT_ROOT_PTR),
        inputs.account().vault().root(),
        "The initial native account vault root should be stored at the INIT_ACCT_VAULT_ROOT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(INIT_NATIVE_ACCT_STORAGE_COMMITMENT_PTR),
        inputs.account().storage().to_commitment(),
        "The initial native account storage commitment should be stored at the INIT_ACCT_STORAGE_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(INPUT_NOTES_COMMITMENT_PTR),
        inputs.input_notes().commitment(),
        "The nullifier commitment should be stored at the INPUT_NOTES_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(INIT_NONCE_PTR)[0],
        inputs.account().nonce(),
        "The initial nonce should be stored at the INIT_NONCE_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(TX_SCRIPT_ROOT_PTR),
        inputs.tx_args().tx_script().as_ref().unwrap().root().as_word(),
        "The transaction script root should be stored at the TX_SCRIPT_ROOT_PTR"
    );
}

fn block_data_memory_assertions(exec_output: &ExecutionOutput, inputs: &MockTransaction) {
    assert_eq!(
        exec_output.get_kernel_mem_word(BLOCK_COMMITMENT_PTR),
        inputs.tx_inputs().block_header().commitment(),
        "The block commitment should be stored at the BLOCK_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(PREV_BLOCK_COMMITMENT_PTR),
        inputs.tx_inputs().block_header().prev_block_commitment(),
        "The previous block commitment should be stored at the PARENT_BLOCK_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(CHAIN_COMMITMENT_PTR),
        inputs.tx_inputs().block_header().chain_commitment(),
        "The chain commitment should be stored at the CHAIN_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(ACCT_DB_ROOT_PTR),
        inputs.tx_inputs().block_header().account_root(),
        "The account db root should be stored at the ACCT_DB_ROOT_PRT"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(NULLIFIER_DB_ROOT_PTR),
        inputs.tx_inputs().block_header().nullifier_root(),
        "The nullifier db root should be stored at the NULLIFIER_DB_ROOT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(TX_COMMITMENT_PTR),
        inputs.tx_inputs().block_header().tx_commitment(),
        "The TX commitment should be stored at the TX_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(PROTOCOL_CONFIG_COMMITMENT_PTR),
        inputs.tx_inputs().block_header().protocol_config(),
        "The protocol config commitment should be stored at the PROTOCOL_CONFIG_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(VALIDATOR_CONFIG_COMMITMENT_PTR),
        inputs.tx_inputs().block_header().validator_config().to_commitment(),
        "The validator config commitment should be stored at the VALIDATOR_CONFIG_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(NEXT_PROTOCOL_CONFIG_COMMITMENT_PTR),
        inputs.tx_inputs().block_header().next_protocol_config_commitment(),
        "The next protocol config commitment should be stored at the NEXT_PROTOCOL_CONFIG_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(BLOCK_METADATA_PTR)[BLOCK_VERSION_IDX],
        Felt::from(inputs.tx_inputs().block_header().version()),
        "The block header version should be stored at BLOCK_METADATA_PTR[BLOCK_VERSION_IDX]"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(BLOCK_METADATA_PTR)[BLOCK_NUMBER_IDX],
        Felt::from(inputs.tx_inputs().block_header().block_num()),
        "The block number should be stored at BLOCK_METADATA_PTR[BLOCK_NUMBER_IDX]"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(BLOCK_METADATA_PTR)[TIMESTAMP_IDX],
        Felt::from(inputs.tx_inputs().block_header().timestamp()),
        "The timestamp should be stored at BLOCK_METADATA_PTR[TIMESTAMP_IDX]"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(FEE_PARAMETERS_PTR)[VERIFICATION_BASE_FEE_IDX],
        Felt::from(inputs.tx_inputs().block_header().fee_parameters().verification_base_fee()),
        "The verification base fee should be stored at FEE_PARAMETERS_PTR[VERIFICATION_BASE_FEE_IDX]"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(NOTE_ROOT_PTR),
        inputs.tx_inputs().block_header().note_root(),
        "The note root should be stored at the NOTE_ROOT_PTR"
    );
}

fn partial_blockchain_memory_assertions(
    exec_output: &ExecutionOutput,
    prepared_tx: &MockTransaction,
) {
    // update the partial blockchain to point to the block against which this transaction is being
    // executed
    let mut partial_blockchain = prepared_tx.tx_inputs().blockchain().clone();
    partial_blockchain.add_block(prepared_tx.tx_inputs().block_header(), true);

    assert_eq!(
        exec_output.get_kernel_mem_word(PARTIAL_BLOCKCHAIN_NUM_LEAVES_PTR)[0],
        Felt::from(partial_blockchain.chain_length()),
        "The number of leaves should be stored at the PARTIAL_BLOCKCHAIN_NUM_LEAVES_PTR"
    );

    for (i, peak) in partial_blockchain.peaks().peaks().iter().enumerate() {
        // The peaks should be stored at the PARTIAL_BLOCKCHAIN_PEAKS_PTR
        let peak_idx: u32 = i.try_into().expect(
            "Number of peaks is log2(number_of_leaves), this value won't be larger than 2**32",
        );
        let word_aligned_peak_idx = peak_idx * WORD_SIZE as u32;
        assert_eq!(
            exec_output.get_kernel_mem_word(PARTIAL_BLOCKCHAIN_PEAKS_PTR + word_aligned_peak_idx),
            *peak
        );
    }
}

fn protocol_config_memory_assertions(exec_output: &ExecutionOutput, inputs: &MockTransaction) {
    let protocol_config = inputs.tx_inputs().protocol_config();

    assert_eq!(
        exec_output.get_kernel_mem_word(FEE_ASSET_ID_PTR),
        protocol_config.fee_asset_id().to_word(),
        "The fee asset ID should be stored at the FEE_ASSET_ID_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(TX_KERNEL_CONFIG_COMMITMENT_PTR),
        protocol_config.tx_kernel().to_commitment(),
        "The tx kernel config commitment should be stored at the TX_KERNEL_CONFIG_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(BATCH_KERNEL_CONFIG_COMMITMENT_PTR),
        protocol_config.batch_kernel().to_commitment(),
        "The batch kernel config commitment should be stored at the BATCH_KERNEL_CONFIG_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(BLOCK_KERNEL_CONFIG_COMMITMENT_PTR),
        protocol_config.block_kernel().to_commitment(),
        "The block kernel config commitment should be stored at the BLOCK_KERNEL_CONFIG_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(PROOF_VERIFICATION_COMMITMENT_PTR),
        protocol_config.proof_verification().to_commitment(),
        "The proof verification config commitment should be stored at the PROOF_VERIFICATION_COMMITMENT_PTR"
    );
}

fn kernel_data_memory_assertions(exec_output: &ExecutionOutput) {
    // check that the number of kernel procedures stored in the memory is equal to the number of
    // procedures in the `TransactionKernel::PROCEDURES` array
    assert_eq!(
        exec_output.get_kernel_mem_word(NUM_KERNEL_PROCEDURES_PTR)[0].as_canonical_u64(),
        TransactionKernel::PROCEDURES.len() as u64,
        "Number of the kernel procedures should be stored at the NUM_KERNEL_PROCEDURES_PTR"
    );

    // check that the hashes of the kernel procedures stored in the memory is equal to the hashes in
    // `TransactionKernel::PROCEDURES` array
    for (i, &proc_hash) in TransactionKernel::PROCEDURES.iter().enumerate() {
        assert_eq!(
            exec_output.get_kernel_mem_word(KERNEL_PROCEDURES_PTR + (i * WORD_SIZE) as u32),
            proc_hash,
            "hash of kernel procedure at index `{i}` does not match the hash stored in memory"
        );
    }
}

fn account_data_memory_assertions(exec_output: &ExecutionOutput, inputs: &MockTransaction) {
    let account_metadata = &inputs.account().to_elements()[0..4];
    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_ACCT_METADATA_PTR).as_elements(),
        account_metadata,
        "The account metadata word should be stored at NATIVE_ACCT_METADATA_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_ACCT_VAULT_ROOT_PTR),
        inputs.account().vault().root(),
        "The account vault root should be stored at NATIVE_ACCT_VAULT_ROOT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_ACCT_STORAGE_COMMITMENT_PTR),
        inputs.account().storage().to_commitment(),
        "The account storage commitment should be stored at NATIVE_ACCT_STORAGE_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_ACCT_CODE_COMMITMENT_PTR),
        inputs.account().code().commitment(),
        "account code commitment should be stored at NATIVE_ACCT_CODE_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_NUM_ACCT_STORAGE_SLOTS_PTR),
        Word::from([u16::try_from(inputs.account().storage().slots().len()).unwrap(), 0, 0, 0]),
        "The number of initialised storage slots should be stored at NATIVE_NUM_ACCT_STORAGE_SLOTS_PTR"
    );

    for (i, elements) in inputs
        .account()
        .storage()
        .to_elements()
        .chunks(StorageSlot::NUM_ELEMENTS / 2)
        .enumerate()
    {
        assert_eq!(
            exec_output.get_kernel_mem_word(
                NATIVE_ACCT_STORAGE_SLOTS_SECTION_PTR + (i * WORD_SIZE) as u32
            ),
            Word::try_from(elements).unwrap(),
            "The account storage slots should be stored starting at NATIVE_ACCT_STORAGE_SLOTS_SECTION_PTR"
        )
    }

    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_NUM_ACCT_PROCEDURES_PTR),
        Word::from([u16::try_from(inputs.account().code().procedures().len()).unwrap(), 0, 0, 0]),
        "The number of procedures should be stored at NATIVE_NUM_ACCT_PROCEDURES_PTR"
    );

    for (i, elements) in inputs
        .account()
        .code()
        .to_elements()
        .chunks(AccountProcedureRoot::NUM_ELEMENTS)
        .enumerate()
    {
        assert_eq!(
            exec_output
                .get_kernel_mem_word(NATIVE_ACCT_PROCEDURES_SECTION_PTR + (i * WORD_SIZE) as u32),
            Word::try_from(elements).unwrap(),
            "The account procedures should be stored starting at NATIVE_ACCT_PROCEDURES_SECTION_PTR"
        );
    }
}

fn input_notes_memory_assertions(
    exec_output: &ExecutionOutput,
    inputs: &MockTransaction,
    note_args: &BTreeMap<NoteId, Word>,
) {
    assert_eq!(
        exec_output.get_kernel_mem_word(INPUT_NOTE_SECTION_PTR),
        Word::from([inputs.input_notes().num_notes(), 0, 0, 0]),
        "number of input notes should be stored at the INPUT_NOTES_OFFSET"
    );

    for (input_note, note_idx) in inputs.input_notes().iter().zip(0_u32..) {
        let note = input_note.note();

        assert_eq!(
            exec_output.get_kernel_mem_word(
                INPUT_NOTE_NULLIFIER_SECTION_PTR + note_idx * WORD_SIZE as u32
            ),
            note.nullifier().as_word(),
            "note nullifier should be computer and stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_DETAILS_COMMITMENT_OFFSET),
            note.details_commitment().as_word(),
            "note details commitment should be computed and stored at INPUT_NOTE_DETAILS_COMMITMENT_OFFSET"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_ID_OFFSET),
            note.id().as_word(),
            "note ID should be computed and stored at INPUT_NOTE_ID_OFFSET"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_SERIAL_NUM_OFFSET),
            note.serial_num(),
            "note serial num should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_SCRIPT_ROOT_OFFSET),
            note.script().root().into(),
            "note script root should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_STORAGE_COMMITMENT_OFFSET),
            note.storage().commitment(),
            "note storage commitment should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_RECIPIENT_OFFSET),
            note.recipient().digest(),
            "note recipient should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_ASSETS_COMMITMENT_OFFSET),
            note.assets().commitment(),
            "note asset commitment should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_METADATA_OFFSET),
            note.metadata().to_metadata_word(),
            "note metadata should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_ATTACHMENTS_COMMITMENT_OFFSET),
            note.attachments().to_commitment(),
            "note attachment should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_ARGS_OFFSET),
            note_args.get(&input_note.id()).copied().unwrap_or_default(),
            "note args should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_NUM_ASSETS_OFFSET),
            Word::from([<u32>::try_from(note.assets().num_assets()).unwrap(), 0, 0, 0]),
            "number of assets should be stored at the correct offset"
        );

        for (asset, asset_idx) in note.assets().iter().cloned().zip(0_u32..) {
            let asset_id = asset.to_id_word();
            let asset_value = asset.to_value_word();

            let asset_id_addr = INPUT_NOTE_ASSETS_OFFSET + asset_idx * ASSET_SIZE;
            let asset_value_addr = asset_id_addr + ASSET_VALUE_OFFSET;

            assert_eq!(
                exec_output.get_note_mem_word(note_idx, asset_id_addr),
                asset_id,
                "asset ID should be stored at the correct offset"
            );

            assert_eq!(
                exec_output.get_note_mem_word(note_idx, asset_value_addr),
                asset_value,
                "asset value should be stored at the correct offset"
            );
        }
    }
}

// ACCOUNT CREATION TESTS
// ================================================================================================

/// Tests that a simple account can be created in a complete transaction execution (not using
/// [`MockTransaction::execute_code`]).
#[tokio::test]
async fn create_simple_account() -> anyhow::Result<()> {
    let account = AccountBuilder::new([6; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .build()?;

    let tx = TestTransactionBuilder::new(account)
        .build()?
        .execute()
        .await
        .context("failed to execute account-creating transaction")?;

    assert_eq!(tx.account_patch().final_nonce(), Some(Felt::ONE));
    // except for the nonce, the delta should be empty
    assert!(tx.account_patch().storage().is_empty());
    assert!(tx.account_patch().vault().is_empty());
    assert_eq!(tx.final_account().nonce(), Felt::ONE);
    // account commitment should not be the empty word
    assert_ne!(tx.account_patch().to_commitment(), EMPTY_WORD);

    Ok(())
}

/// Test helper which executes the prologue to check if the creation of the given `account` with its
/// `seed` is valid in the context of the given `mock_chain`.
pub async fn create_account_test(
    account: Account,
) -> Result<ExecutedTransaction, TransactionExecutorError> {
    TestTransactionBuilder::new(account).build().unwrap().execute().await
}

pub async fn create_multiple_accounts_test(account_type: AccountType) -> anyhow::Result<()> {
    let mut accounts = Vec::new();

    let account = AccountBuilder::new(rand::random())
        .account_type(account_type)
        .with_components(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(vec![StorageSlot::with_value(
            StorageSlotName::mock(0),
            Word::from([255u32; WORD_SIZE]),
        )]))
        .build()
        .with_context(|| format!("account build with account type {account_type} failed"))?;

    accounts.push(account);

    for account in accounts {
        create_account_test(account).await.context(format!(
            "create_multiple_accounts_test test failed for account type {account_type}"
        ))?;
    }

    Ok(())
}

/// Tests that a valid account of each account type can be created successfully.
#[tokio::test]
pub async fn create_accounts_with_all_storage_modes() -> anyhow::Result<()> {
    create_multiple_accounts_test(AccountType::Private).await?;

    create_multiple_accounts_test(AccountType::Public).await
}

/// Tests that supplying an invalid seed causes account creation to fail.
#[tokio::test]
pub async fn create_account_invalid_seed() -> anyhow::Result<()> {
    let mut mock_chain = MockChain::new();
    mock_chain.prove_next_block()?;

    let account = AccountBuilder::new(rand::random())
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build()?;

    // override the seed with an invalid seed to ensure the kernel fails
    let account_seed_key = AccountIdKey::from(account.id()).as_word();
    let adv_inputs = AdviceInputs::default().with_map([(account_seed_key, vec![ZERO; WORD_SIZE])]);

    let mock_tx = mock_chain.build_transaction(account).extend_advice_inputs(adv_inputs).build()?;

    let code = "
      use miden::tx_kernel_core::prologue

      begin
          exec.prologue::prepare_transaction
      end
      ";

    let result = mock_tx.execute_code(code).await;

    assert_execution_error!(result, ERR_ACCOUNT_SEED_AND_COMMITMENT_DIGEST_MISMATCH);

    Ok(())
}

#[tokio::test]
async fn test_get_blk_version() -> anyhow::Result<()> {
    let mock_tx = TestTransactionBuilder::with_existing_mock_account().build()?;
    let code = "
    use miden::tx_kernel_core::memory
    use miden::tx_kernel_core::prologue

    begin
        exec.prologue::prepare_transaction
        exec.memory::get_blk_version

        # truncate the stack
        swap drop
    end
    ";

    let exec_output = mock_tx.execute_code(code).await?;

    assert_eq!(
        exec_output.get_stack_element(0),
        Felt::from(mock_tx.tx_inputs().block_header().version())
    );

    Ok(())
}

#[tokio::test]
async fn test_get_blk_timestamp() -> anyhow::Result<()> {
    let mock_tx = TestTransactionBuilder::with_existing_mock_account().build()?;
    let code = "
    use miden::tx_kernel_core::memory
    use miden::tx_kernel_core::prologue

    begin
        exec.prologue::prepare_transaction
        exec.memory::get_blk_timestamp

        # truncate the stack
        swap drop
    end
    ";

    let exec_output = mock_tx.execute_code(code).await?;

    assert_eq!(
        exec_output.get_stack_element(0),
        Felt::from(mock_tx.tx_inputs().block_header().timestamp())
    );

    Ok(())
}
