use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::fast::ExecutionOutput;
use miden_processor::{AdviceInputs, Word};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountIdVersion,
    AccountProcedureRoot,
    AccountStorage,
    AccountStorageMode,
    AccountType,
    StorageMap,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{FungibleAsset, NonFungibleAsset};
use miden_protocol::errors::tx_kernel::{
    ERR_ACCOUNT_SEED_AND_COMMITMENT_DIGEST_MISMATCH,
    ERR_PROLOGUE_NEW_FUNGIBLE_FAUCET_RESERVED_SLOT_MUST_BE_EMPTY,
    ERR_PROLOGUE_NEW_NON_FUNGIBLE_FAUCET_RESERVED_SLOT_MUST_BE_VALID_EMPTY_SMT,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::memory::{
    ACCT_DB_ROOT_PTR,
    BLOCK_COMMITMENT_PTR,
    BLOCK_METADATA_PTR,
    BLOCK_NUMBER_IDX,
    CHAIN_COMMITMENT_PTR,
    FEE_PARAMETERS_PTR,
    INIT_ACCT_COMMITMENT_PTR,
    INIT_NATIVE_ACCT_STORAGE_COMMITMENT_PTR,
    INIT_NATIVE_ACCT_VAULT_ROOT_PTR,
    INIT_NONCE_PTR,
    INPUT_NOTE_ARGS_OFFSET,
    INPUT_NOTE_ASSETS_COMMITMENT_OFFSET,
    INPUT_NOTE_ASSETS_OFFSET,
    INPUT_NOTE_ATTACHMENT_OFFSET,
    INPUT_NOTE_ID_OFFSET,
    INPUT_NOTE_METADATA_HEADER_OFFSET,
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
    NATIVE_ACCT_ID_AND_NONCE_PTR,
    NATIVE_ACCT_ID_PTR,
    NATIVE_ACCT_PROCEDURES_SECTION_PTR,
    NATIVE_ACCT_STORAGE_COMMITMENT_PTR,
    NATIVE_ACCT_STORAGE_SLOTS_SECTION_PTR,
    NATIVE_ACCT_VAULT_ROOT_PTR,
    NATIVE_ASSET_ID_PREFIX_IDX,
    NATIVE_ASSET_ID_SUFFIX_IDX,
    NATIVE_NUM_ACCT_PROCEDURES_PTR,
    NATIVE_NUM_ACCT_STORAGE_SLOTS_PTR,
    NOTE_ROOT_PTR,
    NULLIFIER_DB_ROOT_PTR,
    NUM_KERNEL_PROCEDURES_PTR,
    PARTIAL_BLOCKCHAIN_NUM_LEAVES_PTR,
    PARTIAL_BLOCKCHAIN_PEAKS_PTR,
    PREV_BLOCK_COMMITMENT_PTR,
    PROTOCOL_VERSION_IDX,
    TIMESTAMP_IDX,
    TX_COMMITMENT_PTR,
    TX_KERNEL_COMMITMENT_PTR,
    TX_SCRIPT_ROOT_PTR,
    VALIDATOR_KEY_COMMITMENT_PTR,
    VERIFICATION_BASE_FEE_IDX,
};
use miden_protocol::transaction::{ExecutedTransaction, TransactionArgs, TransactionKernel};
use miden_protocol::{EMPTY_WORD, ONE, WORD_SIZE};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_tx::TransactionExecutorError;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::{Felt, ZERO};
use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::utils::create_public_p2any_note;
use crate::{
    Auth,
    MockChain,
    TransactionContext,
    TransactionContextBuilder,
    assert_execution_error,
    assert_transaction_executor_error,
};

#[tokio::test]
async fn test_transaction_prologue() -> anyhow::Result<()> {
    let mut tx_context = {
        let account =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
        let input_note_1 = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(100)],
        );
        let input_note_2 = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(100)],
        );
        let input_note_3 = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(111)],
        );
        TransactionContextBuilder::new(account)
            .extend_input_notes(vec![input_note_1, input_note_2, input_note_3])
            .build()?
    };

    let code = "
        use $kernel::prologue

        begin
            exec.prologue::prepare_transaction
        end
        ";

    let mock_tx_script_code = "
        begin
            nop
        end
        ";

    let tx_script = CodeBuilder::default().compile_tx_script(mock_tx_script_code).unwrap();

    let note_args = [Word::from([91u32; 4]), Word::from([92u32; 4])];

    let note_args_map = BTreeMap::from([
        (tx_context.input_notes().get_note(0).note().id(), note_args[0]),
        (tx_context.input_notes().get_note(1).note().id(), note_args[1]),
    ]);

    let tx_args = TransactionArgs::new(tx_context.tx_args().advice_inputs().clone().map)
        .with_tx_script(tx_script)
        .with_note_args(note_args_map);

    tx_context.set_tx_args(tx_args);
    let exec_output = &tx_context.execute_code(code).await?;

    global_input_memory_assertions(exec_output, &tx_context);
    block_data_memory_assertions(exec_output, &tx_context);
    partial_blockchain_memory_assertions(exec_output, &tx_context);
    kernel_data_memory_assertions(exec_output);
    account_data_memory_assertions(exec_output, &tx_context);
    input_notes_memory_assertions(exec_output, &tx_context, &note_args);

    Ok(())
}

fn global_input_memory_assertions(exec_output: &ExecutionOutput, inputs: &TransactionContext) {
    assert_eq!(
        exec_output.get_kernel_mem_word(BLOCK_COMMITMENT_PTR),
        inputs.tx_inputs().block_header().commitment(),
        "The block commitment should be stored at the BLOCK_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_ACCT_ID_PTR)[0],
        inputs.account().id().suffix(),
        "The account ID prefix should be stored at the ACCT_ID_PTR[0]"
    );
    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_ACCT_ID_PTR)[1],
        inputs.account().id().prefix().as_felt(),
        "The account ID suffix should be stored at the ACCT_ID_PTR[1]"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(INIT_ACCT_COMMITMENT_PTR),
        inputs.account().commitment(),
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
        inputs.tx_args().tx_script().as_ref().unwrap().root(),
        "The transaction script root should be stored at the TX_SCRIPT_ROOT_PTR"
    );
}

fn block_data_memory_assertions(exec_output: &ExecutionOutput, inputs: &TransactionContext) {
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
        exec_output.get_kernel_mem_word(TX_KERNEL_COMMITMENT_PTR),
        inputs.tx_inputs().block_header().tx_kernel_commitment(),
        "The kernel commitment should be stored at the TX_KERNEL_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(VALIDATOR_KEY_COMMITMENT_PTR),
        inputs.tx_inputs().block_header().validator_key().to_commitment(),
        "The public key commitment should be stored at the VALIDATOR_KEY_COMMITMENT_PTR"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(BLOCK_METADATA_PTR)[BLOCK_NUMBER_IDX],
        inputs.tx_inputs().block_header().block_num().into(),
        "The block number should be stored at BLOCK_METADATA_PTR[BLOCK_NUMBER_IDX]"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(BLOCK_METADATA_PTR)[PROTOCOL_VERSION_IDX],
        inputs.tx_inputs().block_header().version().into(),
        "The protocol version should be stored at BLOCK_METADATA_PTR[PROTOCOL_VERSION_IDX]"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(BLOCK_METADATA_PTR)[TIMESTAMP_IDX],
        inputs.tx_inputs().block_header().timestamp().into(),
        "The timestamp should be stored at BLOCK_METADATA_PTR[TIMESTAMP_IDX]"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(FEE_PARAMETERS_PTR)[NATIVE_ASSET_ID_SUFFIX_IDX],
        inputs.tx_inputs().block_header().fee_parameters().native_asset_id().suffix(),
        "The native asset ID suffix should be stored at FEE_PARAMETERS_PTR[NATIVE_ASSET_ID_SUFFIX_IDX]"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(FEE_PARAMETERS_PTR)[NATIVE_ASSET_ID_PREFIX_IDX],
        inputs
            .tx_inputs()
            .block_header()
            .fee_parameters()
            .native_asset_id()
            .prefix()
            .as_felt(),
        "The native asset ID prefix should be stored at FEE_PARAMETERS_PTR[NATIVE_ASSET_ID_PREFIX_IDX]"
    );

    assert_eq!(
        exec_output.get_kernel_mem_word(FEE_PARAMETERS_PTR)[VERIFICATION_BASE_FEE_IDX],
        inputs
            .tx_inputs()
            .block_header()
            .fee_parameters()
            .verification_base_fee()
            .into(),
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
    prepared_tx: &TransactionContext,
) {
    // update the partial blockchain to point to the block against which this transaction is being
    // executed
    let mut partial_blockchain = prepared_tx.tx_inputs().blockchain().clone();
    partial_blockchain.add_block(prepared_tx.tx_inputs().block_header(), true);

    assert_eq!(
        exec_output.get_kernel_mem_word(PARTIAL_BLOCKCHAIN_NUM_LEAVES_PTR)[0],
        Felt::new(partial_blockchain.chain_length().as_u64()),
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

fn kernel_data_memory_assertions(exec_output: &ExecutionOutput) {
    // check that the number of kernel procedures stored in the memory is equal to the number of
    // procedures in the `TransactionKernel::PROCEDURES` array
    assert_eq!(
        exec_output.get_kernel_mem_word(NUM_KERNEL_PROCEDURES_PTR)[0].as_int(),
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

fn account_data_memory_assertions(exec_output: &ExecutionOutput, inputs: &TransactionContext) {
    assert_eq!(
        exec_output.get_kernel_mem_word(NATIVE_ACCT_ID_AND_NONCE_PTR),
        Word::new([
            inputs.account().id().suffix(),
            inputs.account().id().prefix().as_felt(),
            ZERO,
            inputs.account().nonce()
        ]),
        "The account ID should be stored at NATIVE_ACCT_ID_AND_NONCE_PTR[0]"
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
        .as_elements()
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
    inputs: &TransactionContext,
    note_args: &[Word],
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
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_ID_OFFSET),
            note.id().as_word(),
            "ID hash should be computed and stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_SERIAL_NUM_OFFSET),
            note.serial_num(),
            "note serial num should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_SCRIPT_ROOT_OFFSET),
            note.script().root(),
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
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_METADATA_HEADER_OFFSET),
            note.metadata().to_header_word(),
            "note metadata header should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_ATTACHMENT_OFFSET),
            note.metadata().to_attachment_word(),
            "note attachment should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_ARGS_OFFSET),
            note_args[note_idx as usize],
            "note args should be stored at the correct offset"
        );

        assert_eq!(
            exec_output.get_note_mem_word(note_idx, INPUT_NOTE_NUM_ASSETS_OFFSET),
            Word::from([<u32>::try_from(note.assets().num_assets()).unwrap(), 0, 0, 0]),
            "number of assets should be stored at the correct offset"
        );

        for (asset, asset_idx) in note.assets().iter().cloned().zip(0_u32..) {
            let word: Word = asset.into();
            assert_eq!(
                exec_output.get_note_mem_word(
                    note_idx,
                    INPUT_NOTE_ASSETS_OFFSET + asset_idx * WORD_SIZE as u32
                ),
                word,
                "assets should be stored at (INPUT_NOTES_DATA_OFFSET + note_index * 2048 + 32 + asset_idx * 4)"
            );
        }
    }
}

// ACCOUNT CREATION TESTS
// ================================================================================================

/// Tests that a simple account can be created in a complete transaction execution (not using
/// [`TransactionContext::execute_code`]).
#[tokio::test]
async fn create_simple_account() -> anyhow::Result<()> {
    let account = AccountBuilder::new([6; 32])
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_empty_slots())
        .build()?;

    let tx = TransactionContextBuilder::new(account)
        .build()?
        .execute()
        .await
        .context("failed to execute account-creating transaction")?;

    assert_eq!(tx.account_delta().nonce_delta(), Felt::new(1));
    // except for the nonce, the delta should be empty
    assert!(tx.account_delta().storage().is_empty());
    assert!(tx.account_delta().vault().is_empty());
    assert_eq!(tx.final_account().nonce(), Felt::new(1));
    // account commitment should not be the empty word
    assert_ne!(tx.account_delta().to_commitment(), EMPTY_WORD);

    Ok(())
}

/// Test helper which executes the prologue to check if the creation of the given `account` with its
/// `seed` is valid in the context of the given `mock_chain`.
pub async fn create_account_test(
    account: Account,
) -> Result<ExecutedTransaction, TransactionExecutorError> {
    TransactionContextBuilder::new(account).build().unwrap().execute().await
}

pub async fn create_multiple_accounts_test(storage_mode: AccountStorageMode) -> anyhow::Result<()> {
    let mut accounts = Vec::new();

    for account_type in [
        AccountType::RegularAccountImmutableCode,
        AccountType::RegularAccountUpdatableCode,
        AccountType::FungibleFaucet,
        AccountType::NonFungibleFaucet,
    ] {
        let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
            .account_type(account_type)
            .storage_mode(storage_mode)
            .with_auth_component(Auth::IncrNonce)
            .with_component(MockAccountComponent::with_slots(vec![StorageSlot::with_value(
                StorageSlotName::mock(0),
                Word::from([255u32; WORD_SIZE]),
            )]))
            .build()
            .with_context(|| {
                format!("account build for {account_type} and {storage_mode} failed")
            })?;

        accounts.push(account);
    }

    for account in accounts {
        let account_type = account.account_type();
        create_account_test(account).await.context(format!(
            "create_multiple_accounts_test test failed for account type {account_type}"
        ))?;
    }

    Ok(())
}

/// Tests that a valid account of each storage mode can be created successfully.
#[tokio::test]
pub async fn create_accounts_with_all_storage_modes() -> anyhow::Result<()> {
    create_multiple_accounts_test(AccountStorageMode::Private).await?;

    create_multiple_accounts_test(AccountStorageMode::Public).await?;

    create_multiple_accounts_test(AccountStorageMode::Network).await
}

/// Takes an account with a placeholder ID and returns the same account but with its ID replaced
/// with a newly generated one.
fn compute_valid_account_id(account: Account) -> Account {
    let init_seed: [u8; 32] = [5; 32];
    let seed = AccountId::compute_account_seed(
        init_seed,
        account.account_type(),
        AccountStorageMode::Public,
        AccountIdVersion::Version0,
        account.code().commitment(),
        account.storage().to_commitment(),
    )
    .unwrap();

    let account_id = AccountId::new(
        seed,
        AccountIdVersion::Version0,
        account.code().commitment(),
        account.storage().to_commitment(),
    )
    .unwrap();

    // Overwrite old ID with generated ID.
    let (_, vault, storage, code, _nonce, _seed) = account.into_parts();
    // Set nonce to zero so this is considered a new account.
    Account::new(account_id, vault, storage, code, ZERO, Some(seed)).unwrap()
}

/// Tests that creating a fungible faucet account with a non-empty initial balance in its reserved
/// slot fails.
#[tokio::test]
pub async fn create_account_fungible_faucet_invalid_initial_balance() -> anyhow::Result<()> {
    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(NoopAuthComponent)
        .with_component(MockAccountComponent::with_empty_slots())
        .build_existing()
        .expect("account should be valid");
    let (id, vault, mut storage, code, _nonce, _seed) = account.into_parts();

    // Set the initial balance to a non-zero value manually, since the builder would not allow us to
    // do that.
    let faucet_data_slot = Word::from([0, 0, 0, 100u32]);
    storage
        .set_item(AccountStorage::faucet_sysdata_slot(), faucet_data_slot)
        .unwrap();

    // The compute account ID function will set the nonce to zero so this is considered a new
    // account.
    let account = Account::new(id, vault, storage, code, ONE, None)?;
    let account = compute_valid_account_id(account);

    let result = create_account_test(account).await;

    assert_transaction_executor_error!(
        result,
        ERR_PROLOGUE_NEW_FUNGIBLE_FAUCET_RESERVED_SLOT_MUST_BE_EMPTY
    );

    Ok(())
}

/// Tests that creating a non fungible faucet account with a non-empty storage map in its reserved
/// slot fails.
#[tokio::test]
pub async fn create_account_non_fungible_faucet_invalid_initial_reserved_slot() -> anyhow::Result<()>
{
    // Create a storage map with a mock asset to make it non-empty.
    let asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);
    let non_fungible_storage_map =
        StorageMap::with_entries([(asset.vault_key().into(), asset.into())]).unwrap();
    let storage = AccountStorage::new(vec![StorageSlot::with_map(
        AccountStorage::faucet_sysdata_slot().clone(),
        non_fungible_storage_map,
    )])
    .unwrap();

    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::NonFungibleFaucet)
        .with_auth_component(NoopAuthComponent)
        .with_component(MockAccountComponent::with_empty_slots())
        .build()
        .expect("account should be valid");
    let (id, vault, _storage, code, _nonce, _seed) = account.into_parts();

    // The compute account ID function will set the nonce to zero so this is considered a new
    // account.
    let account = Account::new(id, vault, storage, code, ONE, None)?;
    let account = compute_valid_account_id(account);

    let result = create_account_test(account).await;

    assert_transaction_executor_error!(
        result,
        ERR_PROLOGUE_NEW_NON_FUNGIBLE_FAUCET_RESERVED_SLOT_MUST_BE_VALID_EMPTY_SMT
    );

    Ok(())
}

/// Tests that supplying an invalid seed causes account creation to fail.
#[tokio::test]
pub async fn create_account_invalid_seed() -> anyhow::Result<()> {
    let mut mock_chain = MockChain::new();
    mock_chain.prove_next_block()?;

    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .account_type(AccountType::RegularAccountUpdatableCode)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build()?;

    let tx_inputs = mock_chain
        .get_transaction_inputs(&account, &[], &[])
        .expect("failed to get transaction inputs from mock chain");

    // override the seed with an invalid seed to ensure the kernel fails
    let account_seed_key = [account.id().suffix(), account.id().prefix().as_felt(), ZERO, ZERO];
    let adv_inputs =
        AdviceInputs::default().with_map([(Word::from(account_seed_key), vec![ZERO; WORD_SIZE])]);

    let tx_context = TransactionContextBuilder::new(account)
        .tx_inputs(tx_inputs)
        .extend_advice_inputs(adv_inputs)
        .build()?;

    let code = "
      use $kernel::prologue

      begin
          exec.prologue::prepare_transaction
      end
      ";

    let result = tx_context.execute_code(code).await;

    assert_execution_error!(result, ERR_ACCOUNT_SEED_AND_COMMITMENT_DIGEST_MISMATCH);

    Ok(())
}

#[tokio::test]
async fn test_get_blk_version() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let code = "
    use $kernel::memory
    use $kernel::prologue

    begin
        exec.prologue::prepare_transaction
        exec.memory::get_blk_version

        # truncate the stack
        swap drop
    end
    ";

    let exec_output = tx_context.execute_code(code).await?;

    assert_eq!(
        exec_output.get_stack_element(0),
        tx_context.tx_inputs().block_header().version().into()
    );

    Ok(())
}

#[tokio::test]
async fn test_get_blk_timestamp() -> anyhow::Result<()> {
    let tx_context = TransactionContextBuilder::with_existing_mock_account().build()?;
    let code = "
    use $kernel::memory
    use $kernel::prologue

    begin
        exec.prologue::prepare_transaction
        exec.memory::get_blk_timestamp

        # truncate the stack
        swap drop
    end
    ";

    let exec_output = tx_context.execute_code(code).await?;

    assert_eq!(
        exec_output.get_stack_element(0),
        tx_context.tx_inputs().block_header().timestamp().into()
    );

    Ok(())
}
