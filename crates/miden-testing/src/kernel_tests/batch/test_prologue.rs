//! Tests for the batch kernel prologue.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::DefaultHost;
use miden_processor::fast::FastProcessor;
use miden_protocol::account::{Account, AccountStorageMode};
use miden_protocol::batch::BatchId;
use miden_protocol::batch::kernel::{BatchAdviceInputs, BatchKernel};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::ProvenTransaction;
use miden_protocol::{CoreLibrary, Word};
use miden_standards::testing::account_component::MockAccountComponent;
use rand::Rng;

use super::proven_tx_builder::MockProvenTxBuilder;
use crate::{AccountState, Auth, MockChain, MockChainBuilder};

fn generate_account(chain: &mut MockChainBuilder) -> Account {
    let account_builder = Account::builder(rand::rng().random())
        .storage_mode(AccountStorageMode::Private)
        .with_component(MockAccountComponent::with_empty_slots());
    chain
        .add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
        .expect("failed to add pending account from builder")
}

/// Tests that the batch kernel prologue correctly loads transaction data from advice
/// and the epilogue produces the expected output format.
#[tokio::test]
async fn test_batch_prologue_basic() -> anyhow::Result<()> {
    // Set up mock chain with accounts
    let mut builder = MockChain::builder();
    let account1 = generate_account(&mut builder);
    let account2 = generate_account(&mut builder);
    let mut chain = builder.build()?;
    chain.prove_next_block()?;
    let block_header = chain.block_header(1);

    // Create mock transactions
    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block_header.commitment())
            .expiration_block_num(BlockNumber::from(1000u32))
            .build()?;

    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.commitment())
            .ref_block_commitment(block_header.commitment())
            .expiration_block_num(BlockNumber::from(500u32))
            .build()?;

    let transactions: Vec<Arc<ProvenTransaction>> = vec![Arc::new(tx1), Arc::new(tx2)];

    // Build inputs
    let advice_inputs = BatchAdviceInputs::new(&block_header, &transactions);
    let batch_id = BatchId::from_transactions(transactions.iter().map(|t| t.as_ref()));
    let stack_inputs = BatchKernel::build_input_stack(block_header.commitment(), batch_id);

    // Execute the batch kernel
    let program = BatchKernel::main();
    let mut host = DefaultHost::default();

    // Load the CoreLibrary MAST forest
    let core_lib = CoreLibrary::default();
    host.load_library(core_lib.mast_forest()).expect("failed to load CoreLibrary");

    let processor = FastProcessor::new_debug(stack_inputs.as_slice(), advice_inputs.into());
    let output = processor.execute(&program, &mut host).await?;

    // Parse output and verify basic structure
    let parsed = BatchKernel::parse_output_stack(&output.stack)?;

    // Verify batch_expiration is min(tx1.expiration=1000, tx2.expiration=500) = 500
    assert_eq!(
        parsed.batch_expiration_block_num,
        BlockNumber::from(500u32),
        "batch_expiration should be min of transaction expirations"
    );

    // TODO: Once note processing is implemented, verify:
    // - input_notes_commitment is correct
    // - output_notes_smt_root is correct

    Ok(())
}

/// Tests that the batch kernel rejects batches with duplicate transaction IDs.
#[tokio::test]
async fn test_batch_prologue_rejects_duplicate_tx_ids() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = generate_account(&mut builder);
    let mut chain = builder.build()?;
    chain.prove_next_block()?;
    let block_header = chain.block_header(1);

    // Create two identical transactions (same TX_ID)
    let tx = MockProvenTxBuilder::with_account(account.id(), Word::empty(), account.commitment())
        .ref_block_commitment(block_header.commitment())
        .expiration_block_num(BlockNumber::from(1000u32))
        .build()?;

    // Duplicate the same transaction
    let transactions: Vec<Arc<ProvenTransaction>> = vec![Arc::new(tx.clone()), Arc::new(tx)];

    let advice_inputs = BatchAdviceInputs::new(&block_header, &transactions);
    let batch_id = BatchId::from_transactions(transactions.iter().map(|t| t.as_ref()));
    let stack_inputs = BatchKernel::build_input_stack(block_header.commitment(), batch_id);

    let program = BatchKernel::main();
    let mut host = DefaultHost::default();
    let core_lib = CoreLibrary::default();
    host.load_library(core_lib.mast_forest()).expect("failed to load CoreLibrary");

    let processor = FastProcessor::new_debug(stack_inputs.as_slice(), advice_inputs.into());
    let result = processor.execute(&program, &mut host).await;

    // Should fail with duplicate TX_ID error
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("duplicate transaction id"),
        "expected duplicate TX_ID error, got: {err}"
    );

    Ok(())
}

/// Tests that the batch kernel rejects expired transactions.
#[tokio::test]
async fn test_batch_prologue_rejects_expired_transaction() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = generate_account(&mut builder);
    let mut chain = builder.build()?;
    chain.prove_next_block()?;
    let block_header = chain.block_header(1);

    // Create transaction that expires at block 1 (same as reference block)
    let tx = MockProvenTxBuilder::with_account(account.id(), Word::empty(), account.commitment())
        .ref_block_commitment(block_header.commitment())
        .expiration_block_num(BlockNumber::from(1u32))
        .build()?;

    let transactions: Vec<Arc<ProvenTransaction>> = vec![Arc::new(tx)];

    let advice_inputs = BatchAdviceInputs::new(&block_header, &transactions);
    let batch_id = BatchId::from_transactions(transactions.iter().map(|t| t.as_ref()));
    let stack_inputs = BatchKernel::build_input_stack(block_header.commitment(), batch_id);

    let program = BatchKernel::main();
    let mut host = DefaultHost::default();
    let core_lib = CoreLibrary::default();
    host.load_library(core_lib.mast_forest()).expect("failed to load CoreLibrary");

    let processor = FastProcessor::new_debug(stack_inputs.as_slice(), advice_inputs.into());
    let result = processor.execute(&program, &mut host).await;

    // Should fail with expired transaction error
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("expired"), "expected expired transaction error, got: {err}");

    Ok(())
}
