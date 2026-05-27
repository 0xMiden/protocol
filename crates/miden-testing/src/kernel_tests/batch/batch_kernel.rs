use alloc::sync::Arc;
use std::collections::BTreeMap;

use anyhow::Context;
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor};
use miden_protocol::Word;
use miden_protocol::batch::{BatchKernel, ProposedBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::vm::{AdviceInputs, Program, StackInputs, StackOutputs};

use super::proposed_batch::{TestSetup, mock_note, mock_output_note, setup_chain};
use super::proven_tx_builder::MockProvenTxBuilder;

// SETUP HELPERS
// ================================================================================================

/// Builds a two-transaction batch with realistic inputs and outputs. The skeleton kernel does not
/// inspect any of this data, but the batch is built end-to-end so the smoke test exercises the
/// real `prepare_inputs` path that the verification PR will eventually consume.
fn two_tx_batch(setup: &mut TestSetup) -> anyhow::Result<ProposedBatch> {
    let block1 = setup.chain.block_header(1);
    let block2 = setup.chain.prove_next_block()?;

    let tx1 = MockProvenTxBuilder::with_account(
        setup.account1.id(),
        Word::empty(),
        setup.account1.to_commitment(),
    )
    .ref_block_commitment(block1.commitment())
    .authenticated_notes(vec![setup.note1.clone()])
    .output_notes(vec![mock_output_note(80)])
    .expiration_block_num(BlockNumber::from(1234u32))
    .build()?;

    let tx2_input = mock_note(81);
    let tx2 = MockProvenTxBuilder::with_account(
        setup.account2.id(),
        Word::empty(),
        setup.account2.to_commitment(),
    )
    .ref_block_commitment(block1.commitment())
    .unauthenticated_notes(vec![tx2_input])
    .output_notes(vec![mock_output_note(82), mock_output_note(83)])
    .expiration_block_num(BlockNumber::from(800u32))
    .build()?;

    Ok(ProposedBatch::new(
        [tx1, tx2].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        setup.chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?)
}

fn run_kernel(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
) -> Result<StackOutputs, miden_processor::ExecutionError> {
    let mut host = DefaultHost::default();
    host.load_library(CoreLibrary::default().mast_forest())
        .expect("loading the core library into the test host should succeed");

    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .with_debugging(true);
    let output = processor.execute_sync(program, &mut host)?;
    Ok(output.stack)
}

// SMOKE TEST
// ================================================================================================

/// The skeleton batch kernel drops its public inputs and exits, leaving the all-zero word output
/// region. This test exercises the full plumbing path (build a realistic `ProposedBatch`, derive
/// stack and advice inputs via `BatchKernel::prepare_inputs`, run the kernel, parse the outputs)
/// and asserts that the contract holds: the kernel runs to completion and emits the empty word
/// shape.
#[test]
fn batch_kernel_skeleton_emits_empty_outputs() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let (stack_inputs, advice_inputs) = BatchKernel::prepare_inputs(&batch);
    let stack_outputs = run_kernel(&BatchKernel::main(), stack_inputs, advice_inputs)
        .context("kernel execution failed")?;
    let (input_notes_commitment, output_notes_commitment, expiration) =
        BatchKernel::parse_output_stack(&stack_outputs).context("parse output stack failed")?;

    assert_eq!(input_notes_commitment, Word::empty());
    assert_eq!(output_notes_commitment, Word::empty());
    assert_eq!(expiration, BlockNumber::from(0u32));

    Ok(())
}
