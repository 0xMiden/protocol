use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::BTreeMap;

use anyhow::Context;
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor};
use miden_protocol::batch::{BatchId, BatchKernel, ProposedBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::vm::{AdviceInputs, StackInputs, StackOutputs};
use miden_protocol::{Felt, Hasher, Word};
use miden_tx_batch_prover::{BatchExecutor, LocalBatchProver};

use super::proposed_batch::{TestSetup, mock_note, mock_output_note, setup_chain};
use super::proven_tx_builder::MockProvenTxBuilder;

// SETUP HELPERS
// ================================================================================================

/// Builds a two-transaction batch:
/// - tx1 (account1): consumes one authenticated input note, produces one output note.
/// - tx2 (account2): consumes one unauthenticated input note, produces two output notes.
pub(super) fn two_tx_batch(setup: &mut TestSetup) -> anyhow::Result<ProposedBatch> {
    let block1 = setup.chain.block_header(1);
    let block2 = setup.chain.prove_next_block()?;

    let tx1 = MockProvenTxBuilder::with_account(
        setup.account1.id(),
        Word::empty(),
        setup.account1.to_commitment(),
    )
    .reference_block(&block1)
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
    .reference_block(&block1)
    .unauthenticated_notes(vec![tx2_input])
    .output_notes(vec![mock_output_note(82), mock_output_note(83)])
    .expiration_block_num(BlockNumber::from(800u32))
    .build()?;

    Ok(ProposedBatch::new_unverified(
        [tx1, tx2].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        setup.chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?)
}

// EXPECTED-VALUE HELPERS
// ================================================================================================

/// Sequential hash over `(NULLIFIER, EMPTY_OR_NOTE_ID)` tuples for every input note in every
/// transaction in transaction order, mirroring the kernel's per-tx absorption.
///
/// We cannot compare against `ProposedBatch::input_notes().commitment()` yet: that commitment is
/// over the batch-level input notes re-sorted and deduped by nullifier, whereas the kernel
/// currently absorbs notes in transaction order without that re-sort/dedupe (tracked as a TODO in
/// `note_tracker.masm`). The two coincide only when transaction order already matches nullifier
/// order; this helper reproduces exactly what the kernel computes today.
fn expected_input_notes_commitment(batch: &ProposedBatch) -> Word {
    let mut elements: Vec<Felt> = Vec::new();
    for tx in batch.transactions() {
        for commit in tx.input_notes().iter() {
            elements.extend_from_slice(commit.nullifier().as_word().as_elements());
            let note_id_or_empty =
                commit.header().map_or(Word::empty(), |header| header.id().as_word());
            elements.extend_from_slice(note_id_or_empty.as_elements());
        }
    }
    if elements.is_empty() {
        Word::empty()
    } else {
        Hasher::hash_elements(&elements)
    }
}

// EXECUTION HELPERS
// ================================================================================================

/// Runs the batch kernel directly over the given inputs, returning its output stack.
///
/// Used by the tampering tests, which corrupt the advice inputs before execution. `BatchExecutor`
/// builds the advice internally from a (valid) `ProposedBatch` and offers no injection point, so it
/// cannot exercise the kernel's rejection paths. This mirrors how the transaction-kernel tests
/// inject tampered advice and run kernel code directly (see `tx_context.execute_code` with
/// `extend_advice_inputs` in `test_prologue.rs`).
fn run_kernel(
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
) -> Result<StackOutputs, miden_processor::ExecutionError> {
    let mut host = DefaultHost::default();
    host.load_library(CoreLibrary::default().mast_forest())
        .expect("loading the core library into the test host should succeed");

    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .expect("failed to create processor")
            .with_debugging(true);
    let output = processor.execute_sync(&BatchKernel::main(), &mut host)?;
    Ok(output.stack)
}

// HAPPY PATH
// ================================================================================================

/// The batch kernel reconstructs every transaction's input notes from the advice provider, anchors
/// them in `BATCH_ID`, and emits the batch's `INPUT_NOTES_COMMITMENT`. The batch note tree root and
/// expiration outputs are not wired up yet, so they remain empty / zero.
#[test]
fn batch_kernel_emits_input_notes_commitment() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;
    let expected_input_notes_commitment = expected_input_notes_commitment(&batch);

    let executed = BatchExecutor::new().execute(batch).context("batch execution failed")?;
    let output = executed.batch_outputs();

    assert_eq!(output.input_notes_commitment(), expected_input_notes_commitment);
    assert_eq!(output.batch_note_tree_root(), Word::empty());
    assert_eq!(output.batch_expiration_block_num(), BlockNumber::from(0u32));

    Ok(())
}

/// Executing a batch and then proving it produces a [`ProvenBatch`] carrying the kernel's proof.
#[test]
fn batch_executor_then_prover_produces_proven_batch() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;
    let expected_id = batch.id();

    let executed = BatchExecutor::new().execute(batch).context("batch execution failed")?;
    let proven = LocalBatchProver::new().prove(executed).context("batch proving failed")?;

    assert_eq!(proven.id(), expected_id);

    Ok(())
}

// NEGATIVE TESTS
// ================================================================================================

/// Corrupting `BATCH_ID` on the input stack makes Layer 1 unloadable from the advice map, so the
/// kernel must abort.
#[test]
fn batch_kernel_rejects_wrong_batch_id() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let block_commitment = batch.reference_block_header().commitment();
    // A BatchId over a one-transaction subset differs from the real (two-tx) batch id, so the
    // kernel cannot find its Layer 1 tuples in the advice map.
    let bogus_tx = &batch.transactions()[0];
    let bogus_batch_id = BatchId::from_ids([(bogus_tx.id(), bogus_tx.account_id())]);
    let stack_inputs = BatchKernel::build_input_stack(block_commitment, bogus_batch_id);
    let (_, advice_inputs) = BatchKernel::prepare_inputs(&batch);

    run_kernel(stack_inputs, advice_inputs).expect_err("kernel must abort on an unknown BATCH_ID");

    Ok(())
}

/// Tampering a verified `tx_id`'s Layer 2 advice-map entry breaks the per-tx header hash check.
#[test]
fn batch_kernel_rejects_tampered_layer_2() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let (stack_inputs, mut advice_inputs) = BatchKernel::prepare_inputs(&batch);

    let tx0_id = batch.transactions()[0].id().as_word();
    let entry = advice_inputs.map.get(&tx0_id).expect("tx0 layer 2 entry");
    let mut tampered: Vec<Felt> = entry.iter().copied().collect();
    tampered[0] += Felt::from(1u32);
    advice_inputs.map.extend([(tx0_id, tampered)]);

    run_kernel(stack_inputs, advice_inputs)
        .expect_err("kernel must abort on a tampered transaction header");

    Ok(())
}

/// Tampering the per-tx input-notes Layer 3 entry breaks the input-note hash check.
#[test]
fn batch_kernel_rejects_tampered_input_notes() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let (stack_inputs, mut advice_inputs) = BatchKernel::prepare_inputs(&batch);

    let key = batch.transactions()[0].input_notes().commitment();
    let entry = advice_inputs.map.get(&key).expect("layer 3 entry");
    let mut tampered: Vec<Felt> = entry.iter().copied().collect();
    tampered[0] += Felt::from(1u32);
    advice_inputs.map.extend([(key, tampered)]);

    run_kernel(stack_inputs, advice_inputs)
        .expect_err("kernel must abort on tampered input notes data");

    Ok(())
}
