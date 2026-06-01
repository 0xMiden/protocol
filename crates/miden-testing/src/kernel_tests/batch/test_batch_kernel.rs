use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::BTreeMap;

use anyhow::Context;
use miden_protocol::batch::{BatchKernel, ProposedBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::vm::AdviceInputs;
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

// TAMPERING HELPERS
// ================================================================================================

/// Builds an advice-inputs override that corrupts the advice-map entry stored under `key`, so the
/// kernel's hash check against `key` fails. Fed to [`BatchExecutor::extend_advice_inputs`] to drive
/// the kernel's rejection paths through the normal executor (mirroring how the transaction-kernel
/// tests inject tampered advice via `extend_advice_inputs`; see `test_prologue.rs`).
fn tampered_advice_for(batch: &ProposedBatch, key: Word) -> AdviceInputs {
    let (_, advice_inputs) = BatchKernel::prepare_inputs(batch);
    let mut tampered: Vec<Felt> = advice_inputs
        .map
        .get(&key)
        .expect("advice-map entry for key")
        .iter()
        .copied()
        .collect();
    tampered[0] += Felt::from(1u32);
    AdviceInputs::default().with_map([(key, tampered)])
}

// HAPPY PATH
// ================================================================================================

/// The batch kernel reconstructs every transaction's input notes from the advice provider, anchors
/// them in `BATCH_ID`, and emits the batch's `INPUT_NOTES_COMMITMENT` and the running-min
/// `batch_expiration_block_num`. The batch note tree root is not wired up yet, so it remains empty.
#[test]
fn batch_kernel_emits_input_notes_commitment_and_expiration() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;
    let expected_input_notes_commitment = expected_input_notes_commitment(&batch);
    // The expected expiration is the minimum over the batch's transactions, which the proposed
    // batch derives independently of the kernel.
    let expected_expiration = batch.batch_expiration_block_num();

    let executed = BatchExecutor::new().execute(batch).context("batch execution failed")?;
    let output = executed.batch_outputs();

    assert_eq!(output.input_notes_commitment(), expected_input_notes_commitment);
    assert_eq!(output.batch_note_tree_root(), Word::empty());
    assert_eq!(output.batch_expiration_block_num(), expected_expiration);
    // Sanity check: the min of the two transactions' expirations (1234 and 800).
    assert_eq!(output.batch_expiration_block_num(), BlockNumber::from(800u32));

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
//
// Each test injects a tampered advice-map entry through `BatchExecutor::extend_advice_inputs` and
// asserts the kernel aborts. The executor builds consistent advice from the (valid) `ProposedBatch`
// and the override then corrupts a single layer's entry, breaking that layer's hash check.

/// Tampering the `BATCH_ID` -> `(tx_id, account_id)` tuples breaks the Layer 1 hash check.
#[test]
fn batch_kernel_rejects_tampered_layer_1() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let override_advice = tampered_advice_for(&batch, batch.id().as_word());

    let result = BatchExecutor::new().extend_advice_inputs(override_advice).execute(batch);
    assert!(result.is_err(), "kernel must abort on a tampered transaction list");

    Ok(())
}

/// Tampering a verified `tx_id`'s header data breaks the Layer 2 hash check.
#[test]
fn batch_kernel_rejects_tampered_layer_2() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let tx0_id = batch.transactions()[0].id().as_word();
    let override_advice = tampered_advice_for(&batch, tx0_id);

    let result = BatchExecutor::new().extend_advice_inputs(override_advice).execute(batch);
    assert!(result.is_err(), "kernel must abort on a tampered transaction header");

    Ok(())
}

/// Tampering a transaction's input-notes data breaks the Layer 3 (input-notes commitment) check.
#[test]
fn batch_kernel_rejects_tampered_input_notes() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let key = batch.transactions()[0].input_notes().commitment();
    let override_advice = tampered_advice_for(&batch, key);

    let result = BatchExecutor::new().extend_advice_inputs(override_advice).execute(batch);
    assert!(result.is_err(), "kernel must abort on tampered input-notes data");

    Ok(())
}
