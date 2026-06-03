use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::BTreeMap;

use anyhow::Context;
use miden_protocol::batch::{BatchKernel, ProposedBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::{MasmError, ProvenBatchError, batch_kernel};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::vm::AdviceInputs;
use miden_protocol::{Felt, Word};
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

/// Asserts that batch execution failed with the kernel raising the expected MASM assertion error.
fn assert_kernel_error<T>(result: Result<T, ProvenBatchError>, expected: MasmError) {
    match result {
        Ok(_) => panic!("expected batch kernel error {expected}, but execution succeeded"),
        Err(ProvenBatchError::BatchKernelExecutionFailed(execution_error)) => assert!(
            expected.matches_execution_error(&execution_error),
            "batch kernel error did not match:\n  expected: {expected}\n  actual: {execution_error}",
        ),
        Err(other) => panic!("expected a batch kernel execution error {expected}, got: {other}"),
    }
}

// HAPPY PATH
// ================================================================================================

/// The batch kernel reconstructs every transaction's input notes, binds them to the global
/// nullifier-sorted list, and emits `INPUT_NOTES_COMMITMENT` equal to the commitment the proposed
/// batch derives over the same notes. `two_tx_batch` has no intra-batch erasure, so the full union
/// is committed. Only the `INPUT_NOTES_COMMITMENT` output is asserted.
#[test]
fn batch_kernel_emits_input_notes_commitment() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;
    let expected_input_notes_commitment = batch.input_notes().commitment();

    let executed = BatchExecutor::new().execute(batch).context("batch execution failed")?;
    let output = executed.batch_outputs();

    assert_eq!(output.input_notes_commitment(), expected_input_notes_commitment);
    assert_eq!(output.batch_note_tree_root(), Word::empty());
    assert_eq!(output.batch_expiration_block_num(), BlockNumber::from(0u32));

    Ok(())
}

/// A note created by one transaction and consumed (unauthenticated) by a later transaction in the
/// same batch is erased: the kernel excludes it from `INPUT_NOTES_COMMITMENT`, matching the empty
/// commitment the proposed batch derives after erasure.
#[test]
fn batch_kernel_erases_note_created_and_consumed_in_batch() -> anyhow::Result<()> {
    let setup = setup_chain();
    let mut chain = setup.chain;
    let block1 = chain.block_header(1);
    let block2 = chain.prove_next_block()?;

    let note = mock_note(40);
    let tx1 = MockProvenTxBuilder::with_account(
        setup.account1.id(),
        Word::empty(),
        setup.account1.to_commitment(),
    )
    .reference_block(&block1)
    .output_notes(vec![RawOutputNote::Full(note.clone()).into_output_note().unwrap()])
    .build()?;
    let tx2 = MockProvenTxBuilder::with_account(
        setup.account2.id(),
        Word::empty(),
        setup.account2.to_commitment(),
    )
    .reference_block(&block1)
    .unauthenticated_notes(vec![note.clone()])
    .build()?;

    let batch = ProposedBatch::new_unverified(
        [tx1, tx2].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;
    // The note is created and consumed within the batch, so the batch has no input notes.
    assert_eq!(batch.input_notes().num_notes(), 0);
    let expected_input_notes_commitment = batch.input_notes().commitment();

    let executed = BatchExecutor::new().execute(batch).context("batch execution failed")?;
    assert_eq!(
        executed.batch_outputs().input_notes_commitment(),
        expected_input_notes_commitment,
    );

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
//
// These three checks are performed by `mem::pipe_preimage_to_memory`, whose bare `assert_eqw`
// carries no named error code, so they assert only that execution fails. The global-list binding
// and erasure checks below raise named `ERR_BATCH_*` errors and are asserted concretely via
// `assert_kernel_error`.

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

// GLOBAL INPUT-NOTE LIST BINDING NEGATIVE TESTS
// ================================================================================================
//
// These corrupt the host-provided global input-note list (overriding it via `extend_advice_inputs`)
// and assert the kernel's binding rejects it, so the host cannot omit, inject, or alter notes.

/// Advice-map key for the global input-note list. Must match `INPUT_NOTE_LIST_KEY_FELT` in
/// `crates/miden-protocol/src/batch/kernel.rs`.
fn input_note_list_key() -> Word {
    Word::from([0xba7c_0001u32; 4])
}

/// Builds the global input-note list blob the kernel expects: `(nullifier, note_id_or_empty)` per
/// note across all transactions, sorted by nullifier.
fn input_note_list_blob(batch: &ProposedBatch) -> Vec<Felt> {
    let mut notes: Vec<(Word, Word)> = Vec::new();
    for tx in batch.transactions() {
        for commit in tx.input_notes().iter() {
            let nullifier = commit.nullifier().as_word();
            let note_id_or_empty =
                commit.header().map_or(Word::empty(), |header| header.id().as_word());
            notes.push((nullifier, note_id_or_empty));
        }
    }
    notes.sort_by(|a, b| a.0.cmp(&b.0));
    let mut blob = Vec::with_capacity(notes.len() * 8);
    for (nullifier, note_id_or_empty) in &notes {
        blob.extend_from_slice(nullifier.as_elements());
        blob.extend_from_slice(note_id_or_empty.as_elements());
    }
    blob
}

/// Omitting an input note from the global list makes its per-transaction lookup fail.
#[test]
fn batch_kernel_rejects_input_note_missing_from_list() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let mut blob = input_note_list_blob(&batch);
    blob.truncate(blob.len() - 8); // drop the last (highest-nullifier) note
    let override_advice = AdviceInputs::default().with_map([(input_note_list_key(), blob)]);

    let result = BatchExecutor::new().extend_advice_inputs(override_advice).execute(batch);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_INPUT_NOTE_NOT_IN_LIST);

    Ok(())
}

/// A duplicate entry breaks the strict-sorted (no-duplicate) invariant.
#[test]
fn batch_kernel_rejects_duplicated_input_note_list_entry() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let blob = input_note_list_blob(&batch);
    // Prepend a copy of the first entry, so two equal nullifiers are adjacent.
    let mut duplicated: Vec<Felt> = blob[0..8].to_vec();
    duplicated.extend_from_slice(&blob);
    let override_advice = AdviceInputs::default().with_map([(input_note_list_key(), duplicated)]);

    let result = BatchExecutor::new().extend_advice_inputs(override_advice).execute(batch);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_NOTE_LIST_NOT_SORTED);

    Ok(())
}

/// Altering a list entry's note id (without touching its nullifier) is caught when the kernel binds
/// the entry to the per-transaction note id.
#[test]
fn batch_kernel_rejects_input_note_list_id_mismatch() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let mut blob = input_note_list_blob(&batch);
    // Corrupt the first entry's note-id word (felts 4..8); the nullifier (felts 0..4) is untouched,
    // so the entry is still found by nullifier but its note id no longer matches.
    blob[4] += Felt::from(1u32);
    let override_advice = AdviceInputs::default().with_map([(input_note_list_key(), blob)]);

    let result = BatchExecutor::new().extend_advice_inputs(override_advice).execute(batch);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_INPUT_NOTE_ID_MISMATCH);

    Ok(())
}

/// Advice-map key for the global output-note list. Must match `OUTPUT_NOTE_LIST_KEY_FELT` in
/// `crates/miden-protocol/src/batch/kernel.rs`.
fn output_note_list_key() -> Word {
    Word::from([0xba7c_0002u32; 4])
}

/// Builds the global output-note list blob the kernel expects: `(note_id, 0, 0, 0, 0)` per output
/// note across all transactions, sorted by note id.
fn output_note_list_blob(batch: &ProposedBatch) -> Vec<Felt> {
    let mut ids: Vec<Word> = Vec::new();
    for tx in batch.transactions() {
        for note in tx.output_notes().iter() {
            ids.push(note.id().as_word());
        }
    }
    ids.sort_unstable();
    let mut blob = Vec::with_capacity(ids.len() * 8);
    for note_id in &ids {
        blob.extend_from_slice(note_id.as_elements());
        blob.extend_from_slice(Word::empty().as_elements());
    }
    blob
}

/// Omitting an output note from the global list makes its per-transaction lookup fail (the
/// output-note binding needed to soundly drive erasure).
#[test]
fn batch_kernel_rejects_output_note_missing_from_list() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let mut blob = output_note_list_blob(&batch);
    blob.truncate(blob.len() - 8); // drop the last (highest-note-id) output note
    let override_advice = AdviceInputs::default().with_map([(output_note_list_key(), blob)]);

    let result = BatchExecutor::new().extend_advice_inputs(override_advice).execute(batch);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_OUTPUT_NOTE_NOT_IN_LIST);

    Ok(())
}

/// Exercises the erasure ordering gate: claiming a consumed input note is created in-batch (by
/// adding its note id to the output list) without any transaction actually creating it leaves the
/// note expected-to-be-erased, so consuming it trips the consume-before-create /
/// circular-dependency check.
#[test]
fn batch_kernel_rejects_consume_before_create() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    // `two_tx_batch`'s tx2 consumes `mock_note(81)` as unauthenticated. Add that note's id to the
    // output list as a phantom creation that no transaction performs.
    let phantom_created_id = mock_note(81).id().as_word();
    let mut ids: Vec<Word> = Vec::new();
    for tx in batch.transactions() {
        for note in tx.output_notes().iter() {
            ids.push(note.id().as_word());
        }
    }
    ids.push(phantom_created_id);
    ids.sort_unstable();
    let mut blob = Vec::with_capacity(ids.len() * 8);
    for note_id in &ids {
        blob.extend_from_slice(note_id.as_elements());
        blob.extend_from_slice(Word::empty().as_elements());
    }
    let override_advice = AdviceInputs::default().with_map([(output_note_list_key(), blob)]);

    let result = BatchExecutor::new().extend_advice_inputs(override_advice).execute(batch);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_NOTE_CONSUMED_BEFORE_CREATED);

    Ok(())
}
