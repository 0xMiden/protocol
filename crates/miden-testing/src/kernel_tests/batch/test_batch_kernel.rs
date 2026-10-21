use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::BTreeMap;
use std::iter;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_protocol::batch::{
    BatchKernel,
    FELTS_PER_NOTE_ENTRY,
    INPUT_NOTE_LIST_KEY,
    OUTPUT_NOTE_LIST_KEY,
    ProposedBatch,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::{MasmError, ProposedBatchError, ProvenBatchError, batch_kernel};
use miden_protocol::note::NoteType;
use miden_protocol::transaction::{ProvenTransaction, RawOutputNote, TransactionCommitments};
use miden_protocol::vm::{AdviceInputs, ExecutionProof, PrecompileStatus};
use miden_protocol::{
    Felt,
    MAX_INPUT_NOTES_PER_BATCH,
    MAX_OUTPUT_NOTES_PER_BATCH,
    MAX_TRANSACTIONS_PER_BATCH,
    MIN_PROOF_SECURITY_LEVEL,
    WORD_SIZE,
    Word,
};
use miden_tx::LocalTransactionProver;
use miden_tx_batch::{BatchExecutor, LocalBatchProver};
use rstest::rstest;

use super::proposed_batch::{TestSetup, mock_note, mock_output_note, setup_chain};
use super::proven_tx_builder::MockProvenTxBuilder;
use crate::{Auth, MockChain};

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

/// Executes and proves one transaction per given auth scheme, so that the transactions carry the
/// real deferred precompile claims of their signature checks.
///
/// Returns the chain together with the proven transactions, in the order of the auth schemes.
async fn proven_transactions(
    auth_schemes: Vec<Auth>,
) -> anyhow::Result<(MockChain, Vec<Arc<ProvenTransaction>>)> {
    let mut builder = MockChain::builder();
    let mut accounts_with_notes = Vec::with_capacity(auth_schemes.len());
    for auth in auth_schemes {
        let account = builder.add_existing_wallet(auth)?;
        let note = builder.add_p2any_note(account.id(), NoteType::Public, [])?;
        accounts_with_notes.push((account, note));
    }
    let chain = builder.build()?;

    let mut transactions = Vec::with_capacity(accounts_with_notes.len());
    for (account, note) in accounts_with_notes {
        let executed = chain
            .build_transaction(account.id())
            .authenticated_input_note(note.id())
            .build()?
            .execute()
            .await?;
        let proven = LocalTransactionProver::default()
            .prove(executed)
            .context("failed to prove transaction")?;
        transactions.push(Arc::new(proven));
    }

    Ok((chain, transactions))
}

/// Builds a batch over the given proven transactions, verifying each of their proofs.
fn propose_batch(
    chain: &MockChain,
    transactions: Vec<Arc<ProvenTransaction>>,
) -> anyhow::Result<ProposedBatch> {
    let (reference_block, partial_blockchain, unauthenticated_note_proofs) =
        chain.get_batch_inputs(transactions.iter().map(|tx| tx.ref_block_num()), iter::empty())?;

    ProposedBatch::new(
        transactions,
        reference_block,
        partial_blockchain,
        unauthenticated_note_proofs,
        MIN_PROOF_SECURITY_LEVEL,
    )
    .context("failed to propose batch")
}

// TAMPERING HELPERS
// ================================================================================================

/// Builds an advice-inputs override that corrupts the advice-map entry stored under `key`, so the
/// kernel's hash check against `key` fails.
fn tampered_advice_for(batch: &ProposedBatch, key: Word) -> AdviceInputs {
    let mut tampered = advice_blob_for(batch, key);
    tampered[0] += Felt::from(1u32);
    AdviceInputs::default().with_map([(key, tampered)])
}

/// Returns the advice-map blob the kernel expects under `key`, read back out of the production
/// advice builder so these tests cannot drift from the serialization they are corrupting.
fn advice_blob_for(batch: &ProposedBatch, key: Word) -> Vec<Felt> {
    let (_, advice_inputs) = BatchKernel::prepare_inputs(batch);
    advice_inputs.map().get(&key).expect("advice-map entry for key").to_vec()
}

/// Splits a note-list blob into its `(KEY, VALUE)` word pairs.
fn note_list_entries(blob: &[Felt]) -> Vec<(Word, Word)> {
    blob.as_chunks::<FELTS_PER_NOTE_ENTRY>()
        .0
        .iter()
        .map(|entry| {
            (
                Word::new([entry[0], entry[1], entry[2], entry[3]]),
                Word::new([entry[4], entry[5], entry[6], entry[7]]),
            )
        })
        .collect()
}

/// Serializes `(KEY, VALUE)` word pairs back into a note-list blob, sorted by KEY as the kernel
/// requires.
fn note_list_blob_from(mut entries: Vec<(Word, Word)>) -> Vec<Felt> {
    entries.sort_by_key(|entry| entry.0);
    let mut blob = Vec::with_capacity(entries.len() * FELTS_PER_NOTE_ENTRY);
    for (key, value) in &entries {
        blob.extend_from_slice(key.as_elements());
        blob.extend_from_slice(value.as_elements());
    }
    blob
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

/// The kernel emits `INPUT_NOTES_COMMITMENT` equal to the commitment the proposed batch derives
/// over the same notes (`two_tx_batch` has no intra-batch erasure, so the full union is
/// committed).
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
    let proven = LocalBatchProver::default().prove(executed).context("batch proving failed")?;

    assert_eq!(proven.id(), expected_id);

    Ok(())
}

/// The batch settles the outstanding precompile claims of its transactions: the executor collects
/// one witness per ECDSA transaction in transaction order, and the prover proves them all at once.
/// A transaction without a signature check contributes no claim.
///
/// Proving dominates the runtime of this test, so the transactions are proven once and each shape
/// is chosen to cover a distinct prover path: one precompile proof over several interleaved claims
/// and one batch without any claim.
#[tokio::test]
async fn prove_batch_settling_precompile_claims() -> anyhow::Result<()> {
    let schemes = vec![Auth::basic_ecdsa(), Auth::basic_ecdsa(), Auth::IncrNonce];
    let (chain, transactions) = proven_transactions(schemes).await?;
    let (ecdsa, no_claim) = (&transactions[..2], &transactions[2]);

    // All transactions belong to different accounts, so their order in a batch is free.
    let shapes = [
        (
            "ecdsa, no claim, ecdsa",
            vec![ecdsa[0].clone(), no_claim.clone(), ecdsa[1].clone()],
            2,
        ),
        ("no claim", vec![no_claim.clone()], 0),
    ];

    for (shape, transactions, expected_root_count) in shapes {
        let batch = propose_batch(&chain, transactions).context(shape)?;

        // The roots the batch must settle, in transaction order.
        let mut expected_roots = Vec::new();
        for transaction in batch.transactions() {
            expected_roots
                .extend(transaction.precompile_witness().map(|witness| witness.root_unchecked()));
        }
        // Pin the count independently, so this fails if transactions stop deferring claims.
        assert_eq!(expected_roots.len(), expected_root_count, "{shape}");

        let executed = BatchExecutor::new().execute(batch).context(shape)?;
        assert_eq!(
            executed
                .precompile_witnesses()
                .iter()
                .map(|witness| witness.root_unchecked())
                .collect::<Vec<_>>(),
            expected_roots,
            "{shape}"
        );

        LocalBatchProver::default().prove(executed).context(shape)?;
    }

    Ok(())
}

/// A transaction whose deferred precompile witness does not match the precompile root its VM proof
/// commits to is rejected when the batch is proposed. This is the guarantee that lets
/// `BatchExecutor::execute` collect the witnesses without re-validating them.
#[tokio::test]
async fn propose_batch_rejects_mismatched_precompile_witness() -> anyhow::Result<()> {
    let (chain, transactions) =
        proven_transactions(vec![Auth::basic_ecdsa(), Auth::basic_ecdsa()]).await?;

    // Move the second transaction's witness onto the first transaction, leaving its VM proof - and
    // therefore the precompile root that proof commits to - untouched.
    let foreign_witness = transactions[1]
        .precompile_witness()
        .context("second transaction does not defer precompile work")?
        .clone();
    let original = transactions[0].as_ref();
    let tampered = ProvenTransaction::new(
        original.account_update().clone(),
        original.input_notes().iter().cloned(),
        original.output_notes().iter().cloned(),
        original.ref_block_num(),
        original.ref_block_commitment(),
        original.expiration_block_num(),
        ExecutionProof::new(
            original.proof().vm().clone(),
            PrecompileStatus::Deferred(foreign_witness),
        ),
        original.log_details().clone(),
    )?;

    let (reference_block, partial_blockchain, unauthenticated_note_proofs) =
        chain.get_batch_inputs(core::iter::once(tampered.ref_block_num()), iter::empty())?;
    let error = ProposedBatch::new(
        vec![Arc::new(tampered)],
        reference_block,
        partial_blockchain,
        unauthenticated_note_proofs,
        MIN_PROOF_SECURITY_LEVEL,
    )
    .expect_err("batch with a mismatched precompile witness was proposed");

    assert_matches!(error, ProposedBatchError::TransactionVerificationFailed { .. });

    Ok(())
}

// NEGATIVE TESTS
// ================================================================================================
//
// Each test merges a tampered advice-map entry over the advice derived from a valid
// `ProposedBatch` and asserts the kernel aborts.

/// Tampering any preimage layer breaks its hash check inside `mem::pipe_preimage_to_memory` (a
/// bare `assert_eqw` with no named error code, so the cases only assert that execution fails).
/// Cases: Layer 1 (`BATCH_ID`), Layer 2 (`tx_id`), Layer 3a (`INPUT_NOTES_COMMITMENT`), Layer
/// 3b (`OUTPUT_NOTES_COMMITMENT`).
#[rstest]
#[case(|batch: &ProposedBatch| batch.id().as_word())]
#[case(|batch: &ProposedBatch| batch.transactions()[0].id().as_word())]
#[case(|batch: &ProposedBatch| batch.transactions()[0].input_notes().commitment())]
#[case(|batch: &ProposedBatch| batch.transactions()[0].output_notes().commitment())]
fn batch_kernel_rejects_tampered_advice(
    #[case] key: fn(&ProposedBatch) -> Word,
) -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let override_advice = tampered_advice_for(&batch, key(&batch));

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert!(result.is_err(), "kernel must abort on tampered advice");

    Ok(())
}

/// A transaction header of the wrong length is rejected before it is piped into the fixed-size
/// per-transaction slot, rather than relying on the hash check alone.
#[test]
fn batch_kernel_rejects_invalid_tx_header_length() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let tx_id = batch.transactions()[0].id().as_word();
    let blob = vec![Felt::from(0u32); 2 * TransactionCommitments::ELEMENTS_LEN];
    let override_advice = AdviceInputs::default().with_map([(tx_id, blob)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_TX_HEADER_INVALID_LENGTH);

    Ok(())
}

/// A batch with more transactions than the kernel's per-transaction regions can hold is rejected
/// before the kernel runs.
#[test]
fn batch_executor_rejects_too_many_transactions() -> anyhow::Result<()> {
    let TestSetup { chain, account1, .. } = setup_chain();
    let block1 = chain.block_header(1);

    // Chain the transactions against a single account: each one picks up where the previous left
    // off, so they merge into one account update and stay under `MAX_ACCOUNTS_PER_BATCH`.
    let num_transactions = MAX_TRANSACTIONS_PER_BATCH + 1;
    let mut transactions = Vec::with_capacity(num_transactions);
    let mut state_commitment = Word::empty();
    for i in 0..num_transactions {
        let next_state_commitment = Word::from([i as u32 + 1, 0, 0, 0]);
        transactions.push(Arc::new(
            MockProvenTxBuilder::with_account(
                account1.id(),
                state_commitment,
                next_state_commitment,
            )
            .reference_block(&block1)
            .build()?,
        ));
        state_commitment = next_state_commitment;
    }

    let batch = ProposedBatch::new_unverified(
        transactions,
        block1,
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    let err = BatchExecutor::new()
        .execute(batch)
        .expect_err("expected the batch execution to reject the oversized transaction list");
    assert_matches!(err, ProvenBatchError::TooManyTransactions(count) if count == num_transactions);

    Ok(())
}

// GLOBAL NOTE LIST BINDING NEGATIVE TESTS
// ================================================================================================
//
// These corrupt the host-provided global note lists and assert the kernel's binding rejects them.

/// Omitting an input note from the global list makes its per-transaction lookup fail.
#[test]
fn batch_kernel_rejects_input_note_missing_from_list() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let mut blob = advice_blob_for(&batch, *INPUT_NOTE_LIST_KEY);
    blob.truncate(blob.len() - FELTS_PER_NOTE_ENTRY); // drop the last (highest-nullifier) note
    let override_advice = AdviceInputs::default().with_map([(*INPUT_NOTE_LIST_KEY, blob)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_INPUT_NOTE_NOT_IN_LIST);

    Ok(())
}

/// A duplicate entry breaks the strict-sorted (no-duplicate) invariant.
#[test]
fn batch_kernel_rejects_duplicated_input_note_list_entry() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let blob = advice_blob_for(&batch, *INPUT_NOTE_LIST_KEY);
    // Prepend a copy of the first entry, so two equal nullifiers are adjacent.
    let mut duplicated: Vec<Felt> = blob[0..FELTS_PER_NOTE_ENTRY].to_vec();
    duplicated.extend_from_slice(&blob);
    let override_advice = AdviceInputs::default().with_map([(*INPUT_NOTE_LIST_KEY, duplicated)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_NOTE_LIST_NOT_SORTED);

    Ok(())
}

/// Two entries in descending nullifier order break the strict-sorted invariant, pinning the
/// direction the sortedness check asserts.
#[test]
fn batch_kernel_rejects_descending_input_note_list() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let blob = advice_blob_for(&batch, *INPUT_NOTE_LIST_KEY);
    assert!(
        blob.len() >= 2 * FELTS_PER_NOTE_ENTRY,
        "the batch should have at least two notes"
    );
    // Swap the first two (distinct, ascending) entries so the pair is strictly descending.
    let mut swapped = blob[FELTS_PER_NOTE_ENTRY..2 * FELTS_PER_NOTE_ENTRY].to_vec();
    swapped.extend_from_slice(&blob[0..FELTS_PER_NOTE_ENTRY]);
    swapped.extend_from_slice(&blob[2 * FELTS_PER_NOTE_ENTRY..]);
    let override_advice = AdviceInputs::default().with_map([(*INPUT_NOTE_LIST_KEY, swapped)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_NOTE_LIST_NOT_SORTED);

    Ok(())
}

/// Altering a list entry's note id (without touching its nullifier) is caught when the kernel binds
/// the entry to the per-transaction note id.
#[test]
fn batch_kernel_rejects_input_note_list_id_mismatch() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let mut blob = advice_blob_for(&batch, *INPUT_NOTE_LIST_KEY);
    // Corrupt the first entry's note-id word only, so the entry is still found by nullifier.
    blob[4] += Felt::from(1u32);
    let override_advice = AdviceInputs::default().with_map([(*INPUT_NOTE_LIST_KEY, blob)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_INPUT_NOTE_ID_MISMATCH);

    Ok(())
}

/// Omitting an output note from the global list makes its per-transaction lookup fail.
#[test]
fn batch_kernel_rejects_output_note_missing_from_list() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let mut blob = advice_blob_for(&batch, *OUTPUT_NOTE_LIST_KEY);
    blob.truncate(blob.len() - FELTS_PER_NOTE_ENTRY); // drop the last (highest-note-id) output note
    let override_advice = AdviceInputs::default().with_map([(*OUTPUT_NOTE_LIST_KEY, blob)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_OUTPUT_NOTE_NOT_IN_LIST);

    Ok(())
}

/// Adding a consumed note's id to the output list as a phantom creation (which no transaction
/// performs) leaves the note expected-to-be-erased, tripping the consume-before-create gate.
#[test]
fn batch_kernel_rejects_consume_before_create() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    // Add tx2's unauthenticated input note id to the output list as a phantom creation.
    let phantom_created_id = mock_note(81).id().as_word();
    let mut entries = note_list_entries(&advice_blob_for(&batch, *OUTPUT_NOTE_LIST_KEY));
    entries.push((phantom_created_id, Word::empty()));
    let blob = note_list_blob_from(entries);
    let override_advice = AdviceInputs::default().with_map([(*OUTPUT_NOTE_LIST_KEY, blob)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_NOTE_CONSUMED_BEFORE_CREATED);

    Ok(())
}

/// An extra input-note list entry that no transaction consumes trips the epilogue sweep requiring
/// every entry to have been consumed (so the host cannot pad the list with phantom notes).
#[test]
fn batch_kernel_rejects_unconsumed_input_note() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    // Append an entry whose nullifier no transaction consumes, keeping the list strictly sorted.
    let mut entries = note_list_entries(&advice_blob_for(&batch, *INPUT_NOTE_LIST_KEY));
    entries.push((Word::from([u32::MAX; 4]), Word::empty()));
    let blob = note_list_blob_from(entries);
    let override_advice = AdviceInputs::default().with_map([(*INPUT_NOTE_LIST_KEY, blob)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_INPUT_NOTE_NOT_CONSUMED);

    Ok(())
}

/// An extra output-note list entry that no transaction creates trips the epilogue sweep requiring
/// every entry to have been created (the injected id matches no input note, so it is not linked
/// for erasure).
#[test]
fn batch_kernel_rejects_uncreated_output_note() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let mut entries = note_list_entries(&advice_blob_for(&batch, *OUTPUT_NOTE_LIST_KEY));
    entries.push((Word::from([u32::MAX; 4]), Word::empty()));
    let blob = note_list_blob_from(entries);
    let override_advice = AdviceInputs::default().with_map([(*OUTPUT_NOTE_LIST_KEY, blob)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_OUTPUT_NOTE_NOT_CREATED);

    Ok(())
}

/// A global input-note list longer than the maximum is rejected during load, before the (here
/// all-zero) entries are inspected.
#[test]
fn batch_kernel_rejects_oversized_input_note_list() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let blob = vec![Felt::from(0u32); (MAX_INPUT_NOTES_PER_BATCH + 1) * FELTS_PER_NOTE_ENTRY];
    let override_advice = AdviceInputs::default().with_map([(*INPUT_NOTE_LIST_KEY, blob)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_NOTE_LIST_TOO_LONG);

    Ok(())
}

/// Same as above for the output-note list.
#[test]
fn batch_kernel_rejects_oversized_output_note_list() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let blob = vec![Felt::from(0u32); (MAX_OUTPUT_NOTES_PER_BATCH + 1) * FELTS_PER_NOTE_ENTRY];
    let override_advice = AdviceInputs::default().with_map([(*OUTPUT_NOTE_LIST_KEY, blob)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_NOTE_LIST_TOO_LONG);

    Ok(())
}

/// A layer-1 tuple list longer than `MAX_TRANSACTIONS_PER_BATCH` is rejected before it is piped
/// and hash-checked against `BATCH_ID`.
#[test]
fn batch_kernel_rejects_too_many_transactions() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    // A layer-1 `(tx_id, account_id)` tuple is 8 felts.
    const FELTS_PER_TX_TUPLE: usize = 2 * WORD_SIZE;
    let blob = vec![Felt::from(0u32); (MAX_TRANSACTIONS_PER_BATCH + 1) * FELTS_PER_TX_TUPLE];
    let override_advice = AdviceInputs::default().with_map([(batch.id().as_word(), blob)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_TOO_MANY_TRANSACTIONS);

    Ok(())
}

/// A per-transaction note set longer than the maximum is rejected before it is piped and
/// hash-checked against the transaction's `INPUT_NOTES_COMMITMENT`.
#[test]
fn batch_kernel_rejects_too_many_notes_per_transaction() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let key = batch.transactions()[0].input_notes().commitment();
    let blob = vec![Felt::from(0u32); (MAX_INPUT_NOTES_PER_BATCH + 1) * FELTS_PER_NOTE_ENTRY];
    let override_advice = AdviceInputs::default().with_map([(key, blob)]);

    let result = BatchExecutor::new().execute_with_advice(batch, override_advice);
    assert_kernel_error(result, batch_kernel::ERR_BATCH_TX_TOO_MANY_NOTES);

    Ok(())
}
