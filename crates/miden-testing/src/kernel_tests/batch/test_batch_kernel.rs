use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::BTreeMap;
use std::iter;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_core::deferred::{PrecompileError, PrecompileWitness, PrecompileWitnessEntry, Tag};
use miden_protocol::batch::ProposedBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::ProvenBatchError;
use miden_protocol::note::NoteType;
use miden_protocol::transaction::ProvenTransaction;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::vm::{ExecutionProof, PrecompileStatus};
use miden_protocol::{Felt, MIN_PROOF_SECURITY_LEVEL, Word};
use miden_tx::LocalTransactionProver;
use miden_tx_batch::{BatchExecutor, LocalBatchProver};
use miden_verifier::{HashFunction, StarkProof, VmProof};

use super::proposed_batch::{TestSetup, mock_note, mock_output_note, setup_chain};
use super::proven_tx_builder::MockProvenTxBuilder;
use crate::{Auth, MockChain};

// SETUP HELPERS
// ================================================================================================

/// Builds a two-transaction batch with realistic inputs and outputs. The skeleton kernel does not
/// inspect any of this data, but the batch is built end-to-end so the smoke test exercises the
/// real `prepare_inputs` path that the verification PR will eventually consume.
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

// TESTS
// ================================================================================================

/// The skeleton batch kernel drops its public inputs and exits, leaving the all-zero word output
/// region. This test exercises the full plumbing path (build a realistic `ProposedBatch`, execute
/// the batch kernel via `BatchExecutor`, parse the outputs) and asserts that the contract holds:
/// the kernel runs to completion and emits the empty word shape.
#[test]
fn batch_kernel_skeleton_emits_empty_outputs() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let executed = BatchExecutor::new().execute(batch).context("batch execution failed")?;
    let output = executed.batch_outputs();

    assert_eq!(output.input_notes_commitment(), Word::empty());
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
    let proven = LocalBatchProver::default().prove(executed).context("batch proving failed")?;

    assert_eq!(proven.id(), expected_id);

    Ok(())
}

/// Deserialization does not verify transaction proofs, so the executor must still reject an
/// invalid portable precompile witness before proof generation can be skipped.
#[test]
fn batch_executor_rejects_invalid_deserialized_precompile_witness() -> anyhow::Result<()> {
    let witness = PrecompileWitness::from_entries(vec![PrecompileWitnessEntry::Data {
        tag: Tag::CHUNKS,
        chunks: vec![[Felt::from(10_u32); 8]],
    }])?;
    let proof = ExecutionProof::new(
        VmProof {
            proof: StarkProof::new(Vec::new(), HashFunction::Blake3_256),
            precompile_root: witness.root_unchecked(),
        },
        PrecompileStatus::Deferred(witness),
    );

    let mut setup = setup_chain();
    let block1 = setup.chain.block_header(1);
    let block2 = setup.chain.prove_next_block()?;
    let transaction = MockProvenTxBuilder::with_account(
        setup.account1.id(),
        Word::empty(),
        setup.account1.to_commitment(),
    )
    .reference_block(&block1)
    .authenticated_notes(vec![setup.note1.clone()])
    .proof(proof)
    .build()?;
    let batch = ProposedBatch::new_unverified(
        vec![Arc::new(transaction)],
        block2.header().clone(),
        setup.chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;
    let decoded = ProposedBatch::read_from_bytes(&batch.to_bytes())?;

    let error = match BatchExecutor::new().execute(decoded) {
        Ok(_) => anyhow::bail!("invalid precompile witness passed batch execution"),
        Err(error) => error,
    };
    assert_matches!(
        error,
        ProvenBatchError::TransactionPrecompileWitnessInvalid { source, .. }
            if matches!(source.root(), PrecompileError::AssertionFailed)
    );

    Ok(())
}

/// The batch settles the outstanding precompile claims of its transactions: the executor collects
/// one witness per ECDSA transaction in transaction order, and the prover proves them all at once.
/// Falcon verifies in-circuit and therefore contributes no claim.
///
/// The four transactions are proven once and reused across the batch shapes, because proving them
/// dominates the runtime of this test.
#[tokio::test]
async fn prove_batch_settling_precompile_claims() -> anyhow::Result<()> {
    let schemes = vec![
        Auth::basic_ecdsa(),
        Auth::basic_ecdsa(),
        Auth::basic_falcon(),
        Auth::basic_falcon(),
    ];
    let (chain, transactions) = proven_transactions(schemes).await?;
    let (ecdsa, falcon) = (&transactions[..2], &transactions[2..]);

    // Each shape pairs transactions of different accounts, so their order in the batch is free.
    let shapes = [
        ("two ecdsa", vec![ecdsa[0].clone(), ecdsa[1].clone()], 2),
        ("ecdsa then falcon", vec![ecdsa[0].clone(), falcon[0].clone()], 1),
        ("falcon then ecdsa", vec![falcon[0].clone(), ecdsa[1].clone()], 1),
        ("two falcon", vec![falcon[0].clone(), falcon[1].clone()], 0),
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
