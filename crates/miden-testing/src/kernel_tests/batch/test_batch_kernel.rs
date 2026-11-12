use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::BTreeMap;
use std::iter;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::{ProposedBatchError, TransactionVerifierError};
use miden_protocol::note::NoteType;
use miden_protocol::transaction::ProvenTransaction;
use miden_protocol::vm::{ExecutionProof, PrecompileStatus};
use miden_protocol::{MIN_PROOF_SECURITY_LEVEL, PROTOCOL_PROOF_HASH, Word};
use miden_tx::LocalTransactionProver;
use miden_tx_batch::{BatchExecutor, LocalBatchProver};

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

/// Executes and proves one transaction per given auth scheme, including in-kernel settlement of
/// the signature checks' precompile claims.
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
    assert_eq!(proven.proof().vm().proof.hash_fn(), PROTOCOL_PROOF_HASH);

    Ok(())
}

/// A batch accepts complete transaction proofs with and without precompile checks. Each transaction
/// has already settled its own claims, so the batch proof carries no separate precompile work.
#[tokio::test]
async fn prove_batch_with_settled_transaction_precompiles() -> anyhow::Result<()> {
    let schemes = vec![Auth::basic_ecdsa(), Auth::basic_ecdsa(), Auth::IncrNonce];
    let (chain, transactions) = proven_transactions(schemes).await?;
    let (ecdsa, no_claim) = (&transactions[..2], &transactions[2]);

    // All transactions belong to different accounts, so their order in a batch is free.
    let shapes = [
        (
            "ecdsa, no claim, ecdsa",
            vec![ecdsa[0].clone(), no_claim.clone(), ecdsa[1].clone()],
        ),
        ("no claim", vec![no_claim.clone()]),
    ];

    for (shape, transactions) in shapes {
        for transaction in &transactions {
            assert!(matches!(transaction.proof().precompile(), PrecompileStatus::Empty), "{shape}");
        }
        let batch = propose_batch(&chain, transactions).context(shape)?;
        let executed = BatchExecutor::new().execute(batch).context(shape)?;
        let proven = LocalBatchProver::default().prove(executed).context(shape)?;
        assert!(matches!(proven.proof().precompile(), PrecompileStatus::Empty), "{shape}");
    }

    Ok(())
}

/// Batch admission rejects both deferred work and a separate precompile proof, even when the
/// carried VM proof is otherwise valid.
#[tokio::test]
async fn propose_batch_rejects_external_precompile_work() -> anyhow::Result<()> {
    let (chain, transactions) = proven_transactions(vec![Auth::IncrNonce]).await?;
    let original = transactions[0].as_ref();
    for external_proof in [
        miden_protocol::testing::dummy_deferred_execution_proof(),
        miden_protocol::testing::dummy_precompile_execution_proof(),
    ] {
        let (_, _, precompile) = external_proof.into_parts();
        let tampered = ProvenTransaction::new(
            original.account_update().clone(),
            original.input_notes().iter().cloned(),
            original.output_notes().iter().cloned(),
            original.ref_block_num(),
            original.ref_block_commitment(),
            original.expiration_block_num(),
            ExecutionProof::from_parts(
                original.proof().compatibility().clone(),
                original.proof().vm().clone(),
                precompile,
            ),
            original.log_details().clone(),
            original.code_patch().clone(),
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
        .expect_err("batch accepted external precompile work");

        assert_matches!(
            error,
            ProposedBatchError::TransactionVerificationFailed {
                source: TransactionVerifierError::TransactionProofContainsPrecompiles,
                ..
            }
        );
    }

    Ok(())
}
