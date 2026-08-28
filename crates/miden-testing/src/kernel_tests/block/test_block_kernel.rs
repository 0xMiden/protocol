use anyhow::Context;
use miden_block_prover::{BlockExecutor, LocalBlockProver};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::ProposedBlock;
use miden_protocol::note::NoteType;
use miden_protocol::{MIN_PROOF_SECURITY_LEVEL, Word};

use super::utils::MockChainBlockExt;
use crate::{Auth, MockChain};

// SETUP HELPERS
// ================================================================================================

/// Builds a two-batch block with realistic inputs and outputs. The skeleton kernel does not inspect
/// any of this data, but the block is built end-to-end so the smoke tests exercise the real
/// `prepare_inputs` path that the verification PRs will eventually consume.
async fn two_batch_block() -> anyhow::Result<ProposedBlock> {
    let mut builder = MockChain::builder();
    let account0 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let note0 =
        builder.add_p2any_note(account0.id(), NoteType::Public, [FungibleAsset::mock(42)])?;
    let note1 =
        builder.add_p2any_note(account1.id(), NoteType::Public, [FungibleAsset::mock(42)])?;
    let chain = builder.build()?;

    let proven_tx0 =
        chain.create_authenticated_notes_proven_tx(account0.id(), [note0.id()]).await?;
    let proven_tx1 =
        chain.create_authenticated_notes_proven_tx(account1.id(), [note1.id()]).await?;

    let batches = [chain.create_batch(vec![proven_tx0])?, chain.create_batch(vec![proven_tx1])?];
    let block_inputs = chain.get_block_inputs(&batches)?;

    ProposedBlock::new(block_inputs, batches.to_vec()).context("failed to propose block")
}

// TESTS
// ================================================================================================

/// The skeleton block kernel drops its public inputs and exits, leaving the all-zero word output
/// region. This test exercises the full plumbing path (build a realistic `ProposedBlock`, execute
/// the block kernel via `BlockExecutor`, parse the outputs) and asserts that the contract holds:
/// the kernel runs to completion and emits the empty word shape.
#[tokio::test]
async fn block_kernel_skeleton_emits_empty_outputs() -> anyhow::Result<()> {
    let block = two_batch_block().await?;

    let executed = BlockExecutor::new().execute(block).context("block execution failed")?;
    let output = executed.block_outputs();

    assert_eq!(output.block_commitment(), Word::empty());
    assert_eq!(output.nullifier_commitment(), Word::empty());

    Ok(())
}

/// Executing a block and then proving it produces the block kernel's execution proof.
#[tokio::test]
async fn block_executor_then_prover_produces_block_proof() -> anyhow::Result<()> {
    let block = two_batch_block().await?;

    let executed = BlockExecutor::new().execute(block).context("block execution failed")?;
    LocalBlockProver::new(MIN_PROOF_SECURITY_LEVEL)
        .prove(executed)
        .context("block proving failed")?;

    Ok(())
}
