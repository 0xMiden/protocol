use core::slice;
use std::collections::BTreeMap;
use std::vec::Vec;

use assert_matches::assert_matches;
use miden_processor::crypto::MerklePath;
use miden_protocol::MAX_BATCHES_PER_BLOCK;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::{BlockInputs, BlockNumber, ProposedBlock};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::errors::ProposedBlockError;
use miden_protocol::note::{NoteAttachment, NoteInclusionProof, NoteType};
use miden_standards::note::P2idNote;
use miden_tx::LocalTransactionProver;

use crate::kernel_tests::block::utils::MockChainBlockExt;
use crate::utils::create_p2any_note;
use crate::{Auth, MockChain};

/// Tests that too many batches produce an error.
#[tokio::test]
async fn proposed_block_fails_on_too_many_batches() -> anyhow::Result<()> {
    let count = MAX_BATCHES_PER_BLOCK + 1;

    let (chain, batches) = {
        let mut builder = MockChain::builder();
        let mut accounts = Vec::new();
        let mut notes = Vec::new();
        for _ in 0..count {
            let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
            let note = builder.add_p2any_note(
                account.id(),
                NoteType::Public,
                [FungibleAsset::mock(42)],
            )?;

            accounts.push(account);
            notes.push(note);
        }

        let chain = builder.build()?;

        let mut batches = Vec::with_capacity(count);
        for i in 0..count {
            let proven_tx = chain
                .create_authenticated_notes_proven_tx(accounts[i].id(), [notes[i].id()])
                .await?;
            batches.push(chain.create_batch(vec![proven_tx])?);
        }

        (chain, batches)
    };

    let block_inputs = BlockInputs::new(
        chain.latest_block_header(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
        BTreeMap::default(),
        BTreeMap::default(),
    );

    let error = ProposedBlock::new(block_inputs, batches).unwrap_err();

    assert_matches!(error, ProposedBlockError::TooManyBatches);

    Ok(())
}

/// Tests that duplicate batches produce an error.
#[tokio::test]
async fn proposed_block_fails_on_duplicate_batches() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender_account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let note =
        builder.add_p2any_note(sender_account.id(), NoteType::Public, [FungibleAsset::mock(42)])?;
    let chain = builder.build()?;

    let proven_tx0 = chain
        .create_authenticated_notes_proven_tx(sender_account.id(), [note.id()])
        .await?;
    let batch0 = chain.create_batch(vec![proven_tx0])?;

    let batches = vec![batch0.clone(), batch0.clone()];

    let block_inputs = BlockInputs::new(
        chain.latest_block_header(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
        BTreeMap::default(),
        BTreeMap::default(),
    );

    let error = ProposedBlock::new(block_inputs, batches).unwrap_err();

    assert_matches!(error, ProposedBlockError::DuplicateBatch { batch_id } if batch_id == batch0.id());

    Ok(())
}

/// Tests that an expired batch produces an error.
#[tokio::test]
async fn proposed_block_fails_on_expired_batches() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account0 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let mut chain = builder.build()?;

    chain.prove_next_block()?;
    let block1_num = chain.block_header(1).block_num();

    let tx0 = chain.create_expiring_proven_tx(account0.id(), block1_num + 5).await?;
    let tx1 = chain.create_expiring_proven_tx(account1.id(), block1_num + 1).await?;

    let batch0 = chain.create_batch(vec![tx0])?;
    let batch1 = chain.create_batch(vec![tx1])?;

    let _block2 = chain.prove_next_block()?;

    let batches = vec![batch0.clone(), batch1.clone()];

    // This block's number is 3 (the previous block is block 2), which means batch 1, which expires
    // at block 2 (due to tx1), will be flagged as expired.
    let block_inputs = chain.get_block_inputs(&batches).expect("failed to get block inputs");
    let error = ProposedBlock::new(block_inputs.clone(), batches.clone()).unwrap_err();

    assert_matches!(
        error,
        ProposedBlockError::ExpiredBatch {
            batch_id,
            batch_expiration_block_num,
            current_block_num
        } if batch_id == batch1.id() &&
          batch_expiration_block_num.as_u32() == 2 &&
          current_block_num.as_u32() == 3
    );

    Ok(())
}

/// Tests that a timestamp at or before the previous block header produces an error.
#[tokio::test]
async fn proposed_block_fails_on_timestamp_not_increasing_monotonically() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let chain = builder.build()?;
    let proven_tx0 = chain.create_authenticated_notes_proven_tx(account, []).await?;

    let batch0 = chain.create_batch(vec![proven_tx0])?;
    let batches = vec![batch0];
    // Mock BlockInputs.
    let block_inputs = BlockInputs::new(
        chain.latest_block_header(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
        BTreeMap::default(),
        BTreeMap::default(),
    );

    let prev_block_timestamp = block_inputs.prev_block_header().timestamp();

    let error =
        ProposedBlock::new_at(block_inputs.clone(), batches.clone(), prev_block_timestamp - 1)
            .unwrap_err();
    assert_matches!(error, ProposedBlockError::TimestampDoesNotIncreaseMonotonically { .. });

    let error = ProposedBlock::new_at(block_inputs, batches, prev_block_timestamp).unwrap_err();
    assert_matches!(error, ProposedBlockError::TimestampDoesNotIncreaseMonotonically { .. });

    Ok(())
}

/// Tests that a partial blockchain that is not at the state of the previous block header produces
/// an error.
#[tokio::test]
async fn proposed_block_fails_on_partial_blockchain_and_prev_block_inconsistency()
-> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let chain = builder.build()?;
    let proven_tx0 = chain.create_authenticated_notes_proven_tx(account, []).await?;

    let batch0 = chain.create_batch(vec![proven_tx0])?;
    let batches = vec![batch0];

    // Select the partial blockchain which is valid for the current block but pass the next block in
    // the chain, which is an inconsistent combination.
    let mut partial_blockchain = chain.latest_partial_blockchain();
    let block2 = chain.clone().prove_next_block()?;

    let block_inputs = BlockInputs::new(
        block2.header().clone(),
        partial_blockchain.clone(),
        BTreeMap::default(),
        BTreeMap::default(),
        BTreeMap::default(),
    );

    let error = ProposedBlock::new(block_inputs.clone(), batches.clone()).unwrap_err();
    assert_matches!(
        error,
        ProposedBlockError::ChainLengthNotEqualToPreviousBlockNumber {
            chain_length,
            prev_block_num
        } if chain_length == partial_blockchain.chain_length() &&
          prev_block_num == block2.header().block_num()
    );

    // Add an invalid value making the chain length equal to block2's number, but resulting in a
    // different chain commitment.
    partial_blockchain.partial_mmr_mut().add(block2.header().nullifier_root(), true);

    let block_inputs = BlockInputs::new(
        block2.header().clone(),
        partial_blockchain.clone(),
        BTreeMap::default(),
        BTreeMap::default(),
        BTreeMap::default(),
    );

    let error = ProposedBlock::new(block_inputs.clone(), batches.clone()).unwrap_err();
    assert_matches!(
        error,
        ProposedBlockError::ChainRootNotEqualToPreviousBlockChainCommitment { .. }
    );

    Ok(())
}

/// Tests that a partial blockchain that does not contain all reference blocks of the batches
/// produces an error.
#[tokio::test]
async fn proposed_block_fails_on_missing_batch_reference_block() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let mut chain = builder.build()?;
    chain.prove_next_block()?;

    let proven_tx0 = chain.create_authenticated_notes_proven_tx(account, []).await?;

    // This batch will reference the latest block with number 1.
    let batch0 = chain.create_batch(vec![proven_tx0.clone()])?;
    let batches = vec![batch0.clone()];

    let block2 = chain.prove_next_block()?;

    let (_, partial_blockchain) =
        chain.latest_selective_partial_blockchain([BlockNumber::GENESIS])?;

    // The proposed block references block 2 but the partial blockchain only contains block 0 but
    // not block 1 which is referenced by the batch.
    let block_inputs = BlockInputs::new(
        block2.header().clone(),
        partial_blockchain.clone(),
        BTreeMap::default(),
        BTreeMap::default(),
        BTreeMap::default(),
    );

    let error = ProposedBlock::new(block_inputs.clone(), batches.clone()).unwrap_err();
    assert_matches!(
        error,
        ProposedBlockError::BatchReferenceBlockMissingFromChain {
          reference_block_num,
          batch_id
        } if reference_block_num == batch0.reference_block_num() &&
          batch_id == batch0.id()
    );

    Ok(())
}

/// Tests that duplicate input notes across batches produce an error.
#[tokio::test]
async fn proposed_block_fails_on_duplicate_input_note() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account0 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let note0 = builder.add_p2any_note(account0.id(), NoteType::Public, [])?;
    let note1 = builder.add_p2any_note(account0.id(), NoteType::Public, [])?;
    let mut chain = builder.build()?;

    // These notes should have different IDs.
    assert_ne!(note0.id(), note1.id());

    // Add notes to the chain.
    chain.prove_next_block()?;

    // Create two different transactions against the same account consuming the same note.
    let tx0 = chain
        .create_authenticated_notes_proven_tx(account1.id(), [note0.id(), note1.id()])
        .await?;
    let tx1 = chain.create_authenticated_notes_proven_tx(account1.id(), [note0.id()]).await?;

    let batch0 = chain.create_batch(vec![tx0])?;
    let batch1 = chain.create_batch(vec![tx1])?;

    let batches = vec![batch0.clone(), batch1.clone()];

    let block_inputs = chain.get_block_inputs(&batches).expect("failed to get block inputs");

    let error = ProposedBlock::new(block_inputs.clone(), batches.clone()).unwrap_err();
    assert_matches!(error, ProposedBlockError::DuplicateInputNote { .. });

    Ok(())
}

/// Tests that duplicate output notes across batches produce an error.
#[tokio::test]
async fn proposed_block_fails_on_duplicate_output_note() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let output_note = create_p2any_note(account.id(), NoteType::Private, [], builder.rng_mut());

    // Create two different notes that will create the same output note. Their IDs will be different
    // due to having a different serial number generated from contained RNG.
    let note0 = builder.add_spawn_note([&output_note])?;
    let note1 = builder.add_spawn_note([&output_note])?;

    let mut chain = builder.build()?;
    chain.prove_next_block()?;

    // Create two different transactions against the same account creating the same note.
    // We use the same account because the sender of the created output note is set to the account
    // of the transaction, so it is essential we use the same account to produce a duplicate output
    // note.
    let tx0 = chain.create_authenticated_notes_proven_tx(account.id(), [note0.id()]).await?;
    let tx1 = chain.create_authenticated_notes_proven_tx(account.id(), [note1.id()]).await?;

    let batch0 = chain.create_batch(vec![tx0])?;
    let batch1 = chain.create_batch(vec![tx1])?;

    let batches = vec![batch0.clone(), batch1.clone()];

    let block_inputs = chain.get_block_inputs(&batches)?;

    let error = ProposedBlock::new(block_inputs.clone(), batches.clone()).unwrap_err();
    assert_matches!(error, ProposedBlockError::DuplicateOutputNote { .. });

    Ok(())
}

/// Tests that a missing note inclusion proof produces an error.
/// Also tests that an error is produced if the block that the note inclusion proof references is
/// not in the partial blockchain.
#[tokio::test]
async fn proposed_block_fails_on_invalid_proof_or_missing_note_inclusion_reference_block()
-> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account0 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let p2id_note = P2idNote::create(
        account0.id(),
        account1.id(),
        vec![],
        NoteType::Private,
        NoteAttachment::default(),
        builder.rng_mut(),
    )?;
    let spawn_note = builder.add_spawn_note([&p2id_note])?;
    let mut chain = builder.build()?;

    // This tx will use block1 as the reference block.
    let tx0 = chain
        .create_unauthenticated_notes_proven_tx(account1.id(), slice::from_ref(&p2id_note))
        .await?;

    // This batch will use block1 as the reference block.
    // With this setup, the block inputs need to contain a reference to block2 in order to prove
    // inclusion of the unauthenticated note.
    let batch0 = chain.create_batch(vec![tx0])?;

    // Add the P2ID note to the chain by consuming the SPAWN note. The note will hence be created as
    // part of block 2 and the note inclusion proof references that block.
    let tx = chain
        .build_tx_context(account0.id(), &[spawn_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    chain.add_pending_executed_transaction(&tx)?;
    let block2 = chain.prove_next_block()?;

    // Seal another block so that the next block will use this one as the reference block and block2
    // is only needed for the note inclusion proof so we can safely remove it to only trigger the
    // error condition we want to trigger.
    let _block3 = chain.prove_next_block()?;

    let batches = vec![batch0.clone()];

    let original_block_inputs = chain.get_block_inputs(&batches)?;

    // Error: Block referenced by note inclusion proof is not in partial blockchain.
    // --------------------------------------------------------------------------------------------

    let mut invalid_block_inputs = original_block_inputs.clone();
    invalid_block_inputs
        .partial_blockchain_mut()
        .partial_mmr_mut()
        .untrack(block2.header().block_num().as_usize());
    invalid_block_inputs
        .partial_blockchain_mut()
        .block_headers_mut()
        .remove(&block2.header().block_num())
        .expect("block2 should have been fetched");

    let error = ProposedBlock::new(invalid_block_inputs, batches.clone()).unwrap_err();
    assert_matches!(error, ProposedBlockError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
      block_number, note_id
    } => {
        assert_eq!(block_number, block2.header().block_num());
        assert_eq!(note_id, p2id_note.id());
    });

    // Error: Invalid note inclusion proof.
    // --------------------------------------------------------------------------------------------

    let original_note_proof = original_block_inputs
        .unauthenticated_note_proofs()
        .get(&p2id_note.id())
        .expect("note proof should have been fetched")
        .clone();
    let mut original_merkle_path = MerklePath::from(original_note_proof.note_path().clone());
    original_merkle_path.push(block2.header().commitment());
    // Add a random hash to the path to make it invalid.
    let invalid_note_path = SparseMerklePath::try_from(original_merkle_path).unwrap();
    let invalid_note_proof = NoteInclusionProof::new(
        original_note_proof.location().block_num(),
        original_note_proof.location().node_index_in_block(),
        invalid_note_path,
    )
    .unwrap();
    let mut invalid_block_inputs = original_block_inputs.clone();
    invalid_block_inputs
        .unauthenticated_note_proofs_mut()
        .insert(p2id_note.id(), invalid_note_proof);

    let error = ProposedBlock::new(invalid_block_inputs, batches.clone()).unwrap_err();
    assert_matches!(error, ProposedBlockError::UnauthenticatedNoteAuthenticationFailed { block_num, note_id, .. } if block_num == block2.header().block_num() && note_id == p2id_note.id());

    Ok(())
}

/// Tests that a missing note inclusion proof produces an error.
#[tokio::test]
async fn proposed_block_fails_on_missing_note_inclusion_proof() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account0 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    // Note that this note is not added to the chain state.
    let note0 = create_p2any_note(account0.id(), NoteType::Private, [], builder.rng_mut());
    let chain = builder.build()?;

    let tx0 = chain
        .create_unauthenticated_notes_proven_tx(account1.id(), slice::from_ref(&note0))
        .await?;

    let batch0 = chain.create_batch(vec![tx0])?;

    let batches = vec![batch0.clone()];

    // This will not include the note inclusion proof for note0, because the note has not been added
    // to the chain.
    let block_inputs = chain.get_block_inputs(&batches)?;

    let error = ProposedBlock::new(block_inputs, batches.clone()).unwrap_err();
    assert_matches!(error, ProposedBlockError::UnauthenticatedNoteConsumed { nullifier } if nullifier == note0.nullifier());

    Ok(())
}

/// Tests that a missing nullifier witness produces an error.
#[tokio::test]
async fn proposed_block_fails_on_missing_nullifier_witness() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let p2id_note =
        builder.add_p2any_note(account.id(), NoteType::Public, [FungibleAsset::mock(50)])?;
    let mut chain = builder.build()?;
    chain.prove_next_block()?;

    // This tx will use block1 as the reference block.
    let tx0 = chain
        .create_unauthenticated_notes_proven_tx(account.id(), slice::from_ref(&p2id_note))
        .await?;

    // This batch will use block1 as the reference block.
    let batch0 = chain.create_batch(vec![tx0])?;

    let batches = vec![batch0.clone()];

    let block_inputs = chain.get_block_inputs(&batches)?;

    // Error: Missing nullifier witness.
    // --------------------------------------------------------------------------------------------

    let mut invalid_block_inputs = block_inputs.clone();
    invalid_block_inputs
        .nullifier_witnesses_mut()
        .remove(&p2id_note.nullifier())
        .expect("nullifier should have been fetched");

    let error = ProposedBlock::new(invalid_block_inputs, batches.clone()).unwrap_err();
    assert_matches!(error, ProposedBlockError::NullifierProofMissing(nullifier) => {
        assert_eq!(nullifier, p2id_note.nullifier());
    });

    Ok(())
}

/// Tests that a nullifier witness pointing to a spent nullifier produces an error.
#[tokio::test]
async fn proposed_block_fails_on_spent_nullifier_witness() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account0 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let p2any_note =
        builder.add_p2any_note(account0.id(), NoteType::Public, [FungibleAsset::mock(50)])?;
    let mut chain = builder.build()?;
    chain.prove_next_block()?;

    // Consume the note with account 0 and add the transaction to a block.
    let tx0 = chain
        .create_authenticated_notes_proven_tx(account0.id(), [p2any_note.id()])
        .await?;
    chain.add_pending_proven_transaction(tx0);
    chain.prove_next_block()?;

    // Consume the (already consumed) note with account 1 and build a batch from it.
    let tx1 = chain
        .create_authenticated_notes_proven_tx(account1.id(), [p2any_note.id()])
        .await?;
    let batch1 = chain.create_batch(vec![tx1])?;
    let batches = vec![batch1];
    let block_inputs = chain.get_block_inputs(&batches)?;

    // The block inputs should contain a nullifier witness for the P2ANY note.
    assert!(block_inputs.nullifier_witnesses().contains_key(&p2any_note.nullifier()));

    let error = ProposedBlock::new(block_inputs, batches).unwrap_err();
    assert_matches!(error, ProposedBlockError::NullifierSpent(nullifier) => {
        assert_eq!(nullifier, p2any_note.nullifier())
    });

    Ok(())
}

/// Tests that multiple transactions against the same account that start from the same initial state
/// commitment but produce different final state commitments produce an error.
#[tokio::test]
async fn proposed_block_fails_on_conflicting_transactions_updating_same_account()
-> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let note0 =
        builder.add_p2any_note(account1.id(), NoteType::Public, [FungibleAsset::mock(100)])?;
    let note1 =
        builder.add_p2any_note(account1.id(), NoteType::Public, [FungibleAsset::mock(200)])?;
    let chain = builder.build()?;

    // These notes should have different IDs.
    assert_ne!(note0.id(), note1.id());

    // Create two different transactions against the same account consuming a different note so they
    // result in a different final state commitment for the account.
    let tx0 = chain.create_authenticated_notes_proven_tx(account1.id(), [note0.id()]).await?;
    let tx1 = chain.create_authenticated_notes_proven_tx(account1.id(), [note1.id()]).await?;

    let batch0 = chain.create_batch(vec![tx0])?;
    let batch1 = chain.create_batch(vec![tx1])?;

    let batches = vec![batch0.clone(), batch1.clone()];
    let block_inputs = chain.get_block_inputs(&batches).expect("failed to get block inputs");

    let error = ProposedBlock::new(block_inputs.clone(), batches).unwrap_err();
    assert_matches!(error, ProposedBlockError::ConflictingBatchesUpdateSameAccount {
      account_id,
      initial_state_commitment,
      first_batch_id,
      second_batch_id
    } if account_id == account1.id() &&
      initial_state_commitment == account1.initial_commitment() &&
      first_batch_id == batch0.id() &&
      second_batch_id == batch1.id()
    );

    Ok(())
}

/// Tests that a missing account witness produces an error.
#[tokio::test]
async fn proposed_block_fails_on_missing_account_witness() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let chain = builder.build()?;
    let tx0 = chain.create_authenticated_notes_proven_tx(account.id(), []).await?;

    let batch0 = chain.create_batch(vec![tx0])?;

    let batches = vec![batch0.clone()];

    // This will not include the note inclusion proof for note0, because the note has not been added
    // to the chain.
    let mut block_inputs = chain.get_block_inputs(&batches)?;
    block_inputs
        .account_witnesses_mut()
        .remove(&account.id())
        .expect("account witness should have been fetched");

    let error = ProposedBlock::new(block_inputs, batches.clone()).unwrap_err();
    assert_matches!(error, ProposedBlockError::MissingAccountWitness(account_id) if account_id == account.id());

    Ok(())
}

/// Tests that, given three transactions 0 -> 1 -> 2 which are executed against the same account and
/// build on top of each other produce an error when tx 1 is missing from the block.
#[tokio::test]
async fn proposed_block_fails_on_inconsistent_account_state_transition() -> anyhow::Result<()> {
    let asset = FungibleAsset::mock(200);

    let mut builder = MockChain::builder();
    let mut account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let note0 = builder.add_p2any_note(account.id(), NoteType::Public, [asset])?;
    let note1 = builder.add_p2any_note(account.id(), NoteType::Public, [asset])?;
    let note2 = builder.add_p2any_note(account.id(), NoteType::Public, [asset])?;
    let chain = builder.build()?;

    // Create three transactions on the same account that build on top of each other.
    let executed_tx0 = chain.create_authenticated_notes_tx(account.clone(), [note0.id()]).await?;

    account.apply_delta(executed_tx0.account_delta())?;
    // Builds a tx on top of the account state from tx0.
    let executed_tx1 = chain.create_authenticated_notes_tx(account.clone(), [note1.id()]).await?;

    account.apply_delta(executed_tx1.account_delta())?;
    // Builds a tx on top of the account state from tx1.
    let executed_tx2 = chain.create_authenticated_notes_tx(account.clone(), [note2.id()]).await?;

    // We will only include tx0 and tx2 and leave out tx1, which will trigger the error condition
    // that there is no transition from tx0 -> tx2.
    let tx0 = LocalTransactionProver::default().prove_dummy(executed_tx0.clone())?;
    let tx2 = LocalTransactionProver::default().prove_dummy(executed_tx2.clone())?;

    let batch0 = chain.create_batch(vec![tx0])?;
    let batch1 = chain.create_batch(vec![tx2])?;

    let batches = vec![batch0.clone(), batch1.clone()];
    let block_inputs = chain.get_block_inputs(&batches)?;

    let error = ProposedBlock::new(block_inputs, batches).unwrap_err();
    assert_matches!(error, ProposedBlockError::InconsistentAccountStateTransition {
      account_id,
      state_commitment,
      remaining_state_commitments
    } if account_id == account.id() &&
      state_commitment == executed_tx0.final_account().commitment() &&
      remaining_state_commitments == [executed_tx2.initial_account().commitment()]
    );

    Ok(())
}
