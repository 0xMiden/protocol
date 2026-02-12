use core::slice;
use std::collections::BTreeMap;
use std::vec::Vec;

use anyhow::Context;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::batch::BatchNoteTree;
use miden_protocol::block::account_tree::AccountTree;
use miden_protocol::block::{BlockInputs, BlockNoteIndex, BlockNoteTree, ProposedBlock};
use miden_protocol::crypto::merkle::smt::Smt;
use miden_protocol::note::{NoteAttachment, NoteType};
use miden_protocol::transaction::InputNoteCommitment;
use miden_standards::note::P2idNote;

use crate::kernel_tests::block::utils::MockChainBlockExt;
use crate::utils::create_p2any_note;
use crate::{Auth, MockChain};

/// Tests the outputs of a proven block with transactions that consume notes, create output notes
/// and modify the account's state.
#[tokio::test]
async fn proven_block_success() -> anyhow::Result<()> {
    // Setup test with notes that produce output notes, in order to test the block note tree root
    // computation.
    // --------------------------------------------------------------------------------------------

    let asset = FungibleAsset::mock(100);
    let mut builder = MockChain::builder();

    let account0 = builder.add_existing_mock_account_with_assets(Auth::IncrNonce, [asset])?;
    let account1 = builder.add_existing_mock_account_with_assets(Auth::IncrNonce, [asset])?;
    let account2 = builder.add_existing_mock_account_with_assets(Auth::IncrNonce, [asset])?;
    let account3 = builder.add_existing_mock_account_with_assets(Auth::IncrNonce, [asset])?;

    let output_note0 = P2idNote::create(
        account0.id(),
        account0.id(),
        vec![asset],
        NoteType::Private,
        NoteAttachment::default(),
        builder.rng_mut(),
    )?;
    let output_note1 = P2idNote::create(
        account1.id(),
        account1.id(),
        vec![asset],
        NoteType::Private,
        NoteAttachment::default(),
        builder.rng_mut(),
    )?;
    let output_note2 = P2idNote::create(
        account2.id(),
        account2.id(),
        vec![asset],
        NoteType::Private,
        NoteAttachment::default(),
        builder.rng_mut(),
    )?;
    let output_note3 = P2idNote::create(
        account3.id(),
        account3.id(),
        vec![asset],
        NoteType::Private,
        NoteAttachment::default(),
        builder.rng_mut(),
    )?;

    let input_note0 = builder.add_spawn_note([&output_note0])?;
    let input_note1 = builder.add_spawn_note([&output_note1])?;
    let input_note2 = builder.add_spawn_note([&output_note2])?;
    let input_note3 = builder.add_spawn_note([&output_note3])?;

    let mut chain = builder.build()?;
    chain.prove_next_block()?;

    let tx0 = chain
        .create_authenticated_notes_proven_tx(account0.id(), [input_note0.id()])
        .await?;
    let tx1 = chain
        .create_authenticated_notes_proven_tx(account1.id(), [input_note1.id()])
        .await?;
    let tx2 = chain
        .create_authenticated_notes_proven_tx(account2.id(), [input_note2.id()])
        .await?;
    let tx3 = chain
        .create_authenticated_notes_proven_tx(account3.id(), [input_note3.id()])
        .await?;

    let batch0 = chain.create_batch(vec![tx0.clone(), tx1.clone()])?;
    let batch1 = chain.create_batch(vec![tx2.clone(), tx3.clone()])?;

    // Sanity check: Batches should have two output notes each.
    assert_eq!(batch0.output_notes().len(), 2);
    assert_eq!(batch1.output_notes().len(), 2);
    let batches = vec![batch0.clone(), batch1.clone()];

    let proposed_block = chain.propose_block(batches.clone()).context("failed to propose block")?;

    // Compute expected block note tree.
    // --------------------------------------------------------------------------------------------

    let batch0_iter = batch0
        .output_notes()
        .iter()
        .enumerate()
        .map(|(note_idx_in_batch, note)| (0, note_idx_in_batch, note));
    let batch1_iter = batch1
        .output_notes()
        .iter()
        .enumerate()
        .map(|(note_idx_in_batch, note)| (1, note_idx_in_batch, note));

    let expected_block_note_tree = BlockNoteTree::with_entries(batch0_iter.chain(batch1_iter).map(
        |(batch_idx, note_idx_in_batch, note)| {
            (
                BlockNoteIndex::new(batch_idx, note_idx_in_batch).unwrap(),
                note.id(),
                note.metadata(),
            )
        },
    ))
    .unwrap();

    // Compute expected nullifier root on the full SMT.
    // --------------------------------------------------------------------------------------------

    let mut expected_nullifier_tree = chain.nullifier_tree().clone();
    for nullifier in proposed_block.created_nullifiers().keys() {
        expected_nullifier_tree
            .mark_spent(*nullifier, proposed_block.block_num())
            .context("failed to mark nullifier as spent")?;
    }

    // Compute expected account root on the full account tree.
    // --------------------------------------------------------------------------------------------

    let mut expected_account_tree = chain.account_tree().clone();
    for (account_id, witness) in proposed_block.updated_accounts() {
        expected_account_tree
            .insert(*account_id, witness.final_state_commitment())
            .context("failed to insert account id into account tree")?;
    }

    // Prove block.
    // --------------------------------------------------------------------------------------------

    let proven_block = chain.prove_block(proposed_block.clone())?;

    // Check tree/chain commitments against expected values.
    // --------------------------------------------------------------------------------------------

    assert_eq!(proven_block.header().nullifier_root(), expected_nullifier_tree.root());
    assert_eq!(proven_block.header().account_root(), expected_account_tree.root());

    // The Mmr in MockChain adds a new block after it is sealed, so at this point the chain contains
    // block2 and has length 3.
    // This means the chain commitment of the mock chain must match the chain commitment of the
    // PartialBlockchain with chain length 2 when the prev block (block2) is added.
    assert_eq!(
        proven_block.header().chain_commitment(),
        chain.blockchain().peaks().hash_peaks()
    );

    assert_eq!(proven_block.header().note_root(), expected_block_note_tree.root());
    // Assert that the block note tree can be reconstructed.
    assert_eq!(proven_block.body().compute_block_note_tree(), expected_block_note_tree);

    // Check input notes / nullifiers.
    // --------------------------------------------------------------------------------------------

    assert_eq!(proven_block.body().created_nullifiers().len(), 4);
    assert!(proven_block.body().created_nullifiers().contains(&input_note0.nullifier()));
    assert!(proven_block.body().created_nullifiers().contains(&input_note1.nullifier()));
    assert!(proven_block.body().created_nullifiers().contains(&input_note2.nullifier()));
    assert!(proven_block.body().created_nullifiers().contains(&input_note3.nullifier()));

    // Check output notes.
    // --------------------------------------------------------------------------------------------

    assert_eq!(proven_block.body().output_note_batches().len(), 2);
    assert_eq!(
        proven_block.body().output_note_batches()[0],
        batch0.output_notes().iter().cloned().enumerate().collect::<Vec<_>>()
    );
    assert_eq!(
        proven_block.body().output_note_batches()[1],
        batch1.output_notes().iter().cloned().enumerate().collect::<Vec<_>>()
    );

    // Check account updates.
    // --------------------------------------------------------------------------------------------

    // The block-level account updates should be the same as the ones on transaction-level.
    for (tx, batch) in [(&tx0, &batch0), (&tx1, &batch0), (&tx2, &batch1), (&tx3, &batch1)] {
        let updated_account = tx.account_id();
        let block_account_update = proven_block
            .body()
            .updated_accounts()
            .iter()
            .find(|update| update.account_id() == updated_account)
            .expect("account should have been updated in the block");

        assert_eq!(
            block_account_update.final_state_commitment(),
            batch.account_updates().get(&updated_account).unwrap().final_state_commitment()
        );
    }

    Ok(())
}

/// Tests that an unauthenticated note is erased when it is created in the same block.
///
/// The high level test setup is that there are four transactions split in two batches:
/// tx0 (batch0): consume note0 -> create output_note0.
/// tx1 (batch1): consume output_note0.
/// tx2 (batch0): consume note2 -> create output_note2.
/// tx3 (batch0): consume note3 -> create output_note3.
///
/// The expected result is that output_note0 is erased from the set of output notes of the block.
///
/// We also test that the batch note tree containing the output generating transactions is a subtree
/// of the subtree of the overall block note tree computed from the block's output notes.
#[tokio::test]
async fn proven_block_erasing_unauthenticated_notes() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account0 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account2 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account3 = builder.add_existing_mock_account(Auth::IncrNonce)?;

    // The builder will use an rng which randomizes the note IDs and therefore their position in the
    // output note batches. This is useful to test that the block note tree is correctly
    // computed no matter at what index the erased note ends up in.
    let output_note0 = create_p2any_note(account0.id(), NoteType::Private, [], builder.rng_mut());
    let output_note2 = create_p2any_note(account2.id(), NoteType::Private, [], builder.rng_mut());
    let output_note3 = create_p2any_note(account3.id(), NoteType::Private, [], builder.rng_mut());

    // Sanity check that these notes have different IDs.
    assert_ne!(output_note0.id(), output_note2.id());
    assert_ne!(output_note2.id(), output_note3.id());

    // Create notes that, when consumed, will create the above corresponding output notes.
    let note0 = builder.add_spawn_note([&output_note0])?;
    let note2 = builder.add_spawn_note([&output_note2])?;
    let note3 = builder.add_spawn_note([&output_note3])?;
    let chain = builder.build()?;

    let tx0 = chain.create_authenticated_notes_proven_tx(account0.id(), [note0.id()]).await?;
    let tx1 = chain
        .create_unauthenticated_notes_proven_tx(account1.id(), slice::from_ref(&output_note0))
        .await?;
    let tx2 = chain.create_authenticated_notes_proven_tx(account2.id(), [note2.id()]).await?;
    let tx3 = chain.create_authenticated_notes_proven_tx(account3.id(), [note3.id()]).await?;

    assert_eq!(tx0.input_notes().num_notes(), 1);
    assert_eq!(tx0.output_notes().num_notes(), 1);
    assert_eq!(tx1.output_notes().num_notes(), 0);
    // The unauthenticated note is an input note of the tx.
    assert_eq!(tx1.input_notes().num_notes(), 1);

    // Sanity check: The input note of tx0 and output note of tx1 should be the same.
    assert_eq!(
        tx0.output_notes().get_note(0).id(),
        tx1.input_notes().get_note(0).header().unwrap().id()
    );

    let batch0 = chain.create_batch(vec![tx2.clone(), tx0.clone(), tx3.clone()])?;
    let batch1 = chain.create_batch(vec![tx1.clone()])?;

    // Sanity check: The batches and contained transactions should have the same input notes (sorted
    // by nullifier).
    let mut expected_input_notes: Vec<_> = tx2
        .input_notes()
        .iter()
        .chain(tx0.input_notes())
        .chain(tx3.input_notes())
        .cloned()
        .collect();
    expected_input_notes.sort_by_key(InputNoteCommitment::nullifier);

    assert_eq!(batch0.input_notes().clone().into_vec(), expected_input_notes);
    assert_eq!(batch1.input_notes(), tx1.input_notes());

    let batches = [batch0.clone(), batch1];
    // This block will use block2 as the reference block.
    let mut block_inputs = chain.get_block_inputs(&batches)?;

    // Remove the nullifier witness for output_note0 which will be erased, to check that the
    // proposed block does not _require_ nullifier witnesses for erased notes.
    block_inputs
        .nullifier_witnesses_mut()
        .remove(&output_note0.nullifier())
        .unwrap();

    let proposed_block = ProposedBlock::new(block_inputs.clone(), batches.to_vec())
        .context("failed to build proposed block")?;

    // The output note should have been erased, so we expect only the nullifiers of note0, note2 and
    // note3 to be created.
    assert_eq!(proposed_block.created_nullifiers().len(), 3);
    assert!(proposed_block.created_nullifiers().contains_key(&note0.nullifier()));
    assert!(proposed_block.created_nullifiers().contains_key(&note2.nullifier()));
    assert!(proposed_block.created_nullifiers().contains_key(&note3.nullifier()));

    // There are two batches in the block.
    assert_eq!(proposed_block.output_note_batches().len(), 2);
    // The second batch does not create any notes.
    assert!(proposed_block.output_note_batches()[1].is_empty());

    // Construct the expected output notes by collecting all output notes from all transactions in
    // batch0. We use a BTreeMap to sort by NoteId and then map each note to its index in this
    // sorted list.
    let mut expected_output_notes_batch0: Vec<_> = tx2
        .output_notes()
        .iter()
        .chain(tx0.output_notes().iter())
        .chain(tx3.output_notes().iter())
        .cloned()
        .map(|note| (note.id(), note))
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .enumerate()
        .map(|(note_idx, (_, note))| (note_idx, note))
        .collect();

    // Find and remove the erased note from the expected output notes.
    let erased_note_idx = expected_output_notes_batch0
        .iter()
        .find_map(|(idx, note)| (note.id() == output_note0.id()).then_some(idx))
        .copied()
        .unwrap();
    expected_output_notes_batch0.remove(erased_note_idx);

    let output_notes_batch0 = &proposed_block.output_note_batches()[0];
    // The first batch creates three notes, one of which is erased, so we expect 2 notes in the
    // output note batch.
    assert_eq!(output_notes_batch0.len(), 2);
    assert_eq!(output_notes_batch0, &expected_output_notes_batch0);

    let proven_block = chain.prove_block(proposed_block.clone())?;
    let actual_block_note_tree = proven_block.body().compute_block_note_tree();

    // Remove the erased note to get the expected batch note tree.
    let mut batch_tree = BatchNoteTree::with_contiguous_leaves(
        batch0.output_notes().iter().map(|note| (note.id(), note.metadata())),
    )
    .unwrap();
    batch_tree.remove(erased_note_idx as u64).unwrap();

    let mut expected_block_note_tree = BlockNoteTree::empty();
    expected_block_note_tree.insert_batch_note_subtree(0, batch_tree).unwrap();

    assert_eq!(expected_block_note_tree.root(), actual_block_note_tree.root());

    Ok(())
}

/// Tests that we can build empty blocks.
#[tokio::test]
async fn proven_block_succeeds_with_empty_batches() -> anyhow::Result<()> {
    // Setup a chain with a non-empty nullifier tree by consuming some notes.
    // --------------------------------------------------------------------------------------------

    let mut builder = MockChain::builder();
    let account0 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let note0 =
        builder.add_p2any_note(account0.id(), NoteType::Public, [FungibleAsset::mock(100)])?;
    let note1 =
        builder.add_p2any_note(account1.id(), NoteType::Public, [FungibleAsset::mock(100)])?;
    let mut chain = builder.build()?;

    let tx0 = chain.create_authenticated_notes_proven_tx(account0.id(), [note0.id()]).await?;
    let tx1 = chain.create_authenticated_notes_proven_tx(account1.id(), [note1.id()]).await?;

    chain.add_pending_proven_transaction(tx0);
    chain.add_pending_proven_transaction(tx1);
    let blockx = chain.prove_next_block()?;

    // Build a block with empty inputs whose account tree and nullifier tree root are not the empty
    // roots.
    // If they are the empty roots, we do not run the branches of code that handle empty blocks.
    // --------------------------------------------------------------------------------------------

    let latest_block_header = chain.latest_block_header();
    assert_eq!(latest_block_header.commitment(), blockx.header().commitment());

    // Sanity check: The account and nullifier tree roots should not be the empty tree roots.
    assert_ne!(latest_block_header.account_root(), AccountTree::<Smt>::default().root());
    assert_ne!(latest_block_header.nullifier_root(), Smt::new().root());

    let (_, empty_partial_blockchain) = chain.latest_selective_partial_blockchain([])?;
    assert_eq!(empty_partial_blockchain.block_headers().count(), 0);

    let block_inputs = BlockInputs::new(
        latest_block_header.clone(),
        empty_partial_blockchain.clone(),
        BTreeMap::default(),
        BTreeMap::default(),
        BTreeMap::default(),
    );

    let batches = Vec::new();
    let proposed_block =
        ProposedBlock::new(block_inputs, batches.clone()).context("failed to propose block")?;

    let proven_block = chain.prove_block(proposed_block.clone())?;

    // Nothing should be created or updated.
    assert_eq!(proven_block.body().updated_accounts().len(), 0);
    assert_eq!(proven_block.body().output_note_batches().len(), 0);
    assert_eq!(proven_block.body().created_nullifiers().len(), 0);
    assert!(proven_block.body().compute_block_note_tree().is_empty());

    // Account and nullifier root should match the previous block header's roots, since nothing has
    // changed.
    assert_eq!(proven_block.header().account_root(), latest_block_header.account_root());
    assert_eq!(proven_block.header().nullifier_root(), latest_block_header.nullifier_root());
    // Block note tree should be the empty root.
    assert_eq!(proven_block.header().note_root(), BlockNoteTree::empty().root());

    // The previous block header should have been added to the chain.
    assert_eq!(
        proven_block.header().chain_commitment(),
        chain.blockchain().peaks().hash_peaks()
    );
    assert_eq!(proven_block.header().block_num(), latest_block_header.block_num() + 1);

    Ok(())
}
