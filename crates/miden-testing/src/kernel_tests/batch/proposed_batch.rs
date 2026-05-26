use alloc::sync::Arc;
use std::collections::BTreeMap;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId, AccountType};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::MerkleError;
use miden_protocol::errors::{BatchAccountUpdateError, ProposedBatchError};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachments,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::{
    InputNote,
    InputNoteCommitment,
    OutputNote,
    PartialBlockchain,
    RawOutputNote,
};
use miden_standards::note::P2idNoteStorage;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::note::NoteBuilder;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use super::proven_tx_builder::MockProvenTxBuilder;
use crate::utils::create_p2any_note;
use crate::{AccountState, Auth, MockChain, MockChainBuilder};

fn mock_account_id(num: u8) -> AccountId {
    AccountIdBuilder::new().build_with_rng(&mut SmallRng::from_seed([num; 32]))
}

pub fn mock_note(num: u8) -> Note {
    let sender = mock_account_id(num);
    NoteBuilder::new(sender, SmallRng::from_seed([num; 32])).build().unwrap()
}

pub fn mock_output_note(num: u8) -> OutputNote {
    RawOutputNote::Full(mock_note(num)).into_output_note().unwrap()
}

struct TestSetup {
    chain: MockChain,
    account1: Account,
    account2: Account,
    note1: Note,
}

fn setup_chain() -> TestSetup {
    let mut builder = MockChain::builder();
    let account1 = generate_account(&mut builder);
    let account2 = generate_account(&mut builder);
    let note1 = builder
        .add_p2id_note(account1.id(), account2.id(), &[FungibleAsset::mock(1)], NoteType::Public)
        .expect("adding p2id note1 should work");
    let mut chain = builder.build().expect("genesis should be valid");
    chain.prove_next_block().expect("valid setup");

    TestSetup { chain, account1, account2, note1 }
}

fn generate_account(chain: &mut MockChainBuilder) -> Account {
    let account_builder = Account::builder(rand::rng().random())
        .account_type(AccountType::Private)
        .with_component(MockAccountComponent::with_empty_slots());
    chain
        .add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
        .expect("failed to add pending account from builder")
}

/// Tests that a note created and consumed in the same batch are erased from the input and
/// output note commitments.
#[test]
fn empty_transaction_batch() -> anyhow::Result<()> {
    let TestSetup { chain, .. } = setup_chain();
    let block1 = chain.block_header(1);

    let error =
        ProposedBatch::new(vec![], block1, chain.latest_partial_blockchain(), BTreeMap::default())
            .unwrap_err();

    assert_matches!(error, ProposedBatchError::EmptyTransactionBatch);

    Ok(())
}

/// Tests that a note created and consumed in the same batch are erased from the input and
/// output note commitments.
#[test]
fn note_created_and_consumed_in_same_batch() -> anyhow::Result<()> {
    let TestSetup { mut chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);
    let block2 = chain.prove_next_block()?;

    let note = mock_note(40);
    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .output_notes(vec![RawOutputNote::Full(note.clone()).into_output_note().unwrap()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.to_commitment())
            .reference_block(&block1)
            .unauthenticated_notes(vec![note.clone()])
            .build()?;

    let batch = ProposedBatch::new(
        [tx1, tx2].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    assert_eq!(batch.input_notes().num_notes(), 0);
    assert_eq!(batch.output_notes().len(), 0);

    Ok(())
}

/// Notes with the same details but different metadata are not considered the same for batch
/// erasure.
#[test]
fn same_details_different_metadata_not_erased_from_batch() -> anyhow::Result<()> {
    let TestSetup { mut chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);
    let block2 = chain.prove_next_block()?;

    // create two notes with identical details (recipient, assets, attachments) but different
    // metadata, so they have distinct note IDs

    let output_note = NoteBuilder::new(mock_account_id(7), SmallRng::from_seed([7; 32]))
        .serial_number([1, 2, 3, 4u32].into())
        .tag(100)
        .note_type(NoteType::Public)
        .build()?;

    let input_note = Note::with_attachments(
        output_note.assets().clone(),
        output_note.metadata().partial_metadata().with_tag(NoteTag::from(200)),
        output_note.recipient().clone(),
        output_note.attachments().clone(),
    );

    let output_note_proven = RawOutputNote::Full(output_note.clone()).into_output_note().unwrap();

    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .output_notes(vec![output_note_proven.clone()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.to_commitment())
            .reference_block(&block1)
            .unauthenticated_notes(vec![input_note.clone()])
            .build()?;

    let batch = ProposedBatch::new(
        [tx1, tx2].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    assert_eq!(
        batch.input_notes().clone().into_vec(),
        vec![InputNoteCommitment::from(&InputNote::unauthenticated(input_note))],
    );
    assert_eq!(batch.output_notes()[0], output_note_proven);

    Ok(())
}

/// Two standards P2ID output notes with identical details but different metadata should both appear
/// in the batch.
#[test]
fn two_p2id_inputs_same_details_different_metadata_in_same_batch() -> anyhow::Result<()> {
    let TestSetup { mut chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);
    let block2 = chain.prove_next_block()?;

    let serial_num = Word::from([11, 22, 33, 44u32]);
    let recipient = P2idNoteStorage::new(account2.id()).into_recipient(serial_num);

    let note_300 = Note::with_attachments(
        NoteAssets::default(),
        PartialNoteMetadata::new(account1.id(), NoteType::Public).with_tag(NoteTag::from(300)),
        recipient.clone(),
        NoteAttachments::default(),
    );
    let note_301 = Note::with_attachments(
        NoteAssets::default(),
        PartialNoteMetadata::new(account1.id(), NoteType::Public).with_tag(NoteTag::from(301)),
        recipient,
        NoteAttachments::default(),
    );

    // Only metadata should be different.
    assert_eq!(note_300.assets(), note_301.assets());
    assert_ne!(note_300.metadata(), note_301.metadata());
    assert_eq!(note_300.recipient(), note_301.recipient());
    assert_eq!(note_300.attachments(), note_301.attachments());

    let tx =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .authenticated_notes(vec![note_300.clone(), note_301.clone()])
            .build()?;

    let batch = ProposedBatch::new(
        vec![Arc::new(tx)],
        block2.header().clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    assert_eq!(batch.input_notes().num_notes(), 2);

    Ok(())
}

/// Tests that an error is returned if the same unauthenticated input note appears multiple
/// times in different transactions.
#[test]
fn duplicate_unauthenticated_input_notes() -> anyhow::Result<()> {
    let TestSetup { chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);

    let note = mock_note(50);
    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .unauthenticated_notes(vec![note.clone()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.to_commitment())
            .reference_block(&block1)
            .unauthenticated_notes(vec![note.clone()])
            .build()?;

    let error = ProposedBatch::new(
        [tx1.clone(), tx2.clone()].into_iter().map(Arc::new).collect(),
        block1,
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )
    .unwrap_err();

    assert_matches!(error, ProposedBatchError::DuplicateInputNote {
        note_nullifier,
        first_transaction_id,
        second_transaction_id
      } if note_nullifier == note.nullifier() &&
        first_transaction_id == tx1.id() &&
        second_transaction_id == tx2.id()
    );

    Ok(())
}

/// Tests that an error is returned if the same authenticated input note appears multiple
/// times in different transactions.
#[test]
fn duplicate_authenticated_input_notes() -> anyhow::Result<()> {
    let TestSetup { mut chain, account1, account2, note1 } = setup_chain();
    let block1 = chain.block_header(1);
    let block2 = chain.prove_next_block()?;

    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .authenticated_notes(vec![note1.clone()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.to_commitment())
            .reference_block(&block1)
            .authenticated_notes(vec![note1.clone()])
            .build()?;

    let error = ProposedBatch::new(
        [tx1.clone(), tx2.clone()].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )
    .unwrap_err();

    assert_matches!(error, ProposedBatchError::DuplicateInputNote {
        note_nullifier,
        first_transaction_id,
        second_transaction_id
      } if note_nullifier == note1.nullifier() &&
        first_transaction_id == tx1.id() &&
        second_transaction_id == tx2.id()
    );

    Ok(())
}

/// Tests that an error is returned if the same input note appears multiple times in different
/// transactions as an unauthenticated or authenticated note.
#[test]
fn duplicate_mixed_input_notes() -> anyhow::Result<()> {
    let TestSetup { mut chain, account1, account2, note1 } = setup_chain();
    let block1 = chain.block_header(1);
    let block2 = chain.prove_next_block()?;

    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .unauthenticated_notes(vec![note1.clone()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.to_commitment())
            .reference_block(&block1)
            .authenticated_notes(vec![note1.clone()])
            .build()?;

    let error = ProposedBatch::new(
        [tx1.clone(), tx2.clone()].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )
    .unwrap_err();

    assert_matches!(error, ProposedBatchError::DuplicateInputNote {
        note_nullifier,
        first_transaction_id,
        second_transaction_id
      } if note_nullifier == note1.nullifier() &&
        first_transaction_id == tx1.id() &&
        second_transaction_id == tx2.id()
    );

    Ok(())
}

/// Tests that an error is returned if the same output note appears multiple times in different
/// transactions.
#[test]
fn duplicate_output_notes() -> anyhow::Result<()> {
    let TestSetup { chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);

    let note0 = mock_output_note(50);
    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .output_notes(vec![note0.clone()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.to_commitment())
            .reference_block(&block1)
            .output_notes(vec![note0.clone()])
            .build()?;

    let error = ProposedBatch::new(
        [tx1.clone(), tx2.clone()].into_iter().map(Arc::new).collect(),
        block1,
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )
    .unwrap_err();

    assert_matches!(error, ProposedBatchError::DuplicateOutputNote {
             note_id,
             first_transaction_id,
             second_transaction_id
           } if note_id == note0.id() &&
             first_transaction_id == tx1.id() &&
             second_transaction_id == tx2.id());

    Ok(())
}

/// Test that an unauthenticated input note for which a proof exists is converted into an
/// authenticated one and becomes part of the batch's input note commitment.
#[tokio::test]
async fn unauthenticated_note_converted_to_authenticated() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account1 = generate_account(&mut builder);
    let note1 = create_p2any_note(account1.id(), NoteType::Public, [], builder.rng_mut());
    let note2 = create_p2any_note(account1.id(), NoteType::Public, [], builder.rng_mut());
    let spawn_note = builder.add_spawn_note([&note1, &note2])?;
    let mut chain = builder.build()?;

    let tx = chain
        .build_tx_context(account1.clone(), &[spawn_note.id()], &[])?
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(note1.clone()),
            RawOutputNote::Full(note2.clone()),
        ])
        .build()?
        .execute()
        .await?;
    chain.add_pending_executed_transaction(&tx)?;

    // Note1 and note2 are included and therefore provable against block1.
    let block1 = chain.prove_next_block()?;
    let block2 = chain.prove_next_block()?;
    let block3 = chain.prove_next_block()?;

    assert_eq!(
        block1.body().output_notes().count(),
        2,
        "block 1 should contain note1 and note2"
    );
    assert!(
        block1.body().output_notes().any(|(_, note)| note.id() == note1.id()),
        "block 1 should contain note1"
    );
    assert!(
        block1.body().output_notes().any(|(_, note)| note.id() == note2.id()),
        "block 1 should contain note2"
    );

    // Consume the authenticated note as an unauthenticated one in the transaction.
    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(block2.header())
            .unauthenticated_notes(vec![note2.clone()])
            .build()?;

    let input_note1 = chain.get_public_note(&note1.id()).expect("note not found");
    let note_inclusion_proof1 = input_note1.proof().expect("note should be of type authenticated");

    let input_note2 = chain.get_public_note(&note2.id()).expect("note not found");
    let note_inclusion_proof2 = input_note2.proof().expect("note should be of type authenticated");

    // The partial blockchain will contain all blocks in the mock chain, in particular block2 which
    // both note inclusion proofs need for verification.
    let partial_blockchain = chain.latest_partial_blockchain();

    // Case 1: Error: A wrong proof is passed.
    // --------------------------------------------------------------------------------------------

    let error = ProposedBatch::new(
        [tx1.clone()].into_iter().map(Arc::new).collect(),
        block3.header().clone(),
        partial_blockchain.clone(),
        BTreeMap::from_iter([(input_note2.id(), note_inclusion_proof1.clone())]),
    )
    .unwrap_err();

    assert_matches!(error, ProposedBatchError::UnauthenticatedNoteAuthenticationFailed {
        note_id,
        block_num,
        source: MerkleError::ConflictingRoots { .. },
      } => {
          assert_eq!(note_id, note2.id());
          assert_eq!(block_num, block1.header().block_num());
      }
    );

    // Case 2: Error: The block referenced by the (valid) note inclusion proof is missing.
    // --------------------------------------------------------------------------------------------

    // Make a clone of the partial blockchain where block1 is missing.
    let mut mmr = partial_blockchain.mmr().clone();
    mmr.untrack(block1.header().block_num().as_usize());
    let blocks = partial_blockchain
        .block_headers()
        .filter(|header| header.block_num() != block1.header().block_num())
        .cloned();

    let error = ProposedBatch::new(
        [tx1.clone()].into_iter().map(Arc::new).collect(),
        block3.header().clone(),
        PartialBlockchain::new(mmr, blocks)
            .context("failed to build partial blockchain with missing block")?,
        BTreeMap::from_iter([(input_note2.id(), note_inclusion_proof2.clone())]),
    )
    .unwrap_err();

    assert_matches!(
        error,
        ProposedBatchError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
          block_number,
          note_id
        } => {
            assert_eq!(block_number, note_inclusion_proof2.location().block_num());
            assert_eq!(note_id, input_note2.id());
        }
    );

    // Case 3: Success: The correct proof is passed.
    // --------------------------------------------------------------------------------------------

    let batch = ProposedBatch::new(
        [tx1].into_iter().map(Arc::new).collect(),
        block3.header().clone(),
        partial_blockchain,
        BTreeMap::from_iter([(input_note2.id(), note_inclusion_proof2.clone())]),
    )?;

    // We expect the unauthenticated input note to have become an authenticated one,
    // meaning it is part of the input note commitment.
    assert_eq!(batch.input_notes().num_notes(), 1);
    assert!(
        batch
            .input_notes()
            .iter()
            .any(|commitment| commitment == &InputNoteCommitment::from(&input_note2))
    );
    assert_eq!(batch.output_notes().len(), 0);

    Ok(())
}

/// Test that an authenticated input note that is also created in the same batch does not error
/// and instead is marked as consumed.
/// - This requires a nullifier collision on the input and output note which is very unlikely in
///   practice.
/// - This makes the created note unspendable as its nullifier is added to the nullifier tree.
/// - The batch kernel cannot return an error in this case as it can't detect this condition due to
///   only having the nullifier for authenticated input notes _but_ not having the nullifier for
///   private output notes.
/// - We test this to ensure the kernel does something reasonable in this case and it is not an
///   attack vector.
#[test]
fn authenticated_note_created_in_same_batch() -> anyhow::Result<()> {
    let TestSetup { mut chain, account1, account2, note1 } = setup_chain();
    let block1 = chain.block_header(1);
    let block2 = chain.prove_next_block()?;

    let note0 = mock_note(50);
    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .output_notes(vec![RawOutputNote::Full(note0.clone()).into_output_note().unwrap()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.to_commitment())
            .reference_block(&block1)
            .authenticated_notes(vec![note1.clone()])
            .build()?;

    let batch = ProposedBatch::new(
        [tx1, tx2].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    assert_eq!(batch.input_notes().num_notes(), 1);
    assert_eq!(batch.output_notes().len(), 1);

    Ok(())
}

/// Test that multiple transactions against the same account
/// 1) can be correctly executed when in the right order,
/// 2) and that an error is returned if they are incorrectly ordered.
#[test]
fn multiple_transactions_against_same_account() -> anyhow::Result<()> {
    let TestSetup { chain, account1, .. } = setup_chain();
    let block1 = chain.block_header(1);

    // Use some random hash as the initial state commitment of tx1.
    let initial_state_commitment = Word::empty();
    let tx1 = MockProvenTxBuilder::with_account(
        account1.id(),
        initial_state_commitment,
        account1.to_commitment(),
    )
    .reference_block(&block1)
    .output_notes(vec![mock_output_note(0)])
    .build()?;

    // Use some random hash as the final state commitment of tx2.
    let final_state_commitment = mock_note(10).id().as_word();
    let tx2 = MockProvenTxBuilder::with_account(
        account1.id(),
        account1.to_commitment(),
        final_state_commitment,
    )
    .reference_block(&block1)
    .build()?;

    // Success: Transactions are correctly ordered.
    let batch = ProposedBatch::new(
        [tx1.clone(), tx2.clone()].into_iter().map(Arc::new).collect(),
        block1.clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    assert_eq!(batch.account_updates().len(), 1);
    // Assert that the initial state commitment from tx1 is used and the final state commitment
    // from tx2.
    assert_eq!(
        batch.account_updates().get(&account1.id()).unwrap().initial_state_commitment(),
        initial_state_commitment
    );
    assert_eq!(
        batch.account_updates().get(&account1.id()).unwrap().final_state_commitment(),
        final_state_commitment
    );

    // Error: Transactions are incorrectly ordered.
    let error = ProposedBatch::new(
        [tx2.clone(), tx1.clone()].into_iter().map(Arc::new).collect(),
        block1,
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )
    .unwrap_err();

    assert_matches!(
        error,
        ProposedBatchError::AccountUpdateError {
            source: BatchAccountUpdateError::AccountUpdateInitialStateMismatch(tx_id),
            ..
        } if tx_id == tx1.id()
    );

    Ok(())
}

/// Tests that the input and outputs notes commitment is correctly computed.
/// - Notes created and consumed in the same batch are erased from these commitments.
/// - The input note commitment is sorted by [`Nullifier`].
/// - The output note commitment is sorted by [`NoteId`].
#[test]
fn input_and_output_notes_commitment() -> anyhow::Result<()> {
    let TestSetup { chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);

    // Randomize the note IDs and nullifiers on each test run to make sure the sorting property
    // is tested with various inputs.
    let mut rng = rand::rng();
    // Generate a single random number and derive other unique numbers from it to avoid collisions.
    let note_num = rng.random();

    let note0 = mock_output_note(note_num);
    let note1 = mock_note(note_num.wrapping_add(1));
    let note2 = mock_output_note(note_num.wrapping_add(2));
    let note3 = mock_output_note(note_num.wrapping_add(3));
    let note4 = mock_note(note_num.wrapping_add(4));
    let note5 = mock_note(note_num.wrapping_add(5));
    let note6 = mock_note(note_num.wrapping_add(6));

    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .unauthenticated_notes(vec![note1.clone(), note5.clone()])
            .output_notes(vec![note0.clone()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.to_commitment())
            .reference_block(&block1)
            .unauthenticated_notes(vec![note4.clone(), note6.clone()])
            .output_notes(vec![
                RawOutputNote::Full(note1.clone()).into_output_note().unwrap(),
                note2.clone(),
                note3.clone(),
            ])
            .build()?;

    let batch = ProposedBatch::new(
        [tx1.clone(), tx2.clone()].into_iter().map(Arc::new).collect(),
        block1,
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    // We expect note1 to be erased from the input/output notes as it is created and consumed
    // in the batch.
    let mut expected_output_notes = [note0, note2, note3];
    // We expect a vector sorted by NoteId.
    expected_output_notes.sort_unstable_by_key(OutputNote::id);

    assert_eq!(batch.output_notes().len(), 3);
    assert_eq!(batch.output_notes(), expected_output_notes);

    let mut expected_input_notes = [
        InputNoteCommitment::from(&InputNote::unauthenticated(note4)),
        InputNoteCommitment::from(&InputNote::unauthenticated(note5)),
        InputNoteCommitment::from(&InputNote::unauthenticated(note6)),
    ];
    // We expect a vector sorted by Nullifier (since InputOutputNoteTracker is set up that way).
    expected_input_notes.sort_unstable_by_key(InputNoteCommitment::nullifier);

    // Input notes are sorted by the order in which they appeared in the batch.
    assert_eq!(batch.input_notes().num_notes(), 3);
    assert_eq!(batch.input_notes().clone().into_vec(), &expected_input_notes);

    Ok(())
}

/// Tests that the expiration block number of a batch is the minimum of all contained transactions.
#[test]
fn batch_expiration() -> anyhow::Result<()> {
    let TestSetup { chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);

    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .expiration_block_num(BlockNumber::from(35))
            .build()?;
    // This transaction has the smallest valid expiration block num that allows it to still be
    // included in the batch.
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.to_commitment())
            .reference_block(&block1)
            .expiration_block_num(block1.block_num() + 1)
            .build()?;

    let batch = ProposedBatch::new(
        [tx1, tx2].into_iter().map(Arc::new).collect(),
        block1.clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    assert_eq!(batch.batch_expiration_block_num(), block1.block_num() + 1);

    Ok(())
}

/// Tests that passing duplicate transactions in a batch returns an error.
#[test]
fn duplicate_transaction() -> anyhow::Result<()> {
    let TestSetup { chain, account1, .. } = setup_chain();
    let block1 = chain.block_header(1);

    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .expiration_block_num(BlockNumber::from(35))
            .build()?;

    let error = ProposedBatch::new(
        [tx1.clone(), tx1.clone()].into_iter().map(Arc::new).collect(),
        block1,
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )
    .unwrap_err();

    assert_matches!(error, ProposedBatchError::DuplicateTransaction { transaction_id } if transaction_id == tx1.id());

    Ok(())
}

/// Tests that transactions with a circular dependency between notes are accepted:
/// TX 1: Inputs [X] -> Outputs [Y]
/// TX 2: Inputs [Y] -> Outputs [X]
#[test]
fn circular_note_dependency() -> anyhow::Result<()> {
    let TestSetup { chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);

    let note_x = mock_note(20);
    let note_y = mock_note(30);

    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .unauthenticated_notes(vec![note_x.clone()])
            .output_notes(vec![RawOutputNote::Full(note_y.clone()).into_output_note().unwrap()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.to_commitment())
            .reference_block(&block1)
            .unauthenticated_notes(vec![note_y.clone()])
            .output_notes(vec![RawOutputNote::Full(note_x.clone()).into_output_note().unwrap()])
            .build()?;

    let batch = ProposedBatch::new(
        [tx1, tx2].into_iter().map(Arc::new).collect(),
        block1,
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    assert_eq!(batch.input_notes().num_notes(), 0);
    assert_eq!(batch.output_notes().len(), 0);

    Ok(())
}

/// Tests that expired transactions cannot be included in a batch.
#[test]
fn expired_transaction() -> anyhow::Result<()> {
    let TestSetup { chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);

    // This transaction expired at the batch's reference block.
    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.to_commitment())
            .reference_block(&block1)
            .expiration_block_num(block1.block_num())
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.to_commitment())
            .reference_block(&block1)
            .expiration_block_num(block1.block_num() + 3)
            .build()?;

    let error = ProposedBatch::new(
        [tx1.clone(), tx2].into_iter().map(Arc::new).collect(),
        block1.clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )
    .unwrap_err();

    assert_matches!(
        error,
        ProposedBatchError::ExpiredTransaction {
            transaction_id,
            transaction_expiration_num,
            reference_block_num
        }  if transaction_id == tx1.id() &&
            transaction_expiration_num == block1.block_num() &&
            reference_block_num == block1.block_num()
    );

    Ok(())
}

/// Tests that a NOOP transaction with state commitments X -> X against account A can appear
/// _before_ a state-updating transaction with state commitments X -> Y against account A.
#[test]
fn noop_tx_before_state_updating_tx_against_same_account() -> anyhow::Result<()> {
    let TestSetup { mut chain, account1, note1, .. } = setup_chain();
    let block1 = chain.block_header(1);
    let block2 = chain.prove_next_block()?;

    let random_final_state_commitment = Word::from([1, 2, 3, 4u32]);

    let note = mock_note(40);
    // consume a random note to make the transaction non-empty
    let noop_tx1 = MockProvenTxBuilder::with_account(
        account1.id(),
        account1.to_commitment(),
        account1.to_commitment(),
    )
    .reference_block(&block1)
    .authenticated_notes(vec![note1])
    .output_notes(vec![RawOutputNote::Full(note.clone()).into_output_note().unwrap()])
    .build()?;

    // sanity check
    assert_eq!(
        noop_tx1.account_update().initial_state_commitment(),
        noop_tx1.account_update().final_state_commitment()
    );

    let tx2 = MockProvenTxBuilder::with_account(
        account1.id(),
        account1.to_commitment(),
        random_final_state_commitment,
    )
    .reference_block(&block1)
    .unauthenticated_notes(vec![note.clone()])
    .build()?;

    let batch = ProposedBatch::new(
        [noop_tx1, tx2].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    let update = batch.account_updates().get(&account1.id()).unwrap();
    assert_eq!(update.initial_state_commitment(), account1.to_commitment());
    assert_eq!(update.final_state_commitment(), random_final_state_commitment);

    Ok(())
}

/// Tests that a transaction with a ref_block_commitment that does not match the commitment of the
/// block at the declared ref_block_num in the partial blockchain is rejected.
///
/// The test uses two independent MockChain instances so that the same block 1 has different block
/// commitments on each chain. A transaction built against chain_a's block 1 is then included in a
/// batch whose partial blockchain comes from chain_b, which has a different commitment for block 1.
#[test]
fn mismatched_ref_block_commitment_rejected() -> anyhow::Result<()> {
    let account_builder = Account::builder([42; 32])
        .account_type(AccountType::Private)
        .with_component(MockAccountComponent::with_empty_slots());

    // Build chain_a with the account.
    let mut builder1 = MockChain::builder();
    let account_a = builder1.add_account_from_builder(
        Auth::IncrNonce,
        account_builder.clone(),
        AccountState::Exists,
    )?;
    let mut chain_a = builder1.build()?;
    let chain_a_block1 = chain_a.prove_next_block()?;

    // Build chain_b with the exact same account.
    let mut builder2 = MockChain::builder();
    let account_b = builder2.add_account_from_builder(
        Auth::IncrNonce,
        account_builder,
        AccountState::Exists,
    )?;
    let mut chain_b = builder2.build()?;
    let chain_b_block1 = chain_b.prove_next_block()?;
    let chain_b_block2 = chain_b.prove_next_block()?;

    // Sanity checks: same account, different block commitments at block 1.
    assert_eq!(
        account_a.to_commitment(),
        account_b.to_commitment(),
        "accounts should have the same commitment"
    );
    assert_ne!(
        chain_a_block1.header().commitment(),
        chain_b_block1.header().commitment(),
        "block 1 should have different commitments on the two chains"
    );

    // Build a transaction that references chain_a's block 1. This means the transaction was
    // executed against a chain state that is incompatible with chain_b.
    let tx =
        MockProvenTxBuilder::with_account(account_a.id(), Word::empty(), account_a.to_commitment())
            .reference_block(chain_a_block1.header())
            .build()?;

    // chain_b's partial blockchain contains block 1, but with chain_b's commitment - not chain_a's.
    // ProposedBatch::new should reject this transaction because its ref_block_commitment doesn't
    // match the commitment of block 1 in the partial blockchain.
    let result = ProposedBatch::new(
        vec![Arc::new(tx.clone())],
        chain_b_block2.header().clone(),
        chain_b.latest_partial_blockchain(),
        BTreeMap::default(),
    )
    .unwrap_err();

    assert_matches!(
        result,
        ProposedBatchError::TransactionReferenceBlockCommitmentMismatch {
              transaction_id, block_num, expected_block_commitment, actual_block_commitment
          } => {
            assert_eq!(transaction_id, tx.id());
            assert_eq!(block_num, tx.ref_block_num());
            assert_eq!(actual_block_commitment, tx.ref_block_commitment());
            assert_eq!(expected_block_commitment, chain_b_block1.header().commitment());
        }
    );

    // Make sure the same error occurs when the block referenced by the transaction is the same as
    // the batch reference block.
    let (ref_block, partial_blockchain) = chain_b.selective_partial_blockchain(
        chain_b_block1.header().block_num(),
        [BlockNumber::GENESIS],
    )?;
    assert_eq!(
        ref_block.block_num(),
        tx.ref_block_num(),
        "tx and batch ref block num should match"
    );

    let result = ProposedBatch::new(
        vec![Arc::new(tx.clone())],
        ref_block.clone(),
        partial_blockchain,
        BTreeMap::default(),
    )
    .unwrap_err();

    assert_matches!(
        result,
        ProposedBatchError::TransactionReferenceBlockCommitmentMismatch {
            transaction_id, block_num, expected_block_commitment, actual_block_commitment
          } => {
            assert_eq!(transaction_id, tx.id());
            assert_eq!(block_num, tx.ref_block_num());
            assert_eq!(actual_block_commitment, tx.ref_block_commitment());
            assert_eq!(expected_block_commitment, ref_block.commitment());
        }
    );

    Ok(())
}

/// Tests that a NOOP transaction with state commitments X -> X against account A can appear
/// _after_ a state-updating transaction with state commitments X -> Y against account A.
#[test]
fn noop_tx_after_state_updating_tx_against_same_account() -> anyhow::Result<()> {
    let TestSetup { mut chain, account1, note1, .. } = setup_chain();
    let block1 = chain.block_header(1);
    let block2 = chain.prove_next_block()?;

    let random_final_state_commitment = Word::from([1, 2, 3, 4u32]);

    let note = mock_note(40);

    let tx1 = MockProvenTxBuilder::with_account(
        account1.id(),
        account1.to_commitment(),
        random_final_state_commitment,
    )
    .reference_block(&block1)
    .unauthenticated_notes(vec![note.clone()])
    .build()?;

    // consume a random note to make the transaction non-empty
    let noop_tx2 = MockProvenTxBuilder::with_account(
        account1.id(),
        random_final_state_commitment,
        random_final_state_commitment,
    )
    .reference_block(&block1)
    .authenticated_notes(vec![note1])
    .output_notes(vec![RawOutputNote::Full(note.clone()).into_output_note().unwrap()])
    .build()?;

    // sanity check
    assert_eq!(
        noop_tx2.account_update().initial_state_commitment(),
        noop_tx2.account_update().final_state_commitment()
    );

    let batch = ProposedBatch::new(
        [tx1, noop_tx2].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    let update = batch.account_updates().get(&account1.id()).unwrap();
    assert_eq!(update.initial_state_commitment(), account1.to_commitment());
    assert_eq!(update.final_state_commitment(), random_final_state_commitment);

    Ok(())
}
