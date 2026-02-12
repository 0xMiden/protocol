use alloc::sync::Arc;
use std::collections::BTreeMap;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId, AccountStorageMode};
use miden_protocol::batch::ProposedBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::MerkleError;
use miden_protocol::errors::{BatchAccountUpdateError, ProposedBatchError};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::{InputNote, InputNoteCommitment, OutputNote, PartialBlockchain};
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
    OutputNote::Full(mock_note(num))
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
        .add_p2id_note(account1.id(), account2.id(), &[], NoteType::Public)
        .expect("adding p2id note1 should work");
    let mut chain = builder.build().expect("genesis should be valid");
    chain.prove_next_block().expect("valid setup");

    TestSetup { chain, account1, account2, note1 }
}

fn generate_account(chain: &mut MockChainBuilder) -> Account {
    let account_builder = Account::builder(rand::rng().random())
        .storage_mode(AccountStorageMode::Private)
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
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block1.commitment())
            .output_notes(vec![OutputNote::Full(note.clone())])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.commitment())
            .ref_block_commitment(block1.commitment())
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

/// Tests that an error is returned if the same unauthenticated input note appears multiple
/// times in different transactions.
#[test]
fn duplicate_unauthenticated_input_notes() -> anyhow::Result<()> {
    let TestSetup { chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);

    let note = mock_note(50);
    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block1.commitment())
            .unauthenticated_notes(vec![note.clone()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.commitment())
            .ref_block_commitment(block1.commitment())
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
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block1.commitment())
            .authenticated_notes(vec![note1.clone()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.commitment())
            .ref_block_commitment(block1.commitment())
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
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block1.commitment())
            .unauthenticated_notes(vec![note1.clone()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.commitment())
            .ref_block_commitment(block1.commitment())
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
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block1.commitment())
            .output_notes(vec![note0.clone()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.commitment())
            .ref_block_commitment(block1.commitment())
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
            OutputNote::Full(note1.clone()),
            OutputNote::Full(note2.clone()),
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
        block1
            .body()
            .output_notes()
            .any(|(_, note)| note.commitment() == note1.commitment()),
        "block 1 should contain note1"
    );
    assert!(
        block1
            .body()
            .output_notes()
            .any(|(_, note)| note.commitment() == note2.commitment()),
        "block 1 should contain note2"
    );

    // Consume the authenticated note as an unauthenticated one in the transaction.
    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block2.header().commitment())
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
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block1.commitment())
            .output_notes(vec![OutputNote::Full(note0.clone())])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.commitment())
            .ref_block_commitment(block1.commitment())
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
        account1.commitment(),
    )
    .ref_block_commitment(block1.commitment())
    .output_notes(vec![mock_output_note(0)])
    .build()?;

    // Use some random hash as the final state commitment of tx2.
    let final_state_commitment = mock_note(10).commitment();
    let tx2 = MockProvenTxBuilder::with_account(
        account1.id(),
        account1.commitment(),
        final_state_commitment,
    )
    .ref_block_commitment(block1.commitment())
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
/// - The input note commitment is sorted by the order in which the notes appeared in the batch.
/// - The output note commitment is sorted by [`NoteId`].
#[test]
fn input_and_output_notes_commitment() -> anyhow::Result<()> {
    let TestSetup { chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);

    let note0 = mock_output_note(50);
    let note1 = mock_note(60);
    let note2 = mock_output_note(70);
    let note3 = mock_output_note(80);
    let note4 = mock_note(90);
    let note5 = mock_note(100);

    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block1.commitment())
            .unauthenticated_notes(vec![note1.clone(), note5.clone()])
            .output_notes(vec![note0.clone()])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.commitment())
            .ref_block_commitment(block1.commitment())
            .unauthenticated_notes(vec![note4.clone()])
            .output_notes(vec![OutputNote::Full(note1.clone()), note2.clone(), note3.clone()])
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

    // Input notes are sorted by the order in which they appeared in the batch.
    assert_eq!(batch.input_notes().num_notes(), 2);
    assert_eq!(
        batch.input_notes().clone().into_vec(),
        &[
            InputNoteCommitment::from(&InputNote::unauthenticated(note5)),
            InputNoteCommitment::from(&InputNote::unauthenticated(note4)),
        ]
    );

    Ok(())
}

/// Tests that the expiration block number of a batch is the minimum of all contained transactions.
#[test]
fn batch_expiration() -> anyhow::Result<()> {
    let TestSetup { chain, account1, account2, .. } = setup_chain();
    let block1 = chain.block_header(1);

    let tx1 =
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block1.commitment())
            .expiration_block_num(BlockNumber::from(35))
            .build()?;
    // This transaction has the smallest valid expiration block num that allows it to still be
    // included in the batch.
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.commitment())
            .ref_block_commitment(block1.commitment())
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
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block1.commitment())
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
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block1.commitment())
            .unauthenticated_notes(vec![note_x.clone()])
            .output_notes(vec![OutputNote::Full(note_y.clone())])
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.commitment())
            .ref_block_commitment(block1.commitment())
            .unauthenticated_notes(vec![note_y.clone()])
            .output_notes(vec![OutputNote::Full(note_x.clone())])
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
        MockProvenTxBuilder::with_account(account1.id(), Word::empty(), account1.commitment())
            .ref_block_commitment(block1.commitment())
            .expiration_block_num(block1.block_num())
            .build()?;
    let tx2 =
        MockProvenTxBuilder::with_account(account2.id(), Word::empty(), account2.commitment())
            .ref_block_commitment(block1.commitment())
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
        account1.commitment(),
        account1.commitment(),
    )
    .ref_block_commitment(block1.commitment())
    .authenticated_notes(vec![note1])
    .output_notes(vec![OutputNote::Full(note.clone())])
    .build()?;

    // sanity check
    assert_eq!(
        noop_tx1.account_update().initial_state_commitment(),
        noop_tx1.account_update().final_state_commitment()
    );

    let tx2 = MockProvenTxBuilder::with_account(
        account1.id(),
        account1.commitment(),
        random_final_state_commitment,
    )
    .ref_block_commitment(block1.commitment())
    .unauthenticated_notes(vec![note.clone()])
    .build()?;

    let batch = ProposedBatch::new(
        [noop_tx1, tx2].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?;

    let update = batch.account_updates().get(&account1.id()).unwrap();
    assert_eq!(update.initial_state_commitment(), account1.commitment());
    assert_eq!(update.final_state_commitment(), random_final_state_commitment);

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
        account1.commitment(),
        random_final_state_commitment,
    )
    .ref_block_commitment(block1.commitment())
    .unauthenticated_notes(vec![note.clone()])
    .build()?;

    // consume a random note to make the transaction non-empty
    let noop_tx2 = MockProvenTxBuilder::with_account(
        account1.id(),
        random_final_state_commitment,
        random_final_state_commitment,
    )
    .ref_block_commitment(block1.commitment())
    .authenticated_notes(vec![note1])
    .output_notes(vec![OutputNote::Full(note.clone())])
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
    assert_eq!(update.initial_state_commitment(), account1.commitment());
    assert_eq!(update.final_state_commitment(), random_final_state_commitment);

    Ok(())
}
