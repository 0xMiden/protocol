use core::slice;
use std::collections::BTreeMap;
use std::vec::Vec;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{Account, AccountId, AccountStorageMode};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::{BlockInputs, ProposedBlock};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::{ExecutedTransaction, OutputNote, TransactionHeader};
use miden_protocol::{Felt, FieldElement};
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::LocalTransactionProver;
use rand::Rng;

use super::utils::MockChainBlockExt;
use crate::{AccountState, Auth, MockChain, TxContextInput};

/// Tests that we can build empty blocks.
#[tokio::test]
async fn proposed_block_succeeds_with_empty_batches() -> anyhow::Result<()> {
    let mut chain = MockChain::builder().build()?;
    chain.prove_next_block()?;

    let block_inputs = BlockInputs::new(
        chain.latest_block_header(),
        chain.latest_partial_blockchain(),
        BTreeMap::default(),
        BTreeMap::default(),
        BTreeMap::default(),
    );
    let block = ProposedBlock::new(block_inputs, Vec::new()).context("failed to propose block")?;

    assert_eq!(block.transactions().count(), 0);
    assert_eq!(block.output_note_batches().len(), 0);
    assert_eq!(block.created_nullifiers().len(), 0);
    assert_eq!(block.batches().as_slice().len(), 0);

    Ok(())
}

/// Tests that a proposed block from two batches with one transaction each can be successfully
/// built.
#[tokio::test]
async fn proposed_block_basic_success() -> anyhow::Result<()> {
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

    let batch0 = chain.create_batch(vec![proven_tx0.clone()])?;
    let batch1 = chain.create_batch(vec![proven_tx1.clone()])?;

    let batches = [batch0, batch1];
    let block_inputs = chain.get_block_inputs(&batches)?;

    let proposed_block = ProposedBlock::new(block_inputs.clone(), batches.to_vec()).unwrap();

    assert_eq!(proposed_block.batches().as_slice(), batches);
    assert_eq!(proposed_block.block_num(), block_inputs.prev_block_header().block_num() + 1);
    let updated_accounts =
        proposed_block.updated_accounts().iter().cloned().collect::<BTreeMap<_, _>>();

    assert_eq!(updated_accounts.len(), 2);
    assert!(proposed_block.transactions().any(|tx_header| {
        tx_header.id() == proven_tx0.id() && tx_header.account_id() == account0.id()
    }));
    assert!(proposed_block.transactions().any(|tx_header| {
        tx_header.id() == proven_tx1.id() && tx_header.account_id() == account1.id()
    }));
    assert_eq!(
        updated_accounts[&account0.id()].final_state_commitment(),
        proven_tx0.account_update().final_state_commitment()
    );
    assert_eq!(
        updated_accounts[&account1.id()].final_state_commitment(),
        proven_tx1.account_update().final_state_commitment()
    );
    // Each tx consumes one note.
    assert_eq!(proposed_block.created_nullifiers().len(), 2);
    assert!(
        proposed_block
            .created_nullifiers()
            .contains_key(&proven_tx0.input_notes().get_note(0).nullifier())
    );
    assert!(
        proposed_block
            .created_nullifiers()
            .contains_key(&proven_tx1.input_notes().get_note(0).nullifier())
    );

    // There are two batches in the block...
    assert_eq!(proposed_block.output_note_batches().len(), 2);
    // ... but none of them create notes.
    assert!(proposed_block.output_note_batches()[0].is_empty());
    assert!(proposed_block.output_note_batches()[1].is_empty());

    Ok(())
}

/// Tests that account updates are correctly aggregated into a block-level account update.
#[tokio::test]
async fn proposed_block_aggregates_account_state_transition() -> anyhow::Result<()> {
    let asset = FungibleAsset::mock(100);
    let sender_id = AccountId::try_from(ACCOUNT_ID_SENDER)?;

    let mut builder = MockChain::builder();
    let mut account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let note0 = builder.add_p2id_note(sender_id, account1.id(), &[asset], NoteType::Private)?;
    let note1 = builder.add_p2id_note(sender_id, account1.id(), &[asset], NoteType::Public)?;
    let note2 = builder.add_p2id_note(sender_id, account1.id(), &[asset], NoteType::Public)?;
    let mut chain = builder.build()?;

    // Add notes to the chain.
    chain.prove_next_block()?;

    // Create three transactions on the same account that build on top of each other.
    let executed_tx0 = chain.create_authenticated_notes_tx(account1.id(), [note0.id()]).await?;

    account1.apply_delta(executed_tx0.account_delta())?;
    let executed_tx1 = chain.create_authenticated_notes_tx(account1.clone(), [note1.id()]).await?;

    account1.apply_delta(executed_tx1.account_delta())?;
    let executed_tx2 = chain.create_authenticated_notes_tx(account1.clone(), [note2.id()]).await?;

    let [tx0, tx1, tx2] = [executed_tx0, executed_tx1, executed_tx2]
        .into_iter()
        .map(|tx| LocalTransactionProver::default().prove_dummy(tx).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .expect("we should have provided three executed txs");

    let batch0 = chain.create_batch(vec![tx2.clone()])?;
    let batch1 = chain.create_batch(vec![tx0.clone(), tx1.clone()])?;

    let batches = vec![batch0.clone(), batch1.clone()];
    let block_inputs = chain.get_block_inputs(&batches).unwrap();

    let block =
        ProposedBlock::new(block_inputs, batches).context("failed to build proposed block")?;

    assert_eq!(block.updated_accounts().len(), 1);
    let (account_id, account_update) = &block.updated_accounts()[0];
    assert_eq!(*account_id, account1.id());
    assert_eq!(
        account_update.initial_state_commitment(),
        tx0.account_update().initial_state_commitment()
    );
    assert_eq!(
        account_update.final_state_commitment(),
        tx2.account_update().final_state_commitment()
    );
    // The transactions are in the flattened order of the batches.
    assert_eq!(
        block.transactions().map(TransactionHeader::id).collect::<Vec<_>>(),
        [tx2.id(), tx0.id(), tx1.id()]
    );

    assert_matches!(account_update.details(), AccountUpdateDetails::Delta(delta) => {
        assert_eq!(delta.vault().fungible().num_assets(), 1);
        assert_eq!(delta.vault().fungible().amount(&asset.unwrap_fungible().faucet_id()).unwrap(), 300);
    });

    Ok(())
}

/// Tests that unauthenticated notes can be authenticated when inclusion proofs are provided.
#[tokio::test]
async fn proposed_block_authenticating_unauthenticated_notes() -> anyhow::Result<()> {
    let sender_id = AccountId::try_from(ACCOUNT_ID_SENDER)?;

    let mut builder = MockChain::builder();
    let account0 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let note0 = builder.add_p2id_note(sender_id, account0.id(), &[], NoteType::Private)?;
    let note1 = builder.add_p2id_note(sender_id, account1.id(), &[], NoteType::Public)?;
    let chain = builder.build()?;

    // These txs will use block1 as the reference block.
    let tx0 = chain
        .create_unauthenticated_notes_proven_tx(account0.id(), slice::from_ref(&note0))
        .await?;
    let tx1 = chain
        .create_unauthenticated_notes_proven_tx(account1.id(), slice::from_ref(&note1))
        .await?;

    // These batches will use block1 as the reference block.
    let batch0 = chain.create_batch(vec![tx0.clone()])?;
    let batch1 = chain.create_batch(vec![tx1.clone()])?;

    let batches = [batch0, batch1];
    // This block will use block2 as the reference block.
    let block_inputs = chain.get_block_inputs(&batches)?;

    // Sanity check: Block inputs should contain nullifiers for the unauthenticated notes since they
    // are part of the chain.
    assert!(block_inputs.nullifier_witnesses().contains_key(&note0.nullifier()));
    assert!(block_inputs.nullifier_witnesses().contains_key(&note1.nullifier()));

    let proposed_block = ProposedBlock::new(block_inputs.clone(), batches.to_vec())
        .context("failed to build proposed block")?;

    // We expect both notes to have been authenticated and therefore should be part of the
    // nullifiers of this block.
    assert_eq!(proposed_block.created_nullifiers().len(), 2);
    assert!(proposed_block.created_nullifiers().contains_key(&note0.nullifier()));
    assert!(proposed_block.created_nullifiers().contains_key(&note1.nullifier()));
    // There are two batches in the block...
    assert_eq!(proposed_block.output_note_batches().len(), 2);
    // ... but none of them create notes.
    assert!(proposed_block.output_note_batches()[0].is_empty());
    assert!(proposed_block.output_note_batches()[1].is_empty());

    Ok(())
}

/// Tests that a batch that expires at the block being proposed is still accepted.
#[tokio::test]
async fn proposed_block_with_batch_at_expiration_limit() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account0 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let account1 = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let mut chain = builder.build()?;

    chain.prove_next_block()?;
    let block1_num = chain.block_header(1).block_num();

    let tx0 = chain.create_expiring_proven_tx(account0.id(), block1_num + 5).await?;
    let tx1 = chain.create_expiring_proven_tx(account1.id(), block1_num + 2).await?;

    let batch0 = chain.create_batch(vec![tx0])?;
    let batch1 = chain.create_batch(vec![tx1])?;

    // sanity check: batch 1 should expire at block 3.
    assert_eq!(batch1.batch_expiration_block_num().as_u32(), 3);

    let _block2 = chain.prove_next_block()?;

    let batches = vec![batch0.clone(), batch1.clone()];

    // This block's number is 3 (the previous block is block 2), which means batch 1, which expires
    // at block 3 (due to tx1) should still be accepted into the block.
    let block_inputs = chain.get_block_inputs(&batches)?;
    ProposedBlock::new(block_inputs.clone(), batches.clone())?;

    Ok(())
}

/// Tests that a NOOP transaction with state commitments X -> X against account A can appear
/// in one batch while another batch contains a state-updating transaction with state commitments X
/// -> Y against the same account A. Both batches are in the same block.
#[tokio::test]
async fn noop_tx_and_state_updating_tx_against_same_account_in_same_block() -> anyhow::Result<()> {
    let account_builder = Account::builder(rand::rng().random())
        .storage_mode(AccountStorageMode::Public)
        .with_component(MockAccountComponent::with_empty_slots());

    let mut builder = MockChain::builder();
    let mut account0 = builder.add_account_from_builder(
        Auth::Conditional,
        account_builder,
        AccountState::Exists,
    )?;

    let noop_note0 =
        NoteBuilder::new(ACCOUNT_ID_SENDER.try_into().unwrap(), &mut rand::rng()).build()?;
    let noop_note1 =
        NoteBuilder::new(ACCOUNT_ID_SENDER.try_into().unwrap(), &mut rand::rng()).build()?;
    builder.add_output_note(OutputNote::Full(noop_note0.clone()));
    builder.add_output_note(OutputNote::Full(noop_note1.clone()));
    let mut chain = builder.build()?;

    let noop_tx = generate_conditional_tx(&mut chain, account0.id(), noop_note0, false).await;
    account0.apply_delta(noop_tx.account_delta())?;
    let state_updating_tx =
        generate_conditional_tx(&mut chain, account0.clone(), noop_note1, true).await;

    // sanity check: NOOP transaction's init and final commitment should be the same.
    assert_eq!(noop_tx.initial_account().commitment(), noop_tx.final_account().commitment());
    // sanity check: State-updating transaction's init and final commitment should *not* be the
    // same.
    assert_ne!(
        state_updating_tx.initial_account().commitment(),
        state_updating_tx.final_account().commitment()
    );

    let tx0 = LocalTransactionProver::default().prove_dummy(noop_tx)?;
    let tx1 = LocalTransactionProver::default().prove_dummy(state_updating_tx)?;

    let batch0 = chain.create_batch(vec![tx0])?;
    let batch1 = chain.create_batch(vec![tx1.clone()])?;

    let batches = vec![batch0.clone(), batch1.clone()];

    let block_inputs = chain.get_block_inputs(&batches)?;
    let block = ProposedBlock::new(block_inputs, batches.clone())?;

    let (_, update) = block.updated_accounts().iter().next().unwrap();
    assert_eq!(update.initial_state_commitment(), account0.commitment());
    assert_eq!(update.final_state_commitment(), tx1.account_update().final_state_commitment());

    Ok(())
}

// HELPER FUNCTIONS
// ================================================================================================

/// Generates a transaction, which depending on the `modify_storage` flag, does the following:
/// - if `modify_storage` is true, it increments the storage item of the account.
/// - if `modify_storage` is false, it does nothing (NOOP).
///
/// To make this transaction (always) non-empty, it consumes one "noop note", which does nothing.
async fn generate_conditional_tx(
    chain: &mut MockChain,
    input: impl Into<TxContextInput>,
    noop_note: Note,
    modify_storage: bool,
) -> ExecutedTransaction {
    let auth_args = [
        // increment nonce if modify_storage is true
        if modify_storage { Felt::ONE } else { Felt::ZERO },
        Felt::new(99),
        Felt::new(98),
        Felt::new(97),
    ];

    let tx_context = chain
        .build_tx_context(input.into(), &[noop_note.id()], &[])
        .unwrap()
        .auth_args(auth_args.into())
        .build()
        .unwrap();
    tx_context.execute().await.unwrap()
}
