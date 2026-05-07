use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::BTreeMap;

use anyhow::Context;
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor};
use miden_protocol::account::{Account, AccountStorageMode};
use miden_protocol::batch::{BatchKernel, ProposedBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::transaction::ToInputNoteCommitments;
use miden_protocol::vm::{AdviceInputs, StackInputs, StackOutputs};
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::testing::account_component::MockAccountComponent;
use rand::Rng;

use super::proposed_batch::{mock_note, mock_output_note};
use super::proven_tx_builder::MockProvenTxBuilder;
use crate::{AccountState, Auth, MockChain, MockChainBuilder};

// SETUP HELPERS
// ================================================================================================

struct TestSetup {
    chain: MockChain,
    account1: Account,
    account2: Account,
    auth_note: Note,
}

fn setup() -> TestSetup {
    let mut builder = MockChain::builder();
    let account1 = generate_account(&mut builder);
    let account2 = generate_account(&mut builder);
    let auth_note = builder
        .add_p2id_note(account1.id(), account2.id(), &[], NoteType::Public)
        .expect("adding p2id note should work");
    let mut chain = builder.build().expect("genesis should be valid");
    chain.prove_next_block().expect("first block should prove");
    TestSetup { chain, account1, account2, auth_note }
}

fn generate_account(chain: &mut MockChainBuilder) -> Account {
    let account_builder = Account::builder(rand::rng().random())
        .storage_mode(AccountStorageMode::Private)
        .with_component(MockAccountComponent::with_empty_slots());
    chain
        .add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
        .expect("failed to add pending account from builder")
}

/// Builds a two-transaction batch:
/// - tx1 (account1): consumes one authenticated input note, produces one output note, expiration =
///   1234.
/// - tx2 (account2): consumes one unauthenticated input note, produces two output notes, expiration
///   = 800.
fn two_tx_batch(setup: &mut TestSetup) -> anyhow::Result<ProposedBatch> {
    let block1 = setup.chain.block_header(1);
    let block2 = setup.chain.prove_next_block()?;

    let tx1 = MockProvenTxBuilder::with_account(
        setup.account1.id(),
        Word::empty(),
        setup.account1.to_commitment(),
    )
    .ref_block_commitment(block1.commitment())
    .authenticated_notes(vec![setup.auth_note.clone()])
    .output_notes(vec![mock_output_note(80)])
    .expiration_block_num(BlockNumber::from(1234u32))
    .build()?;

    let tx2_input = mock_note(81);
    let tx2 = MockProvenTxBuilder::with_account(
        setup.account2.id(),
        Word::empty(),
        setup.account2.to_commitment(),
    )
    .ref_block_commitment(block1.commitment())
    .unauthenticated_notes(vec![tx2_input])
    .output_notes(vec![mock_output_note(82), mock_output_note(83)])
    .expiration_block_num(BlockNumber::from(800u32))
    .build()?;

    Ok(ProposedBatch::new(
        [tx1, tx2].into_iter().map(Arc::new).collect(),
        block2.header().clone(),
        setup.chain.latest_partial_blockchain(),
        BTreeMap::default(),
    )?)
}

// EXPECTED-VALUE HELPERS
// ================================================================================================

/// Sequential hash over `(NULLIFIER, EMPTY_OR_NOTE_COMMITMENT)` tuples for every input note in
/// every transaction in iteration order. Mirrors the kernel's per-tx absorption (no erasure).
fn expected_input_notes_commitment(batch: &ProposedBatch) -> Word {
    let mut elements: Vec<Felt> = Vec::new();
    for tx in batch.transactions() {
        for commit in tx.input_notes().iter() {
            elements.extend_from_slice(commit.nullifier().as_word().as_elements());
            let note_or_zero = commit.note_commitment().unwrap_or(Word::empty());
            elements.extend_from_slice(note_or_zero.as_elements());
        }
    }
    if elements.is_empty() {
        Word::empty()
    } else {
        Hasher::hash_elements(&elements)
    }
}

/// Sequential hash over `(NOTE_ID, METADATA_COMMITMENT)` tuples for every output note in every
/// transaction in iteration order.
fn expected_output_notes_commitment(batch: &ProposedBatch) -> Word {
    let mut elements: Vec<Felt> = Vec::new();
    for tx in batch.transactions() {
        for note in tx.output_notes().iter() {
            elements.extend_from_slice(note.id().as_word().as_elements());
            elements.extend_from_slice(note.metadata().to_commitment().as_elements());
        }
    }
    if elements.is_empty() {
        Word::empty()
    } else {
        Hasher::hash_elements(&elements)
    }
}

// EXECUTION HELPERS
// ================================================================================================

fn run_kernel(
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
) -> Result<StackOutputs, miden_processor::ExecutionError> {
    let mut host = DefaultHost::default();
    host.load_library(CoreLibrary::default().mast_forest())
        .expect("loading the core library into the test host should succeed");

    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .with_debugging(true);
    let output = processor.execute_sync(&BatchKernel::main(), &mut host)?;
    Ok(output.stack)
}

// HAPPY PATH
// ================================================================================================

#[test]
fn batch_kernel_happy_path() -> anyhow::Result<()> {
    let mut setup = setup();
    let batch = two_tx_batch(&mut setup)?;

    let (stack_inputs, advice_inputs) = BatchKernel::prepare_inputs(&batch);
    let stack_outputs =
        run_kernel(stack_inputs, advice_inputs).context("kernel execution failed")?;
    let (input_notes_commitment, output_notes_commitment, expiration) =
        BatchKernel::parse_output_stack(&stack_outputs).context("parse output stack failed")?;

    assert_eq!(input_notes_commitment, expected_input_notes_commitment(&batch));
    assert_eq!(output_notes_commitment, expected_output_notes_commitment(&batch));
    assert_eq!(expiration, batch.batch_expiration_block_num());
    assert_eq!(expiration, BlockNumber::from(800u32));

    Ok(())
}

// NEGATIVE TESTS
// ================================================================================================

/// Corrupting `TRANSACTIONS_COMMITMENT` on the input stack makes Layer 1 unloadable from the
/// advice map, so the kernel must abort.
#[test]
fn batch_kernel_rejects_wrong_transactions_commitment() -> anyhow::Result<()> {
    let mut setup = setup();
    let batch = two_tx_batch(&mut setup)?;

    let block_hash = batch.reference_block_header().commitment();
    let bogus_commitment = Word::from([12345u32; 4]);
    let stack_inputs = BatchKernel::build_input_stack(block_hash, bogus_commitment);
    let (_, advice_inputs) = BatchKernel::prepare_inputs(&batch);

    let err = run_kernel(stack_inputs, advice_inputs).expect_err("kernel must abort");
    let msg = err.to_string();
    assert!(
        msg.contains("advice map") || msg.contains("not found") || msg.contains("missing"),
        "unexpected error: {msg}",
    );
    Ok(())
}

/// Tampering a verified `tx_id`'s Layer 2 advice-map entry breaks the per-tx hash check.
#[test]
fn batch_kernel_rejects_tampered_layer_2() -> anyhow::Result<()> {
    let mut setup = setup();
    let batch = two_tx_batch(&mut setup)?;

    let (stack_inputs, mut advice_inputs) = BatchKernel::prepare_inputs(&batch);

    let tx0_id = batch.transactions()[0].id().as_word();
    let entry = advice_inputs.map.get(&tx0_id).expect("tx0 layer 2 entry");
    let mut tampered: Vec<Felt> = entry.iter().copied().collect();
    tampered[0] += Felt::new(1);
    advice_inputs.map.extend([(tx0_id, tampered)]);

    let err = run_kernel(stack_inputs, advice_inputs).expect_err("kernel must abort");
    let msg = err.to_string();
    assert!(
        msg.contains("transaction header data piped from the advice map"),
        "unexpected error: {msg}",
    );
    Ok(())
}

/// Tampering the per-tx input-notes Layer 3 entry breaks the input-note hash check.
#[test]
fn batch_kernel_rejects_tampered_input_notes() -> anyhow::Result<()> {
    let mut setup = setup();
    let batch = two_tx_batch(&mut setup)?;

    let (stack_inputs, mut advice_inputs) = BatchKernel::prepare_inputs(&batch);

    let key = batch.transactions()[0].input_notes().commitment();
    let entry = advice_inputs.map.get(&key).expect("layer 3 entry");
    let mut tampered: Vec<Felt> = entry.iter().copied().collect();
    tampered[0] += Felt::new(1);
    advice_inputs.map.extend([(key, tampered)]);

    let err = run_kernel(stack_inputs, advice_inputs).expect_err("kernel must abort");
    let msg = err.to_string();
    assert!(
        msg.contains("per-transaction input notes data piped"),
        "unexpected error: {msg}",
    );
    Ok(())
}

/// Tampering the per-tx output-notes Layer 3' entry breaks the output-note hash check.
#[test]
fn batch_kernel_rejects_tampered_output_notes() -> anyhow::Result<()> {
    let mut setup = setup();
    let batch = two_tx_batch(&mut setup)?;

    let (stack_inputs, mut advice_inputs) = BatchKernel::prepare_inputs(&batch);

    let key = batch.transactions()[0].output_notes().commitment();
    let entry = advice_inputs.map.get(&key).expect("layer 3' entry");
    let mut tampered: Vec<Felt> = entry.iter().copied().collect();
    tampered[0] += Felt::new(1);
    advice_inputs.map.extend([(key, tampered)]);

    let err = run_kernel(stack_inputs, advice_inputs).expect_err("kernel must abort");
    let msg = err.to_string();
    assert!(
        msg.contains("per-transaction output notes data piped"),
        "unexpected error: {msg}",
    );
    Ok(())
}
