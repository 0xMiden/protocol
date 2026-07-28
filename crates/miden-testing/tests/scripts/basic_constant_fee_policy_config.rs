//! Tests for the [`miden_standards::note::BasicConstantFeePolicyConfigNote`] standardized note,
//! which schedules a fee for a note script root by calling the consuming network account's
//! [`BasicConstantFeeManager`](miden_standards::account::fees::BasicConstantFeeManager)
//! `set_note_fee` procedure.

use std::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::errors::standards::ERR_SENDER_NOT_OWNER;
use miden_standards::note::BasicConstantFeePolicyConfigNote;
use miden_testing::{MockChain, assert_transaction_executor_error};

use super::basic_constant_fee_manager::{
    build_manageable_fee_account,
    committed_fee_schedule_entry,
    fee_asset,
    non_owner_id,
    owner_id,
};
use super::fee_manager::{FEE_AMOUNT, priced_root};
use crate::consume_note;

// HELPERS
// ================================================================================================

/// Builds a `BasicConstantFeePolicyConfigNote` scheduling `fee` (in the account's fee asset) for
/// `priced_root()` on `account`, authored by `sender`, and converts it to a protocol [`Note`].
fn build_config_note(
    sender: AccountId,
    account: AccountId,
    fee: u64,
    serial_seed: u32,
) -> anyhow::Result<Note> {
    let note = BasicConstantFeePolicyConfigNote::builder()
        .sender(sender)
        .account(account)
        .note_script_root(priced_root())
        .fee_asset(fee_asset(fee)?)
        .serial_number(Word::from([serial_seed, 0, 0, 0]))
        .build()?;
    Ok(Note::from(note))
}

// TESTS
// ================================================================================================

/// Consuming an owner-authored `BasicConstantFeePolicyConfigNote` schedules the carried fee for the
/// target note script root; the write lands in the fee schedule as the set-marked entry
/// `[fee, 0, 0, 1]`. This exercises the standardized note's script and builder end-to-end.
#[tokio::test]
async fn config_note_schedules_fee() -> anyhow::Result<()> {
    let owner = owner_id();
    // The config note's script root is fixed, so allowlist and 0-fee-schedule it up front.
    let account = build_manageable_fee_account(
        owner,
        BTreeSet::from([BasicConstantFeePolicyConfigNote::script_root()]),
    )?;
    let config_note = build_config_note(owner, account.id(), FEE_AMOUNT, 1)?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_note(&mut mock_chain, account.id(), &config_note).await?;

    let entry = committed_fee_schedule_entry(&mock_chain, account.id(), priced_root())?;
    assert_eq!(entry, Word::from([FEE_AMOUNT as u32, 0, 0, 1]));

    Ok(())
}

/// A `BasicConstantFeePolicyConfigNote` authored by a non-owner is rejected: the account's
/// `set_note_fee` runs `authority::assert_authorized`, which fails when the note sender is not the
/// Ownable2Step owner.
#[tokio::test]
async fn non_owner_config_note_is_rejected() -> anyhow::Result<()> {
    let owner = owner_id();
    let account = build_manageable_fee_account(
        owner,
        BTreeSet::from([BasicConstantFeePolicyConfigNote::script_root()]),
    )?;
    let attacker_note = build_config_note(non_owner_id(), account.id(), FEE_AMOUNT, 2)?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(attacker_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(attacker_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}
