//! Tests for the [`miden_standards::note::ConstantFeePolicyConfigNote`] standardized note,
//! which schedules a fee for a note script root by calling the consuming network account's
//! [`ConstantFeeManager`](miden_standards::account::fees::ConstantFeeManager)
//! `set_note_fee` procedure.

use std::collections::BTreeSet;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{AccountId, AccountType};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::errors::MasmError;
use miden_protocol::errors::protocol::ERR_NOTE_TOO_MANY_STORAGE_ITEMS;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::errors::standards::{
    ERR_CONSTANT_FEE_POLICY_CONFIG_ACCOUNT_MISMATCH,
    ERR_CONSTANT_FEE_POLICY_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_NETWORK_ACCOUNT_TARGET_MISSING,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::note::{ConstantFeePolicyConfigNote, NetworkAccountTarget, NoteExecutionHint};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{MockChain, assert_transaction_executor_error};
use rstest::rstest;

use super::constant_fee_manager::{
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

/// Builds a `ConstantFeePolicyConfigNote` scheduling `fee_asset` for `priced_root()` on `account`,
/// authored by `sender`, and converts it to a protocol [`Note`].
///
/// `serial_seed` distinguishes otherwise-identical notes so that several can coexist in one chain
/// without sharing a note ID. Shared with the `constant_fee_manager` suite, which uses the
/// standardized note to exercise `set_note_fee` behaviors that don't require a hand-crafted note.
pub(super) fn build_config_note(
    sender: AccountId,
    account: AccountId,
    fee_asset: FungibleAsset,
    serial_seed: u32,
) -> anyhow::Result<Note> {
    let note = ConstantFeePolicyConfigNote::builder()
        .sender(sender)
        .target(account)
        .note_script_root(priced_root())
        .fee_asset(fee_asset)
        .serial_number(Word::from([serial_seed, 0, 0, 0]))
        .build()?;
    Ok(Note::from(note))
}

/// Builds a note carrying the config-note script (so its root is allowlisted and priced like a real
/// config note) but with `num_items` storage felts instead of the required `NUM_STORAGE_ITEMS`, to
/// exercise the script's storage-count guard. It targets `account` (via a `NetworkAccountTarget`
/// attachment, like a real config note) so the note passes the target check and reaches the guard.
fn build_wrong_storage_config_note(
    sender: AccountId,
    account: AccountId,
    num_items: usize,
) -> anyhow::Result<Note> {
    let mut rng = RandomCoin::new(Word::from([7u32, 0, 0, 0]));
    let target = NetworkAccountTarget::new(account, NoteExecutionHint::Always)?;
    let note = NoteBuilder::new(sender, &mut rng)
        .script(ConstantFeePolicyConfigNote::script())
        .note_storage(vec![Felt::from(1u32); num_items])?
        .attachment(target)
        .build()?;
    Ok(note)
}

// TESTS
// ================================================================================================

/// Consuming an owner-authored `ConstantFeePolicyConfigNote` schedules the carried fee for the
/// target note script root; the write lands in the fee schedule as the set-marked entry
/// `[fee, 0, 0, 1]`. This exercises the standardized note's script and builder end-to-end.
#[tokio::test]
async fn config_note_schedules_fee() -> anyhow::Result<()> {
    let owner = owner_id();
    // The config note's script root is fixed, so allowlist and 0-fee-schedule it up front.
    let account = build_manageable_fee_account(
        owner,
        BTreeSet::from([ConstantFeePolicyConfigNote::script_root()]),
    )?;
    let config_note = build_config_note(owner, account.id(), fee_asset(FEE_AMOUNT)?, 1)?;

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

/// A `ConstantFeePolicyConfigNote` authored by a non-owner is rejected: the account's
/// `set_note_fee` runs `authority::assert_authorized`, which fails when the note sender is not the
/// Ownable2Step owner.
#[tokio::test]
async fn non_owner_config_note_is_rejected() -> anyhow::Result<()> {
    let owner = owner_id();
    let account = build_manageable_fee_account(
        owner,
        BTreeSet::from([ConstantFeePolicyConfigNote::script_root()]),
    )?;
    let attacker_note = build_config_note(non_owner_id(), account.id(), fee_asset(FEE_AMOUNT)?, 2)?;

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

/// A note carrying the config-note script but a storage item count other than `NUM_STORAGE_ITEMS`
/// (too few, empty, or too many) is rejected before it can call `set_note_fee`. An oversized note
/// is rejected by the bound the script passes to `get_bounded_storage`, before its storage is
/// loaded; the other counts reach the script's own storage-count guard. The note's script root is
/// unchanged by the storage, so it is still allowlisted, priced, and account-targeted like a real
/// config note; only the storage layout is malformed.
#[rstest]
#[case::empty(0, ERR_CONSTANT_FEE_POLICY_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS)]
#[case::too_few(
    ConstantFeePolicyConfigNote::NUM_STORAGE_ITEMS - 4,
    ERR_CONSTANT_FEE_POLICY_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
)]
#[case::too_many(ConstantFeePolicyConfigNote::NUM_STORAGE_ITEMS + 4, ERR_NOTE_TOO_MANY_STORAGE_ITEMS)]
#[tokio::test]
async fn config_note_with_wrong_storage_item_count_is_rejected(
    #[case] num_items: usize,
    #[case] expected_error: MasmError,
) -> anyhow::Result<()> {
    let owner = owner_id();
    let account = build_manageable_fee_account(
        owner,
        BTreeSet::from([ConstantFeePolicyConfigNote::script_root()]),
    )?;
    let malformed_note = build_wrong_storage_config_note(owner, account.id(), num_items)?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(malformed_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(malformed_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// A config note targeted at one account cannot be consumed by a different account: the script's
/// `NetworkAccountTarget` check rejects it before `set_note_fee` runs, even though the consuming
/// account allowlists the note's root and its `Authority` would accept the sender. This prevents a
/// third party from hijacking a public config note away from its intended account.
#[tokio::test]
async fn config_note_for_another_account_is_rejected() -> anyhow::Result<()> {
    let owner = owner_id();
    // The note targets a different (public) account than the one that will consume it.
    let target_account =
        AccountId::builder().account_type(AccountType::Public).build_with_seed([80; 32]);
    let consuming_account = build_manageable_fee_account(
        owner,
        BTreeSet::from([ConstantFeePolicyConfigNote::script_root()]),
    )?;
    let config_note = build_config_note(owner, target_account, fee_asset(FEE_AMOUNT)?, 3)?;

    let mut builder = MockChain::builder();
    builder.add_account(consuming_account.clone())?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(consuming_account.id())
        .authenticated_input_note(config_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_CONSTANT_FEE_POLICY_CONFIG_ACCOUNT_MISMATCH);

    Ok(())
}

/// A hand-crafted note reusing the config-note script but WITHOUT a `NetworkAccountTarget`
/// attachment is rejected: the target check fails closed on the missing attachment before the
/// storage-count guard or `set_note_fee`. The storage count is valid here, so only the absent
/// attachment can cause the failure.
#[tokio::test]
async fn config_note_without_target_attachment_is_rejected() -> anyhow::Result<()> {
    let owner = owner_id();
    let account = build_manageable_fee_account(
        owner,
        BTreeSet::from([ConstantFeePolicyConfigNote::script_root()]),
    )?;
    let mut rng = RandomCoin::new(Word::from([9u32, 0, 0, 0]));
    let note = NoteBuilder::new(owner, &mut rng)
        .script(ConstantFeePolicyConfigNote::script())
        .note_storage(vec![Felt::from(1u32); ConstantFeePolicyConfigNote::NUM_STORAGE_ITEMS])?
        .build()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NETWORK_ACCOUNT_TARGET_MISSING);

    Ok(())
}
