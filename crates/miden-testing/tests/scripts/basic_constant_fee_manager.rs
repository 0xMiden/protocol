//! Tests for the [`miden_standards::account::fees::BasicConstantFeeManager`] authority-gated admin
//! component, which mutates the fee schedule map owned by
//! [`miden_standards::account::fees::BasicConstantFeePolicy`] after deployment via the owner-gated
//! `set_note_fee` procedure.
//!
//! The fee schedule and the fee asset ID both live on an `AuthNetworkAccount`, so these tests
//! compose a network account. The admin notes that call `set_note_fee` are themselves allowlisted
//! and scheduled at a 0 fee, so the still-active constant policy prices them for free.

use std::collections::BTreeSet;

use miden_protocol::account::{Account, AccountId, StorageMapKey};
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::note::{Note, NoteScriptRoot};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::auth::NetworkAccount;
use miden_standards::account::fees::{
    BasicConstantFeeManager,
    BasicConstantFeePolicy,
    FeePolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::{
    ERR_FEE_ASSET_ID_MISMATCH,
    ERR_FUNGIBLE_ASSET_AMOUNT_EXCEEDS_MAX_ALLOWED_AMOUNT,
    ERR_FUNGIBLE_ASSET_VALUE_MALFORMED,
    ERR_SENDER_NOT_OWNER,
};
use miden_testing::{MockChain, assert_transaction_executor_error};
use rstest::rstest;

use super::fee_manager::{FEE_AMOUNT, fee_faucet_id, priced_root};
use super::rbac::{build_note, test_account_id};
use crate::consume_note;

// HELPERS
// ================================================================================================

/// The fee asset the account is configured with, carrying `amount`.
fn fee_asset(amount: u64) -> anyhow::Result<FungibleAsset> {
    Ok(FungibleAsset::new(fee_faucet_id()?, amount)?)
}

/// Builds a `sender`-authored note whose script calls `set_note_fee` with the given fee asset ID
/// and value words. The sender must be the account owner under `Authority::OwnerControlled`. Taking
/// raw words lets tests pass a hand-crafted value that the `FungibleAsset` builder could not emit.
fn build_set_note_fee_note_raw(
    sender: AccountId,
    lookup_key: NoteScriptRoot,
    fee_asset_id: Word,
    fee_asset_value: Word,
) -> anyhow::Result<Note> {
    build_note(
        sender,
        format!(
            r#"
        use miden::standards::fees::policies::basic_constant_fee_manager

        @note_script
        pub proc main
            # set_note_fee inputs: [NOTE_LOOKUP_KEY, FEE_ASSET_ID, FEE_ASSET_VALUE, pad(4)]
            push.{fee_asset_value}
            push.{fee_asset_id}
            push.{lookup_key}
            call.basic_constant_fee_manager::set_note_fee

            dropw dropw dropw
        end
        "#,
            lookup_key = lookup_key.as_word(),
        ),
    )
}

/// Builds a `sender`-authored note scheduling `fee_asset` for `lookup_key`.
fn build_set_note_fee_note(
    sender: AccountId,
    lookup_key: NoteScriptRoot,
    fee_asset: FungibleAsset,
) -> anyhow::Result<Note> {
    build_set_note_fee_note_raw(
        sender,
        lookup_key,
        fee_asset.to_id_word(),
        fee_asset.to_value_word(),
    )
}

/// Builds a network account composing `BasicConstantFeePolicy` (via the `FeePolicyManager`) +
/// `BasicConstantFeeManager` + `Ownable2Step(owner)` + `Authority::OwnerControlled`.
///
/// `priced_root()` is intentionally left unscheduled — the manager is the only way it gets a fee.
/// Each `admin_note_root` is allowlisted and scheduled at a 0 fee so the network account can
/// consume the admin notes for free.
fn build_manageable_fee_account(
    owner: AccountId,
    admin_note_roots: BTreeSet<NoteScriptRoot>,
) -> anyhow::Result<Account> {
    let mut policy = BasicConstantFeePolicy::new();
    for root in &admin_note_roots {
        policy = policy.with_fee(*root, AssetAmount::ZERO);
    }
    let fee_policy_manager = FeePolicyManager::builder()
        .fee_faucet_id(fee_faucet_id()?)
        .active_fee_policy(policy.into())
        .build();

    Ok(NetworkAccount::builder([7; 32], admin_note_roots, fee_policy_manager)?
        .with_component(BasicWallet)
        .with_component(Ownable2Step::new(owner))
        .with_component(Authority::OwnerControlled)
        .with_component(BasicConstantFeeManager::for_basic_constant_fee_policy())
        .build_existing()?)
}

/// Reads the fee schedule entry stored for `lookup_key` in the account's committed state.
fn committed_fee_schedule_entry(
    mock_chain: &MockChain,
    account_id: AccountId,
    lookup_key: NoteScriptRoot,
) -> anyhow::Result<Word> {
    let account = mock_chain.committed_account(account_id)?;
    let entry = account.storage().get_map_item(
        BasicConstantFeePolicy::fee_schedule_slot_name(),
        StorageMapKey::new(lookup_key.as_word()),
    )?;
    Ok(entry)
}

/// Returns the account's configured fee asset ID word.
fn fee_asset_id_word() -> anyhow::Result<Word> {
    Ok(fee_asset(0)?.to_id_word())
}

// TESTS
// ================================================================================================

/// The owner schedules a fee for a previously unscheduled note script root; the write lands in the
/// fee schedule map as the set-marked entry `[fee, 0, 0, 1]`.
#[tokio::test]
async fn owner_set_note_fee_writes_schedule_entry() -> anyhow::Result<()> {
    let owner = test_account_id(70);
    let set_note = build_set_note_fee_note(owner, priced_root(), fee_asset(FEE_AMOUNT)?)?;
    let account = build_manageable_fee_account(owner, BTreeSet::from([set_note.script().root()]))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_note(&mut mock_chain, account.id(), &set_note).await?;

    let entry = committed_fee_schedule_entry(&mock_chain, account.id(), priced_root())?;
    assert_eq!(entry, Word::from([FEE_AMOUNT as u32, 0, 0, 1]));

    Ok(())
}

/// Scheduling an explicit fee of 0 records a set-marked entry `[0, 0, 0, 1]`, distinguishing it
/// from an unset key (which reads as the zero word).
#[tokio::test]
async fn owner_set_note_fee_zero_schedules_free_note() -> anyhow::Result<()> {
    let owner = test_account_id(70);
    let set_note = build_set_note_fee_note(owner, priced_root(), fee_asset(0)?)?;
    let account = build_manageable_fee_account(owner, BTreeSet::from([set_note.script().root()]))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_note(&mut mock_chain, account.id(), &set_note).await?;

    let entry = committed_fee_schedule_entry(&mock_chain, account.id(), priced_root())?;
    assert_eq!(entry, Word::from([0u32, 0, 0, 1]));

    Ok(())
}

/// A later `set_note_fee` for the same key replaces the previously scheduled fee.
#[tokio::test]
async fn owner_set_note_fee_overwrites_existing_entry() -> anyhow::Result<()> {
    let owner = test_account_id(70);
    let updated_fee = FEE_AMOUNT + 123;
    let first = build_set_note_fee_note(owner, priced_root(), fee_asset(FEE_AMOUNT)?)?;
    let second = build_set_note_fee_note(owner, priced_root(), fee_asset(updated_fee)?)?;
    let account = build_manageable_fee_account(
        owner,
        BTreeSet::from([first.script().root(), second.script().root()]),
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(first.clone()));
    builder.add_output_note(RawOutputNote::Full(second.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_note(&mut mock_chain, account.id(), &first).await?;
    consume_note(&mut mock_chain, account.id(), &second).await?;

    let entry = committed_fee_schedule_entry(&mock_chain, account.id(), priced_root())?;
    assert_eq!(entry, Word::from([updated_fee as u32, 0, 0, 1]));

    Ok(())
}

/// `Authority::OwnerControlled` rejects a non-owner sender: `set_note_fee` runs
/// `authority::assert_authorized`, which fails when the note sender is not the Ownable2Step owner.
#[tokio::test]
async fn non_owner_set_note_fee_is_rejected() -> anyhow::Result<()> {
    let owner = test_account_id(70);
    let attacker_note =
        build_set_note_fee_note(test_account_id(71), priced_root(), fee_asset(FEE_AMOUNT)?)?;
    let account =
        build_manageable_fee_account(owner, BTreeSet::from([attacker_note.script().root()]))?;

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

/// `set_note_fee` rejects a fee asset whose ID does not match the account's configured fee asset:
/// the owner schedules a fee in a different faucet's asset, which the fee-asset-ID check aborts.
#[tokio::test]
async fn set_note_fee_with_wrong_fee_asset_is_rejected() -> anyhow::Result<()> {
    let owner = test_account_id(70);
    let wrong_asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?, FEE_AMOUNT)?;
    let set_note = build_set_note_fee_note(owner, priced_root(), wrong_asset)?;
    let account = build_manageable_fee_account(owner, BTreeSet::from([set_note.script().root()]))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(set_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_ASSET_ID_MISMATCH);

    Ok(())
}

/// `set_note_fee` rejects a fee asset value word that is not a well-formed fungible value: a
/// hand-crafted note carries the correct fee asset ID but a value with a non-zero padding element
/// (any of the three), which the value-word validation aborts before it can poison the fee
/// schedule.
#[rstest]
#[case::element_1(1)]
#[case::element_2(2)]
#[case::element_3(3)]
#[tokio::test]
async fn set_note_fee_with_malformed_fee_asset_value_is_rejected(
    #[case] dirty_element: usize,
) -> anyhow::Result<()> {
    let owner = test_account_id(70);
    // A value word with a non-zero element where a fungible value must be zero-padded.
    let mut value = [FEE_AMOUNT as u32, 0, 0, 0];
    value[dirty_element] = 1;
    let set_note =
        build_set_note_fee_note_raw(owner, priced_root(), fee_asset_id_word()?, Word::from(value))?;
    let account = build_manageable_fee_account(owner, BTreeSet::from([set_note.script().root()]))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(set_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FUNGIBLE_ASSET_VALUE_MALFORMED);

    Ok(())
}

/// `set_note_fee` rejects a fee amount that exceeds the maximum fungible asset amount, before it
/// can be scheduled as an unpayable fee.
#[tokio::test]
async fn set_note_fee_with_amount_over_max_is_rejected() -> anyhow::Result<()> {
    let owner = test_account_id(70);
    // One above the maximum fungible asset amount; still a valid field element.
    let over_max =
        Word::from([Felt::from(AssetAmount::MAX) + Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    let set_note =
        build_set_note_fee_note_raw(owner, priced_root(), fee_asset_id_word()?, over_max)?;
    let account = build_manageable_fee_account(owner, BTreeSet::from([set_note.script().root()]))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(set_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_FUNGIBLE_ASSET_AMOUNT_EXCEEDS_MAX_ALLOWED_AMOUNT
    );

    Ok(())
}

/// The maximum fungible asset amount is the inclusive upper bound: scheduling exactly `MAX_AMOUNT`
/// is accepted and lands as the set-marked entry `[MAX_AMOUNT, 0, 0, 1]`.
#[tokio::test]
async fn owner_set_note_fee_at_max_amount_is_accepted() -> anyhow::Result<()> {
    let owner = test_account_id(70);
    let max_value = Word::from([Felt::from(AssetAmount::MAX), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    let set_note =
        build_set_note_fee_note_raw(owner, priced_root(), fee_asset_id_word()?, max_value)?;
    let account = build_manageable_fee_account(owner, BTreeSet::from([set_note.script().root()]))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_note(&mut mock_chain, account.id(), &set_note).await?;

    let entry = committed_fee_schedule_entry(&mock_chain, account.id(), priced_root())?;
    assert_eq!(
        entry,
        Word::from([Felt::from(AssetAmount::MAX), Felt::ZERO, Felt::ZERO, Felt::ONE])
    );

    Ok(())
}
