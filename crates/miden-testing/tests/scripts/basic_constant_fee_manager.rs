//! Tests for the [`miden_standards::account::fees::BasicConstantFeeManager`] authority-gated admin
//! component, which mutates the fee schedule map owned by
//! [`miden_standards::account::fees::BasicConstantFeePolicy`] after deployment via the owner-gated
//! `set_note_fee` procedure.
//!
//! The fee schedule and the fee asset ID both live on an `AuthNetworkAccount`, so these tests
//! compose a network account. The admin notes that call `set_note_fee` are themselves allowlisted
//! and scheduled at a 0 fee, so the still-active constant policy prices them for free.

use std::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId, StorageMapKey};
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::note::{Note, NoteScriptRoot};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::auth::NetworkAccount;
use miden_standards::account::fees::{
    BasicConstantFeeManager,
    BasicConstantFeePolicy,
    FeePolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::{ERR_FEE_ASSET_ID_MISMATCH, ERR_SENDER_NOT_OWNER};
use miden_testing::{MockChain, assert_transaction_executor_error};

use super::fee_manager::{FEE_AMOUNT, fee_faucet_id, priced_root};
use super::rbac::{build_note, test_account_id};

// HELPERS
// ================================================================================================

fn owner_id() -> AccountId {
    test_account_id(70)
}

fn non_owner_id() -> AccountId {
    test_account_id(71)
}

/// The fee asset the account is configured with, carrying `amount`.
fn fee_asset(amount: u64) -> anyhow::Result<FungibleAsset> {
    Ok(FungibleAsset::new(fee_faucet_id()?, amount)?)
}

/// Builds a `sender`-authored note whose script schedules `fee_asset` for `lookup_key` by calling
/// `basic_constant_fee_manager::set_note_fee`. The sender must be the account owner under
/// `Authority::OwnerControlled`.
fn build_set_note_fee_note(
    sender: AccountId,
    lookup_key: NoteScriptRoot,
    fee_asset: FungibleAsset,
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
            fee_asset_value = fee_asset.to_value_word(),
            fee_asset_id = fee_asset.to_id_word(),
            lookup_key = lookup_key.as_word(),
        ),
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

/// Consumes an admin note against the network account and commits the block, so the fee schedule
/// write is visible in the account's committed state.
async fn consume_admin_note(
    mock_chain: &mut MockChain,
    account_id: AccountId,
    note: &Note,
) -> anyhow::Result<()> {
    let executed = mock_chain
        .build_transaction(account_id)
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    Ok(())
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

// TESTS
// ================================================================================================

/// The owner schedules a fee for a previously unscheduled note script root; the write lands in the
/// fee schedule map as the set-marked entry `[fee, 0, 0, 1]`.
#[tokio::test]
async fn owner_set_note_fee_writes_schedule_entry() -> anyhow::Result<()> {
    let owner = owner_id();
    let set_note = build_set_note_fee_note(owner, priced_root(), fee_asset(FEE_AMOUNT)?)?;
    let account = build_manageable_fee_account(owner, BTreeSet::from([set_note.script().root()]))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, account.id(), &set_note).await?;

    let entry = committed_fee_schedule_entry(&mock_chain, account.id(), priced_root())?;
    assert_eq!(entry, Word::from([FEE_AMOUNT as u32, 0, 0, 1]));

    Ok(())
}

/// Scheduling an explicit fee of 0 records a set-marked entry `[0, 0, 0, 1]`, distinguishing it
/// from an unset key (which reads as the zero word).
#[tokio::test]
async fn owner_set_note_fee_zero_schedules_free_note() -> anyhow::Result<()> {
    let owner = owner_id();
    let set_note = build_set_note_fee_note(owner, priced_root(), fee_asset(0)?)?;
    let account = build_manageable_fee_account(owner, BTreeSet::from([set_note.script().root()]))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, account.id(), &set_note).await?;

    let entry = committed_fee_schedule_entry(&mock_chain, account.id(), priced_root())?;
    assert_eq!(entry, Word::from([0u32, 0, 0, 1]));

    Ok(())
}

/// A later `set_note_fee` for the same key replaces the previously scheduled fee.
#[tokio::test]
async fn owner_set_note_fee_overwrites_existing_entry() -> anyhow::Result<()> {
    let owner = owner_id();
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

    consume_admin_note(&mut mock_chain, account.id(), &first).await?;
    consume_admin_note(&mut mock_chain, account.id(), &second).await?;

    let entry = committed_fee_schedule_entry(&mock_chain, account.id(), priced_root())?;
    assert_eq!(entry, Word::from([updated_fee as u32, 0, 0, 1]));

    Ok(())
}

/// `Authority::OwnerControlled` rejects a non-owner sender: `set_note_fee` runs
/// `authority::assert_authorized`, which fails when the note sender is not the Ownable2Step owner.
#[tokio::test]
async fn non_owner_set_note_fee_is_rejected() -> anyhow::Result<()> {
    let owner = owner_id();
    let attacker_note =
        build_set_note_fee_note(non_owner_id(), priced_root(), fee_asset(FEE_AMOUNT)?)?;
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
    let owner = owner_id();
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
