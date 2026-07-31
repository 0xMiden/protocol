extern crate alloc;

use alloc::vec::Vec;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Felt;
use miden_protocol::account::{Account, AccountId, AccountType};
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_standards::errors::standards::{
    ERR_OWNER_CONFIG_TARGET_ACCOUNT_MISMATCH,
    ERR_OWNER_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_OWNER_CONFIG_UNKNOWN_SELECTOR,
};
use miden_standards::note::{
    NetworkAccountTarget,
    NoteExecutionHint,
    OwnerConfig,
    OwnerConfigNote,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{MockChain, assert_transaction_executor_error};

// The `Ownable2Step` account and storage-getter helpers are shared with the parent
// `ownable2step` suite, which owns the exhaustive tests of the underlying component. This
// suite only checks that the OwnerConfig note dispatches each action and rejects malformed
// notes.
use super::{create_ownable_account, get_nominated_owner_from_storage, get_owner_from_storage};

// HELPERS
// ================================================================================================

/// Builds an [`OwnerConfigNote`] for `config` sent by `sender` and targeting `account`.
fn owner_config_note(
    sender: AccountId,
    account: AccountId,
    config: OwnerConfig,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = OwnerConfigNote::builder()
        .sender(sender)
        .account(account)
        .config(config)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the OwnerConfig script with hand-crafted storage, bypassing the builder
/// so malformed inputs can be exercised.
///
/// It carries a `NetworkAccountTarget` for the consuming account, like a real config note, so
/// the note passes the script's target check and reaches the guard under test.
fn malformed_owner_config_note(
    sender: AccountId,
    target: AccountId,
    storage: Vec<Felt>,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(OwnerConfigNote::script())
        .note_storage(storage)?
        .attachment(NetworkAccountTarget::new(target, NoteExecutionHint::Always)?)
        .build()?;
    Ok(note)
}

async fn execute_note_and_apply(
    mock_chain: &MockChain,
    account: &Account,
    note: &Note,
) -> anyhow::Result<Account> {
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_patch(executed.account_patch())?;

    Ok(updated)
}

// TESTS
// ================================================================================================

/// The note dispatches the TransferOwnership and AcceptOwnership actions: the owner nominates a new
/// owner, who then accepts.
#[tokio::test]
async fn transfer_then_accept_dispatch() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([2; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let transfer = owner_config_note(
        owner,
        account.id(),
        OwnerConfig::TransferOwnership { new_owner: Some(new_owner) },
        &mut rng,
    )?;
    let updated = execute_note_and_apply(&mock_chain, &account, &transfer).await?;
    assert_eq!(get_nominated_owner_from_storage(&updated)?, Some(new_owner));

    let accept =
        owner_config_note(new_owner, updated.id(), OwnerConfig::AcceptOwnership, &mut rng)?;
    let final_account = execute_note_and_apply(&mock_chain, &updated, &accept).await?;

    assert_eq!(get_owner_from_storage(&final_account)?, Some(new_owner));
    assert_eq!(get_nominated_owner_from_storage(&final_account)?, None);
    Ok(())
}

/// The note dispatches the RenounceOwnership action: the owner renounces, leaving the account
/// ownerless.
#[tokio::test]
async fn renounce_dispatch() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let note = owner_config_note(owner, account.id(), OwnerConfig::RenounceOwnership, &mut rng)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &note).await?;

    assert_eq!(get_owner_from_storage(&updated)?, None);
    Ok(())
}

/// A note whose selector matches no known action is rejected by the script's dispatch guard.
#[tokio::test]
async fn unknown_selector_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // selector 99 is not a known action
    let note = malformed_owner_config_note(owner, account.id(), vec![Felt::from(99u32)], &mut rng)?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_OWNER_CONFIG_UNKNOWN_SELECTOR);
    Ok(())
}

/// A note whose storage item count does not match its selector is rejected by the count guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // TransferOwnership selector (0) but only one storage item instead of the expected three
    let note = malformed_owner_config_note(owner, account.id(), vec![Felt::from(0u32)], &mut rng)?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_OWNER_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS);
    Ok(())
}

/// The note is bound to its target account, so a decoy account cannot consume a note meant for
/// another account. The decoy carries the same `Ownable2Step` setup with the same owner, so the
/// sender-based authorization would pass; consuming a note targeted at a different account aborts
/// at the target check before any ownership change runs.
#[tokio::test]
async fn decoy_account_cannot_consume_note_of_another_account() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let decoy = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(decoy.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // The note's intended target. It need not be built: the note only references its ID.
    let target = AccountId::builder().account_type(AccountType::Public).build_with_seed([9; 32]);

    let note = owner_config_note(owner, target, OwnerConfig::AcceptOwnership, &mut rng)?;
    let result = mock_chain
        .build_transaction(decoy.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_OWNER_CONFIG_TARGET_ACCOUNT_MISMATCH);
    Ok(())
}
