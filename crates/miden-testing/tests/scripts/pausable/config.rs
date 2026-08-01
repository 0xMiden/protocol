extern crate alloc;

use alloc::vec::Vec;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::AccessControl;
use miden_standards::account::access::pausable::{Pausable, PausableManager, PausableStorage};
use miden_standards::errors::standards::{
    ERR_PAUSE_CONFIG_TARGET_ACCOUNT_MISMATCH,
    ERR_PAUSE_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_PAUSE_CONFIG_UNKNOWN_SELECTOR,
};
use miden_standards::note::{
    NetworkAccountTarget,
    NoteExecutionHint,
    PauseConfig,
    PauseConfigNote,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

// HELPERS
// ================================================================================================

/// Builds an account with `PausableManager` gated by `owner` via `Authority::OwnerControlled`
/// (installed by `AccessControl::Ownable2Step`), plus the `Pausable` storage component.
fn create_pausable_account(owner: AccountId) -> anyhow::Result<Account> {
    let account = AccountBuilder::new([43; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(Pausable::unpaused())
        .with_component(PausableManager)
        .build_existing()?;
    Ok(account)
}

fn is_paused(account: &Account) -> anyhow::Result<bool> {
    let word = account.storage().get_item(PausableStorage::is_paused_slot())?;
    Ok(word != Word::default())
}

/// Builds a [`PauseConfigNote`] for `config` sent by `sender` and targeting `account`.
fn pause_config_note(
    sender: AccountId,
    account: AccountId,
    config: PauseConfig,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = PauseConfigNote::builder()
        .sender(sender)
        .target(account)
        .config(config)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the PauseConfig script with hand-crafted storage, bypassing the builder
/// so malformed inputs can be exercised.
///
/// It carries a `NetworkAccountTarget` for the consuming account, like a real config note, so
/// the note passes the script's target check and reaches the guard under test.
fn malformed_pause_config_note(
    sender: AccountId,
    target: AccountId,
    storage: Vec<Felt>,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(PauseConfigNote::script())
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

/// The note dispatches the Pause and Unpause actions: the owner pauses the account, then unpauses
/// it.
#[tokio::test]
async fn pause_then_unpause_dispatch() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_pausable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let pause = pause_config_note(owner, account.id(), PauseConfig::Pause, &mut rng)?;
    let paused = execute_note_and_apply(&mock_chain, &account, &pause).await?;
    assert!(is_paused(&paused)?);

    let unpause = pause_config_note(owner, paused.id(), PauseConfig::Unpause, &mut rng)?;
    let unpaused = execute_note_and_apply(&mock_chain, &paused, &unpause).await?;
    assert!(!is_paused(&unpaused)?);
    Ok(())
}

/// A note whose selector matches no known action is rejected by the script's dispatch guard.
#[tokio::test]
async fn unknown_selector_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_pausable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // selector 99 is not a known action
    let note = malformed_pause_config_note(owner, account.id(), vec![Felt::from(99u32)], &mut rng)?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_PAUSE_CONFIG_UNKNOWN_SELECTOR);
    Ok(())
}

/// A note whose storage item count does not match its selector is rejected by the count guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_pausable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // Pause selector (0) but two storage items instead of the expected one
    let note = malformed_pause_config_note(
        owner,
        account.id(),
        vec![Felt::from(0u32), Felt::from(0u32)],
        &mut rng,
    )?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_PAUSE_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS);
    Ok(())
}

/// The note is bound to its target account, so a decoy account cannot consume a note meant for
/// another account. The decoy carries the same `PausableManager` setup with the same owner, so the
/// sender-based authorization would pass; consuming a note targeted at a different account aborts
/// at the target check before the pause state changes.
#[tokio::test]
async fn decoy_account_cannot_consume_note_of_another_account() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let decoy = create_pausable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(decoy.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // The note's intended target. It need not be built: the note only references its ID.
    let target = AccountId::builder().account_type(AccountType::Public).build_with_seed([9; 32]);

    let note = pause_config_note(owner, target, PauseConfig::Pause, &mut rng)?;
    let result = mock_chain
        .build_transaction(decoy.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSE_CONFIG_TARGET_ACCOUNT_MISMATCH);
    Ok(())
}
