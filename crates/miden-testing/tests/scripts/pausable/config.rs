extern crate alloc;

use alloc::vec::Vec;

use assert_matches::assert_matches;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::errors::protocol::ERR_NOTE_TOO_MANY_STORAGE_ITEMS;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS, Word};
use miden_standards::account::access::AccessControl;
use miden_standards::account::access::pausable::{Pausable, PausableManager, PausableStorage};
use miden_standards::errors::standards::{
    ERR_PAUSE_CONFIG_TARGET_ACCOUNT_MISMATCH,
    ERR_PAUSE_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_PAUSE_CONFIG_UNKNOWN_SELECTOR,
};
use miden_standards::note::{
    AccountTargetNetworkNote,
    NetworkAccountTarget,
    NetworkAccountTargetError,
    NoteExecutionHint,
    PauseConfig,
    PauseConfigNote,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use crate::into_private_note;

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

    // no storage items at all instead of the single expected selector item
    let note = malformed_pause_config_note(owner, account.id(), Vec::new(), &mut rng)?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_PAUSE_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS);
    Ok(())
}

/// A note carrying more storage items than any action accepts is rejected before its storage is
/// loaded, so the work an oversized note can impose on whoever attempts to consume it is bounded by
/// the longest layout the script accepts rather than by `MAX_NOTE_STORAGE_ITEMS`.
#[tokio::test]
async fn oversized_storage_is_rejected_before_the_storage_is_loaded() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_pausable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let storage = vec![Felt::from(0u32); MAX_NOTE_STORAGE_ITEMS];
    let note = malformed_pause_config_note(owner, account.id(), storage, &mut rng)?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_NOTE_TOO_MANY_STORAGE_ITEMS);
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

/// The note script does not read the note type, so a private note carrying the same script and
/// storage dispatches the action when it is consumed in a local transaction; authorization still
/// runs against the note sender. The public-note requirement of the standard lives at the
/// network-routing boundary instead, which rejects that same note.
#[tokio::test]
async fn private_note_dispatches_locally_but_is_not_network_routable() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_pausable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let note =
        into_private_note(pause_config_note(owner, account.id(), PauseConfig::Pause, &mut rng)?);

    // The network never routes it: a network note must be public.
    assert_matches!(
        AccountTargetNetworkNote::new(note.clone()),
        Err(NetworkAccountTargetError::NoteNotPublic(_))
    );

    // Consumed locally, it dispatches the Pause action like its public counterpart.
    let paused = execute_note_and_apply(&mock_chain, &account, &note).await?;
    assert!(is_paused(&paused)?);

    Ok(())
}
