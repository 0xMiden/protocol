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
    ERR_PAUSE_ACTION_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_PAUSE_ACTION_UNKNOWN_SELECTOR,
};
use miden_standards::note::{PauseAction, PauseActionNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

// HELPERS
// ================================================================================================

/// Builds an account with `PausableManager` gated by `owner` via `Authority::OwnerControlled`
/// (installed by `AccessControl::Ownable2Step`), plus the `Pausable` storage component.
fn create_pausable_account(owner: AccountId) -> anyhow::Result<Account> {
    let account = AccountBuilder::new([43; 32])
        .account_type(AccountType::Public)
        .with_component(Auth::IncrNonce)
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

/// Builds a [`PauseActionNote`] for `action` sent by `sender` and targeting `account`.
fn pause_action_note(
    sender: AccountId,
    account: AccountId,
    action: PauseAction,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = PauseActionNote::builder()
        .sender(sender)
        .account(account)
        .action(action)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the PauseAction script with hand-crafted storage, bypassing the builder
/// so malformed inputs can be exercised.
fn malformed_pause_action_note(
    sender: AccountId,
    storage: Vec<Felt>,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(PauseActionNote::script())
        .note_storage(storage)?
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

    let pause = pause_action_note(owner, account.id(), PauseAction::Pause, &mut rng)?;
    let paused = execute_note_and_apply(&mock_chain, &account, &pause).await?;
    assert!(is_paused(&paused)?);

    let unpause = pause_action_note(owner, paused.id(), PauseAction::Unpause, &mut rng)?;
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
    let note = malformed_pause_action_note(owner, vec![Felt::from(99u32)], &mut rng)?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_PAUSE_ACTION_UNKNOWN_SELECTOR);
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
    let note =
        malformed_pause_action_note(owner, vec![Felt::from(0u32), Felt::from(0u32)], &mut rng)?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_PAUSE_ACTION_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS);
    Ok(())
}
