extern crate alloc;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Felt;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::Ownable2Step;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NO_NOMINATED_OWNER,
    ERR_OWNER_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_OWNER_CONFIG_UNKNOWN_SELECTOR,
    ERR_SENDER_NOT_NOMINATED_OWNER,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::note::{OwnerConfigAction, OwnerConfigNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

// HELPERS
// ================================================================================================

/// Builds an account carrying the `Ownable2Step` component, owned by `owner`.
fn create_ownable_account(owner: AccountId) -> anyhow::Result<Account> {
    let component_code = r#"
        use miden::standards::access::ownable2step
        pub use {get_owner, get_nominated_owner, transfer_ownership, accept_ownership, renounce_ownership} from miden::standards::access::ownable2step
    "#;
    let component_code_obj =
        CodeBuilder::default().compile_component_code("test::ownable", component_code)?;

    let storage_slots = vec![Ownable2Step::new(owner).to_storage_slot()];

    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component({
            let metadata = AccountComponentMetadata::new("test::ownable");
            AccountComponent::new(component_code_obj, storage_slots, metadata)?
        })
        .build_existing()?;
    Ok(account)
}

fn get_owner_from_storage(account: &Account) -> anyhow::Result<Option<AccountId>> {
    Ok(Ownable2Step::try_from_storage(account.storage())?.owner())
}

fn get_nominated_owner_from_storage(account: &Account) -> anyhow::Result<Option<AccountId>> {
    Ok(Ownable2Step::try_from_storage(account.storage())?.nominated_owner())
}

/// Builds an [`OwnerConfigNote`] for `action` sent by `sender` and targeting `account`.
fn owner_config_note(
    sender: AccountId,
    account: AccountId,
    action: OwnerConfigAction,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = OwnerConfigNote::builder()
        .sender(sender)
        .account(account)
        .action(action)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the OwnerConfig script with hand-crafted storage, bypassing the builder
/// so malformed inputs can be exercised.
fn malformed_owner_config_note(
    sender: AccountId,
    storage: Vec<Felt>,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(OwnerConfigNote::script())
        .note_storage(storage)?
        .build()?;
    Ok(note)
}

// TESTS
// ================================================================================================

/// The full happy path: the owner nominates a new owner, who then accepts.
#[tokio::test]
async fn transfer_then_accept_transfers_ownership() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([2; 32]);

    let account = create_ownable_account(owner)?;

    // Step 1: owner nominates new_owner.
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let transfer_note = owner_config_note(
        owner,
        account.id(),
        OwnerConfigAction::TransferOwnership { new_owner: Some(new_owner) },
        &mut rng,
    )?;

    builder.add_output_note(RawOutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain.build_tx_context(account.id(), &[transfer_note.id()], &[])?.build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_patch(executed.account_patch())?;

    assert_eq!(get_owner_from_storage(&updated)?, Some(owner));
    assert_eq!(get_nominated_owner_from_storage(&updated)?, Some(new_owner));

    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    // Step 2: new_owner accepts.
    let mut rng2 = RandomCoin::new([Felt::from(200u32); 4].into());
    let accept_note =
        owner_config_note(new_owner, updated.id(), OwnerConfigAction::AcceptOwnership, &mut rng2)?;

    let tx2 = mock_chain
        .build_tx_context(updated.clone(), &[], std::slice::from_ref(&accept_note))?
        .build()?;
    let executed2 = tx2.execute().await?;

    let mut final_account = updated.clone();
    final_account.apply_patch(executed2.account_patch())?;

    assert_eq!(get_owner_from_storage(&final_account)?, Some(new_owner));
    assert_eq!(get_nominated_owner_from_storage(&final_account)?, None);
    Ok(())
}

/// A transfer note sent by a non-owner is rejected by the `Ownable2Step` procedure.
#[tokio::test]
async fn transfer_from_non_owner_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let non_owner = AccountIdBuilder::new().build_with_seed([2; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([3; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let note = owner_config_note(
        non_owner,
        account.id(),
        OwnerConfigAction::TransferOwnership { new_owner: Some(new_owner) },
        &mut rng,
    )?;

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain.build_tx_context(account.id(), &[note.id()], &[])?.build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);
    Ok(())
}

/// A note whose selector matches no known action is rejected by the script's dispatch guard.
#[tokio::test]
async fn unknown_selector_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // selector 99 is not a known action
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let note = malformed_owner_config_note(owner, vec![Felt::from(99u32)], &mut rng)?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[], std::slice::from_ref(&note))?
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_OWNER_CONFIG_UNKNOWN_SELECTOR);
    Ok(())
}

/// A note whose storage item count does not match its selector is rejected by the script's count
/// guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // TransferOwnership selector (0) but only one storage item instead of the expected three
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let note = malformed_owner_config_note(owner, vec![Felt::from(0u32)], &mut rng)?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[], std::slice::from_ref(&note))?
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_OWNER_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS);
    Ok(())
}

/// Accepting from an account that is not the nominated owner is rejected.
#[tokio::test]
async fn accept_from_non_nominated_owner_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([2; 32]);
    let wrong = AccountIdBuilder::new().build_with_seed([3; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let transfer_note = owner_config_note(
        owner,
        account.id(),
        OwnerConfigAction::TransferOwnership { new_owner: Some(new_owner) },
        &mut rng,
    )?;

    builder.add_output_note(RawOutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain.build_tx_context(account.id(), &[transfer_note.id()], &[])?.build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_patch(executed.account_patch())?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    // wrong account attempts to accept
    let mut rng2 = RandomCoin::new([Felt::from(200u32); 4].into());
    let accept_note =
        owner_config_note(wrong, updated.id(), OwnerConfigAction::AcceptOwnership, &mut rng2)?;

    let tx2 = mock_chain
        .build_tx_context(updated.clone(), &[], std::slice::from_ref(&accept_note))?
        .build()?;
    let result = tx2.execute().await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_NOMINATED_OWNER);
    Ok(())
}

/// Accepting when there is no pending nomination is rejected.
#[tokio::test]
async fn accept_without_nomination_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let mut rng = RandomCoin::new([Felt::from(200u32); 4].into());
    let accept_note =
        owner_config_note(owner, account.id(), OwnerConfigAction::AcceptOwnership, &mut rng)?;

    builder.add_output_note(RawOutputNote::Full(accept_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain.build_tx_context(account.id(), &[accept_note.id()], &[])?.build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_NO_NOMINATED_OWNER);
    Ok(())
}

/// A cancelling transfer (zero address) clears a pending nomination without changing the owner.
#[tokio::test]
async fn cancel_transfer_clears_nomination() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([2; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let transfer_note = owner_config_note(
        owner,
        account.id(),
        OwnerConfigAction::TransferOwnership { new_owner: Some(new_owner) },
        &mut rng,
    )?;

    builder.add_output_note(RawOutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain.build_tx_context(account.id(), &[transfer_note.id()], &[])?.build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_patch(executed.account_patch())?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    // cancel by transferring to the zero address (new_owner = None)
    let mut rng2 = RandomCoin::new([Felt::from(200u32); 4].into());
    let cancel_note = owner_config_note(
        owner,
        updated.id(),
        OwnerConfigAction::TransferOwnership { new_owner: None },
        &mut rng2,
    )?;

    let tx2 = mock_chain
        .build_tx_context(updated.clone(), &[], std::slice::from_ref(&cancel_note))?
        .build()?;
    let executed2 = tx2.execute().await?;

    let mut final_account = updated.clone();
    final_account.apply_patch(executed2.account_patch())?;

    assert_eq!(get_owner_from_storage(&final_account)?, Some(owner));
    assert_eq!(get_nominated_owner_from_storage(&final_account)?, None);
    Ok(())
}

/// The owner renounces ownership, leaving the account ownerless.
#[tokio::test]
async fn renounce_leaves_account_ownerless() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let renounce_note =
        owner_config_note(owner, account.id(), OwnerConfigAction::RenounceOwnership, &mut rng)?;

    builder.add_output_note(RawOutputNote::Full(renounce_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain.build_tx_context(account.id(), &[renounce_note.id()], &[])?.build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_patch(executed.account_patch())?;

    assert_eq!(get_owner_from_storage(&updated)?, None);
    assert_eq!(get_nominated_owner_from_storage(&updated)?, None);
    Ok(())
}

/// A renounce note sent by a non-owner is rejected.
#[tokio::test]
async fn renounce_from_non_owner_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let non_owner = AccountIdBuilder::new().build_with_seed([2; 32]);

    let account = create_ownable_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let note =
        owner_config_note(non_owner, account.id(), OwnerConfigAction::RenounceOwnership, &mut rng)?;

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain.build_tx_context(account.id(), &[note.id()], &[])?.build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);
    Ok(())
}
