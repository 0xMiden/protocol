extern crate alloc;

use alloc::sync::Arc;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Felt;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountStorageMode,
    AccountType,
    StorageSlot,
};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::assembly::debuginfo::SourceManagerSync;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::Ownable;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_SENDER_NOT_OWNER;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

// HELPERS
// ================================================================================================

fn create_ownable_account(
    owner: AccountId,
    initial_storage: Vec<StorageSlot>,
) -> anyhow::Result<Account> {
    let component_code = r#"
        use miden::standards::access::ownable
        pub use ownable::get_owner
        pub use ownable::transfer_ownership
        pub use ownable::renounce_ownership
    "#;
    let component_code_obj =
        CodeBuilder::default().compile_component_code("test::ownable", component_code)?;

    let mut storage_slots = initial_storage;
    storage_slots.push(Ownable::new(owner).to_storage_slot());

    let account = AccountBuilder::new([1; 32])
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component({
            let metadata = AccountComponentMetadata::new("test::ownable", AccountType::all());
            AccountComponent::new(component_code_obj, storage_slots, metadata)?
        })
        .build_existing()?;
    Ok(account)
}

fn get_owner_from_storage(account: &Account) -> anyhow::Result<Option<AccountId>> {
    let ownable = Ownable::try_from_storage(account.storage())?;
    Ok(ownable.owner())
}

fn create_transfer_note(
    sender: AccountId,
    new_owner: AccountId,
    rng: &mut RandomCoin,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = format!(
        r#"
        use miden::standards::access::ownable->test_account
        begin
            repeat.14 push.0 end
            push.{new_owner_prefix}
            push.{new_owner_suffix}
            call.test_account::transfer_ownership
            dropw dropw dropw dropw
        end
    "#,
        new_owner_prefix = new_owner.prefix().as_felt(),
        new_owner_suffix = Felt::new(new_owner.suffix().as_canonical_u64()),
    );

    let note = NoteBuilder::new(sender, rng)
        .source_manager(source_manager)
        .code(script)
        .build()?;

    Ok(note)
}

fn create_renounce_note(
    sender: AccountId,
    rng: &mut RandomCoin,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = r#"
        use miden::standards::access::ownable->test_account
        begin
            repeat.16 push.0 end
            call.test_account::renounce_ownership
            dropw dropw dropw dropw
        end
    "#;

    let note = NoteBuilder::new(sender, rng)
        .source_manager(source_manager)
        .code(script)
        .build()?;

    Ok(note)
}

// TESTS
// ================================================================================================

/// A non-owner cannot transfer ownership.
#[tokio::test]
async fn test_transfer_ownership_only_owner() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let non_owner = AccountIdBuilder::new().build_with_seed([2; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([3; 32]);

    let account = create_ownable_account(owner, vec![])?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let note = create_transfer_note(non_owner, new_owner, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);
    Ok(())
}

/// The owner transfers ownership in a single step; the new owner takes effect immediately.
#[tokio::test]
async fn test_transfer_ownership_is_immediate() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([2; 32]);

    let account = create_ownable_account(owner, vec![])?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let transfer_note =
        create_transfer_note(owner, new_owner, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(RawOutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[transfer_note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_delta(executed.account_delta())?;

    // The owner is updated directly, with no nomination/acceptance step.
    assert_eq!(get_owner_from_storage(&updated)?, Some(new_owner));
    Ok(())
}

/// The owner renounces ownership, leaving the account permanently ownerless.
#[tokio::test]
async fn test_renounce_ownership() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_ownable_account(owner, vec![])?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let renounce_note = create_renounce_note(owner, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(RawOutputNote::Full(renounce_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[renounce_note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_delta(executed.account_delta())?;

    assert_eq!(get_owner_from_storage(&updated)?, None);
    Ok(())
}

/// A non-owner cannot renounce ownership.
#[tokio::test]
async fn test_renounce_ownership_only_owner() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let non_owner = AccountIdBuilder::new().build_with_seed([2; 32]);

    let account = create_ownable_account(owner, vec![])?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let renounce_note = create_renounce_note(non_owner, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(RawOutputNote::Full(renounce_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[renounce_note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);
    Ok(())
}

/// `transfer_ownership` fails when the new owner account ID is invalid.
/// An invalid account ID has its suffix's lower 8 bits set to a non-zero value.
#[tokio::test]
async fn test_transfer_ownership_fails_with_invalid_account_id() -> anyhow::Result<()> {
    use miden_protocol::errors::protocol::ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO;

    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_ownable_account(owner, vec![])?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let invalid_prefix = owner.prefix().as_felt();
    let invalid_suffix = Felt::new(1);

    let script = format!(
        r#"
        use miden::standards::access::ownable->test_account
        begin
            repeat.14 push.0 end
            push.{invalid_suffix}
            push.{invalid_prefix}
            call.test_account::transfer_ownership
            dropw dropw dropw dropw
        end
    "#,
    );

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());
    let note = NoteBuilder::new(owner, &mut rng)
        .source_manager(Arc::clone(&source_manager))
        .code(script)
        .build()?;

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(
        result,
        ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO
    );
    Ok(())
}
