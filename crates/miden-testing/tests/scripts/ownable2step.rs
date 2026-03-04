extern crate alloc;

use alloc::sync::Arc;

use miden_processor::crypto::RpoRandomCoin;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountStorageMode,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::assembly::debuginfo::SourceManagerSync;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::OutputNote;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, FieldElement, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NO_NOMINATED_OWNER,
    ERR_SENDER_NOT_NOMINATED_OWNER,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

static OWNER_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::ownable2step::owner_config")
        .expect("storage slot name should be valid")
});

// HELPERS
// ================================================================================================

fn create_ownable_account(
    owner: AccountId,
    initial_storage: Vec<StorageSlot>,
) -> anyhow::Result<Account> {
    let component_code = r#"
        use miden::standards::access::ownable2step
        pub use ownable2step::get_owner
        pub use ownable2step::get_nominated_owner
        pub use ownable2step::transfer_ownership
        pub use ownable2step::accept_ownership
        pub use ownable2step::renounce_ownership
    "#;
    let component_code_obj =
        CodeBuilder::default().compile_component_code("test::ownable", component_code)?;

    let ownership_word: Word = [
        Felt::ZERO,               // word[0] → stack[3] = nominated_suffix
        Felt::ZERO,               // word[1] → stack[2] = nominated_prefix
        owner.suffix(),           // word[2] → stack[1] = owner_suffix
        owner.prefix().as_felt(), // word[3] → stack[0] = owner_prefix
    ]
    .into();

    let mut storage_slots = initial_storage;
    storage_slots.push(StorageSlot::with_value(OWNER_CONFIG_SLOT_NAME.clone(), ownership_word));

    let account = AccountBuilder::new([1; 32])
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component({
            let metadata = AccountComponentMetadata::new("test::ownable").with_supports_all_types();
            AccountComponent::new(component_code_obj, storage_slots, metadata)?
        })
        .build_existing()?;
    Ok(account)
}

fn get_owner_from_storage(account: &Account) -> anyhow::Result<Option<AccountId>> {
    let word = account.storage().get_item(&OWNER_CONFIG_SLOT_NAME)?;
    let prefix = word[3];
    let suffix = word[2];
    if prefix == Felt::ZERO && suffix == Felt::ZERO {
        Ok(None)
    } else {
        Ok(Some(AccountId::try_from([prefix, suffix])?))
    }
}

fn get_nominated_owner_from_storage(account: &Account) -> anyhow::Result<Option<AccountId>> {
    let word = account.storage().get_item(&OWNER_CONFIG_SLOT_NAME)?;
    let prefix = word[1];
    let suffix = word[0];
    if prefix == Felt::ZERO && suffix == Felt::ZERO {
        Ok(None)
    } else {
        Ok(Some(AccountId::try_from([prefix, suffix])?))
    }
}

fn create_transfer_note(
    sender: AccountId,
    new_owner: AccountId,
    rng: &mut RpoRandomCoin,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = format!(
        r#"
        use miden::standards::access::ownable2step->test_account
        begin
            repeat.14 push.0 end
            push.{new_owner_suffix} push.{new_owner_prefix}
            call.test_account::transfer_ownership
            dropw dropw dropw dropw
        end
    "#,
        new_owner_suffix = new_owner.suffix(),
        new_owner_prefix = new_owner.prefix().as_felt(),
    );

    let note = NoteBuilder::new(sender, rng)
        .source_manager(source_manager)
        .code(script)
        .build()?;

    Ok(note)
}

fn create_accept_note(
    sender: AccountId,
    rng: &mut RpoRandomCoin,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = r#"
        use miden::standards::access::ownable2step->test_account
        begin
            repeat.16 push.0 end
            call.test_account::accept_ownership
            dropw dropw dropw dropw
        end
    "#;

    let note = NoteBuilder::new(sender, rng)
        .source_manager(source_manager)
        .code(script)
        .build()?;

    Ok(note)
}

fn create_renounce_note(
    sender: AccountId,
    rng: &mut RpoRandomCoin,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = r#"
        use miden::standards::access::ownable2step->test_account
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

#[tokio::test]
async fn test_transfer_ownership_only_owner() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let non_owner = AccountIdBuilder::new().build_with_seed([2; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([3; 32]);

    let account = create_ownable_account(owner, vec![])?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RpoRandomCoin::new([Felt::from(100u32); 4].into());
    let note = create_transfer_note(non_owner, new_owner, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(OutputNote::Full(note.clone()));
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

#[tokio::test]
async fn test_complete_ownership_transfer() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([2; 32]);

    let account = create_ownable_account(owner, vec![])?;

    // Step 1: transfer ownership
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RpoRandomCoin::new([Felt::from(100u32); 4].into());
    let transfer_note =
        create_transfer_note(owner, new_owner, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(OutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[transfer_note.id()], &[])?
        .with_source_manager(Arc::clone(&source_manager))
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_delta(executed.account_delta())?;

    // Verify intermediate state: owner unchanged, nominated set
    assert_eq!(get_owner_from_storage(&updated)?, Some(owner));
    assert_eq!(get_nominated_owner_from_storage(&updated)?, Some(new_owner));

    // Commit step 1 to the chain
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    // Step 2: accept ownership
    let mut rng2 = RpoRandomCoin::new([Felt::from(200u32); 4].into());
    let accept_note = create_accept_note(new_owner, &mut rng2, Arc::clone(&source_manager))?;

    let tx2 = mock_chain
        .build_tx_context(updated.clone(), &[], std::slice::from_ref(&accept_note))?
        .with_source_manager(source_manager)
        .build()?;
    let executed2 = tx2.execute().await?;

    let mut final_account = updated.clone();
    final_account.apply_delta(executed2.account_delta())?;

    assert_eq!(get_owner_from_storage(&final_account)?, Some(new_owner));
    assert_eq!(get_nominated_owner_from_storage(&final_account)?, None);
    Ok(())
}

#[tokio::test]
async fn test_accept_ownership_only_nominated_owner() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([2; 32]);
    let wrong = AccountIdBuilder::new().build_with_seed([3; 32]);

    let account = create_ownable_account(owner, vec![])?;

    // Step 1: transfer
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RpoRandomCoin::new([Felt::from(100u32); 4].into());
    let transfer_note =
        create_transfer_note(owner, new_owner, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(OutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[transfer_note.id()], &[])?
        .with_source_manager(Arc::clone(&source_manager))
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_delta(executed.account_delta())?;

    // Commit step 1 to the chain
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    // Step 2: wrong account tries accept
    let mut rng2 = RpoRandomCoin::new([Felt::from(200u32); 4].into());
    let accept_note = create_accept_note(wrong, &mut rng2, Arc::clone(&source_manager))?;

    let tx2 = mock_chain
        .build_tx_context(updated.clone(), &[], std::slice::from_ref(&accept_note))?
        .with_source_manager(source_manager)
        .build()?;
    let result = tx2.execute().await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_NOMINATED_OWNER);
    Ok(())
}

#[tokio::test]
async fn test_accept_ownership_no_nominated() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_ownable_account(owner, vec![])?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RpoRandomCoin::new([Felt::from(200u32); 4].into());
    let accept_note = create_accept_note(owner, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(OutputNote::Full(accept_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[accept_note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_NO_NOMINATED_OWNER);
    Ok(())
}

#[tokio::test]
async fn test_cancel_transfer() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([2; 32]);

    let account = create_ownable_account(owner, vec![])?;

    // Step 1: transfer
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RpoRandomCoin::new([Felt::from(100u32); 4].into());
    let transfer_note =
        create_transfer_note(owner, new_owner, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(OutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[transfer_note.id()], &[])?
        .with_source_manager(Arc::clone(&source_manager))
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_delta(executed.account_delta())?;

    // Commit step 1 to the chain
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    // Step 2: cancel by transferring to self (owner)
    let mut rng2 = RpoRandomCoin::new([Felt::from(200u32); 4].into());
    let cancel_note = create_transfer_note(owner, owner, &mut rng2, Arc::clone(&source_manager))?;

    let tx2 = mock_chain
        .build_tx_context(updated.clone(), &[], std::slice::from_ref(&cancel_note))?
        .with_source_manager(source_manager)
        .build()?;
    let executed2 = tx2.execute().await?;

    let mut final_account = updated.clone();
    final_account.apply_delta(executed2.account_delta())?;

    assert_eq!(get_nominated_owner_from_storage(&final_account)?, None);
    assert_eq!(get_owner_from_storage(&final_account)?, Some(owner));
    Ok(())
}

/// Tests that an owner can transfer to themselves when no nominated transfer exists.
/// This is a no-op but should succeed without errors.
#[tokio::test]
async fn test_transfer_to_self_no_nominated() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_ownable_account(owner, vec![])?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RpoRandomCoin::new([Felt::from(100u32); 4].into());
    let note = create_transfer_note(owner, owner, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(OutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_delta(executed.account_delta())?;

    assert_eq!(get_owner_from_storage(&updated)?, Some(owner));
    assert_eq!(get_nominated_owner_from_storage(&updated)?, None);
    Ok(())
}

#[tokio::test]
async fn test_renounce_ownership() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let new_owner = AccountIdBuilder::new().build_with_seed([2; 32]);

    let account = create_ownable_account(owner, vec![])?;

    // Step 1: transfer (to have nominated)
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
    let mut rng = RpoRandomCoin::new([Felt::from(100u32); 4].into());
    let transfer_note =
        create_transfer_note(owner, new_owner, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(OutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(account.id(), &[transfer_note.id()], &[])?
        .with_source_manager(Arc::clone(&source_manager))
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_delta(executed.account_delta())?;

    // Commit step 1 to the chain
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    // Step 2: renounce
    let mut rng2 = RpoRandomCoin::new([Felt::from(200u32); 4].into());
    let renounce_note = create_renounce_note(owner, &mut rng2, Arc::clone(&source_manager))?;

    let tx2 = mock_chain
        .build_tx_context(updated.clone(), &[], std::slice::from_ref(&renounce_note))?
        .with_source_manager(source_manager)
        .build()?;
    let executed2 = tx2.execute().await?;

    let mut final_account = updated.clone();
    final_account.apply_delta(executed2.account_delta())?;

    assert_eq!(get_owner_from_storage(&final_account)?, None);
    assert_eq!(get_nominated_owner_from_storage(&final_account)?, None);
    Ok(())
}

/// Tests that transfer_ownership fails when the new owner account ID is invalid.
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
        use miden::standards::access::ownable2step->test_account
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
    let mut rng = RpoRandomCoin::new([Felt::from(100u32); 4].into());
    let note = NoteBuilder::new(owner, &mut rng)
        .source_manager(Arc::clone(&source_manager))
        .code(script)
        .build()?;

    builder.add_output_note(OutputNote::Full(note.clone()));
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
