//! Tests for the `BLOCKLIST_CONFIG` standard note, which dispatches the
//! [`miden_standards::account::policies::BlocklistManager`] admin procedures from a note.
//!
//! The suite covers the note itself: that each selector dispatches to the matching procedure, and
//! that the script's own guards reject malformed storage. The blocklist semantics (the
//! `check_policy` predicate, the noop cases) and the `Authority` rejection of an unauthorized
//! sender are covered by the parent [`super`] suite.

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{AccountId, AccountType, StorageMapKey};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::policies::BlocklistStorage;
use miden_standards::errors::standards::{
    ERR_BLOCKLIST_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_BLOCKLIST_CONFIG_UNKNOWN_SELECTOR,
    ERR_NOTE_CONSUMER_NOT_ATTACHMENT_TARGET,
};
use miden_standards::note::{
    BlocklistConfig,
    BlocklistConfigNote,
    NetworkAccountTarget,
    NoteExecutionHint,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use super::{
    add_faucet_with_owner_blocklist_transfer,
    add_rbac_faucet_with_blocklist,
    dummy_owner,
};
use crate::consume_note;
use crate::scripts::rbac::{build_grant_role_note, role, test_account_id};

// HELPERS
// ================================================================================================

/// Builds a [`BlocklistConfigNote`] for `config`, sent by `sender` and targeting the faucet.
fn blocklist_config_note(
    sender: AccountId,
    faucet_id: AccountId,
    config: BlocklistConfig,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    let note = BlocklistConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(config)
        .generate_serial_number(&mut rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the BlocklistConfig script with hand-crafted storage, bypassing the
/// builder so malformed inputs can be exercised.
///
/// It carries a `NetworkAccountTarget` for the consuming account, like a real config note, so
/// the note passes the script's target check and reaches the guard under test.
fn malformed_blocklist_config_note(
    sender: AccountId,
    target: AccountId,
    storage: Vec<Felt>,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    let note = NoteBuilder::new(sender, &mut rng)
        .script(BlocklistConfigNote::script())
        .note_storage(storage)?
        .attachment(NetworkAccountTarget::new(target, NoteExecutionHint::Always)?)
        .build()?;
    Ok(note)
}

/// Returns whether `target` is blocked in the faucet's latest committed `blocked_accounts` map.
fn is_blocked(
    mock_chain: &MockChain,
    faucet_id: AccountId,
    target: AccountId,
) -> anyhow::Result<bool> {
    let faucet = mock_chain.committed_account(faucet_id)?;
    let key = StorageMapKey::new(AccountIdKey::from(target).as_word());
    let word = faucet.storage().get_map_item(BlocklistStorage::blocked_accounts_slot(), key)?;
    Ok(word != Word::default())
}

// TESTS
// ================================================================================================

/// The note dispatches the BlockAccount and UnblockAccount actions: the owner blocks an account,
/// then unblocks it.
#[tokio::test]
async fn block_and_unblock() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    let block = blocklist_config_note(
        owner_id,
        faucet.id(),
        BlocklistConfig::BlockAccount { account: target_account.id() },
        1,
    )?;
    let unblock = blocklist_config_note(
        owner_id,
        faucet.id(),
        BlocklistConfig::UnblockAccount { account: target_account.id() },
        2,
    )?;
    for note in [&block, &unblock] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;
    assert!(!is_blocked(&mock_chain, faucet.id(), target_account.id())?);

    consume_note(&mut mock_chain, faucet.id(), &block).await?;
    assert!(is_blocked(&mock_chain, faucet.id(), target_account.id())?);

    consume_note(&mut mock_chain, faucet.id(), &unblock).await?;
    assert!(!is_blocked(&mock_chain, faucet.id(), target_account.id())?);

    Ok(())
}

/// Under `Authority::RbacControlled` the note is authorized for a `BLOCKLISTER` role holder.
#[tokio::test]
async fn rbac_blocklister_can_block() -> anyhow::Result<()> {
    let admin = test_account_id(70);
    let blocklister = test_account_id(71);

    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_rbac_faucet_with_blocklist(&mut builder, admin)?;

    let grant = build_grant_role_note(admin, &role("BLOCKLISTER"), blocklister)?;
    let block = blocklist_config_note(
        blocklister,
        faucet.id(),
        BlocklistConfig::BlockAccount { account: target_account.id() },
        3,
    )?;
    for note in [&grant, &block] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_note(&mut mock_chain, faucet.id(), &grant).await?;
    consume_note(&mut mock_chain, faucet.id(), &block).await?;

    assert!(is_blocked(&mock_chain, faucet.id(), target_account.id())?);

    Ok(())
}

/// A note whose selector matches no known action is rejected by the script's dispatch guard.
#[tokio::test]
async fn unknown_selector_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    // selector 99 is not a known action
    let note = malformed_blocklist_config_note(
        owner_id,
        faucet.id(),
        vec![
            Felt::from(99u32),
            target_account.id().suffix(),
            target_account.id().prefix().as_felt(),
        ],
        6,
    )?;

    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(faucet.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_BLOCKLIST_CONFIG_UNKNOWN_SELECTOR);

    Ok(())
}

/// A note whose storage item count does not match its selector is rejected by the count guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    // BlockAccount selector (0) but the account prefix is missing
    let note = malformed_blocklist_config_note(
        owner_id,
        faucet.id(),
        vec![Felt::from(0u32), target_account.id().suffix()],
        7,
    )?;

    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(faucet.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_BLOCKLIST_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
    );

    Ok(())
}

/// The note is bound to its target faucet, so a decoy faucet cannot consume a note meant for
/// another one. The decoy carries the same manager setup with the same owner, so the sender-based
/// authorization would pass; consuming a note targeted at a different faucet aborts at the target
/// check before the list changes.
#[tokio::test]
async fn decoy_faucet_cannot_consume_note_of_another_faucet() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let decoy = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    // The note's intended target. It need not be built: the note only references its ID.
    let target = AccountId::builder().account_type(AccountType::Public).build_with_seed([9; 32]);

    let note = blocklist_config_note(
        owner_id,
        target,
        BlocklistConfig::BlockAccount { account: target_account.id() },
        9,
    )?;

    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(decoy.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_CONSUMER_NOT_ATTACHMENT_TARGET);
    Ok(())
}
