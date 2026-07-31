//! Tests for the `ALLOWLIST_CONFIG` standard note, which dispatches the
//! [`miden_standards::account::policies::AllowlistManager`] admin procedures from a note.
//!
//! The suite covers the note itself: that each selector dispatches to the matching procedure, and
//! that the script's own guards reject malformed storage. The allowlist semantics (the
//! `check_policy` predicate, the noop cases) and the `Authority` rejection of an unauthorized
//! sender are covered by the parent [`super`] suite.

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{AccountId, AccountType, StorageMapKey};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::policies::AllowlistStorage;
use miden_standards::errors::standards::{
    ERR_ALLOWLIST_CONFIG_TARGET_ACCOUNT_MISMATCH,
    ERR_ALLOWLIST_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_ALLOWLIST_CONFIG_UNKNOWN_SELECTOR,
};
use miden_standards::note::{
    AllowlistConfig,
    AllowlistConfigNote,
    NetworkAccountTarget,
    NoteExecutionHint,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use super::{
    add_faucet_with_owner_allowlist_transfer,
    add_rbac_faucet_with_allowlist,
    dummy_owner,
};
use crate::consume_note;
use crate::scripts::rbac::{build_grant_role_note, role, test_account_id};

// HELPERS
// ================================================================================================

/// Builds an [`AllowlistConfigNote`] for `config`, sent by `sender` and targeting the faucet.
fn allowlist_config_note(
    sender: AccountId,
    faucet_id: AccountId,
    config: AllowlistConfig,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    let note = AllowlistConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(config)
        .generate_serial_number(&mut rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the AllowlistConfig script with hand-crafted storage, bypassing the
/// builder so malformed inputs can be exercised.
/// It carries a `NetworkAccountTarget` for the consuming account, like a real config note,
/// so the note passes the script's target check and reaches the guard under test.
fn malformed_allowlist_config_note(
    sender: AccountId,
    target: AccountId,
    storage: Vec<Felt>,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    let note = NoteBuilder::new(sender, &mut rng)
        .script(AllowlistConfigNote::script())
        .note_storage(storage)?
        .attachment(NetworkAccountTarget::new(target, NoteExecutionHint::Always)?)
        .build()?;
    Ok(note)
}

/// Returns whether `target` is allowed in the faucet's latest committed `allowed_accounts` map.
fn is_allowed(
    mock_chain: &MockChain,
    faucet_id: AccountId,
    target: AccountId,
) -> anyhow::Result<bool> {
    let faucet = mock_chain.committed_account(faucet_id)?;
    let key = StorageMapKey::new(AccountIdKey::from(target).as_word());
    let word = faucet.storage().get_map_item(AllowlistStorage::allowed_accounts_slot(), key)?;
    Ok(word != Word::default())
}

// TESTS
// ================================================================================================

/// The note dispatches the AllowAccount and DisallowAccount actions: the owner allows an account,
/// then disallows it.
#[tokio::test]
async fn allow_then_disallow_dispatch() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    let allow = allowlist_config_note(
        owner_id,
        faucet.id(),
        AllowlistConfig::AllowAccount { account: target_account.id() },
        1,
    )?;
    let disallow = allowlist_config_note(
        owner_id,
        faucet.id(),
        AllowlistConfig::DisallowAccount { account: target_account.id() },
        2,
    )?;
    for note in [&allow, &disallow] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;
    assert!(!is_allowed(&mock_chain, faucet.id(), target_account.id())?);

    consume_note(&mut mock_chain, faucet.id(), &allow).await?;
    assert!(is_allowed(&mock_chain, faucet.id(), target_account.id())?);

    consume_note(&mut mock_chain, faucet.id(), &disallow).await?;
    assert!(!is_allowed(&mock_chain, faucet.id(), target_account.id())?);

    Ok(())
}

/// Under `Authority::RbacControlled` the note is authorized for an `ALLOWLISTER` role holder.
#[tokio::test]
async fn rbac_allowlister_can_allow() -> anyhow::Result<()> {
    let admin = test_account_id(80);
    let allowlister = test_account_id(81);

    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_rbac_faucet_with_allowlist(&mut builder, admin, [])?;

    let grant = build_grant_role_note(admin, &role("ALLOWLISTER"), allowlister)?;
    let allow = allowlist_config_note(
        allowlister,
        faucet.id(),
        AllowlistConfig::AllowAccount { account: target_account.id() },
        3,
    )?;
    for note in [&grant, &allow] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_note(&mut mock_chain, faucet.id(), &grant).await?;
    consume_note(&mut mock_chain, faucet.id(), &allow).await?;

    assert!(is_allowed(&mock_chain, faucet.id(), target_account.id())?);

    Ok(())
}

/// A note whose selector matches no known action is rejected by the script's dispatch guard.
#[tokio::test]
async fn unknown_selector_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    // selector 99 is not a known action
    let note = malformed_allowlist_config_note(
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

    assert_transaction_executor_error!(result, ERR_ALLOWLIST_CONFIG_UNKNOWN_SELECTOR);

    Ok(())
}

/// A note whose storage item count does not match its selector is rejected by the count guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    // AllowAccount selector (0) but the account prefix is missing
    let note = malformed_allowlist_config_note(
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
        ERR_ALLOWLIST_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
    );

    Ok(())
}

/// The note is bound to its target faucet, so a decoy faucet cannot consume a note meant for
/// another one. The decoy carries the same manager setup with the same owner, so the sender-based
/// authorization would pass; consuming a note targeted at a different faucet aborts at the target
/// check before the list changes. Without the binding the decoy would succeed and burn the note,
/// denying it to its intended target.
#[tokio::test]
async fn decoy_faucet_cannot_consume_note_of_another_faucet() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let decoy = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    // The note's intended target. It need not be built: the note only references its ID.
    let target = AccountId::builder().account_type(AccountType::Public).build_with_seed([9; 32]);

    let note = allowlist_config_note(
        owner_id,
        target,
        AllowlistConfig::AllowAccount { account: target_account.id() },
        9,
    )?;

    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(decoy.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ALLOWLIST_CONFIG_TARGET_ACCOUNT_MISMATCH);
    Ok(())
}
