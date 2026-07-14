extern crate alloc;

use alloc::vec::Vec;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Felt;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::note::Note;
use miden_standards::errors::standards::{
    ERR_RBAC_ACTION_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS, ERR_RBAC_ACTION_UNKNOWN_SELECTOR,
};
use miden_standards::note::{RbacAction, RbacActionNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{MockChain, assert_transaction_executor_error};

// The RBAC account and storage-getter helpers are shared with the `rbac` suite, which owns the
// exhaustive tests of the underlying component. This suite only checks that the RbacAction
// note dispatches each action and rejects malformed notes.
use super::rbac::{create_rbac_chain, get_role_config, is_role_member, role, test_account_id};

// HELPERS
// ================================================================================================

/// Builds an [`RbacActionNote`] for `action` sent by `sender` and targeting `account`.
fn rbac_action_note(
    sender: AccountId,
    account: AccountId,
    action: RbacAction,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = RbacActionNote::builder()
        .sender(sender)
        .account(account)
        .action(action)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the RbacAction script with hand-crafted storage, bypassing the builder
/// so malformed inputs can be exercised.
fn malformed_rbac_action_note(
    sender: AccountId,
    storage: Vec<Felt>,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(RbacActionNote::script())
        .note_storage(storage)?
        .build()?;
    Ok(note)
}

async fn execute_note_and_apply(
    mock_chain: &MockChain,
    account: &Account,
    note: Note,
) -> anyhow::Result<Account> {
    let executed = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await?;

    let mut updated = account.clone();
    updated.apply_patch(executed.account_patch())?;

    Ok(updated)
}

// TESTS
// ================================================================================================

/// The note dispatches GrantRole and RevokeRole: the admin grants a role, then revokes it.
#[tokio::test]
async fn grant_then_revoke_dispatch() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let member = test_account_id(42);
    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let grant = rbac_action_note(
        admin,
        account.id(),
        RbacAction::GrantRole { role: minter.clone(), account: member },
        &mut rng,
    )?;
    let granted = execute_note_and_apply(&mock_chain, &account, grant).await?;
    assert!(is_role_member(&granted, &minter, member)?);

    let revoke = rbac_action_note(
        admin,
        granted.id(),
        RbacAction::RevokeRole { role: minter.clone(), account: member },
        &mut rng,
    )?;
    let revoked = execute_note_and_apply(&mock_chain, &granted, revoke).await?;
    assert!(!is_role_member(&revoked, &minter, member)?);
    Ok(())
}

/// The note dispatches SetRoleAdmin: the admin delegates a role's admin to another role.
#[tokio::test]
async fn set_role_admin_dispatch() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let minter = role("MINTER");
    let mint_admin = role("MINT_ADMIN");

    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let note = rbac_action_note(
        admin,
        account.id(),
        RbacAction::SetRoleAdmin {
            role: minter.clone(),
            admin_role: Some(mint_admin.clone()),
        },
        &mut rng,
    )?;
    let updated = execute_note_and_apply(&mock_chain, &account, note).await?;

    let (_, admin_role_symbol) = get_role_config(&updated, &minter)?;
    assert_eq!(admin_role_symbol, mint_admin.as_element());
    Ok(())
}

/// The note dispatches RenounceRole: a role holder renounces its role.
#[tokio::test]
async fn renounce_dispatch() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let member = test_account_id(42);
    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let grant = rbac_action_note(
        admin,
        account.id(),
        RbacAction::GrantRole { role: minter.clone(), account: member },
        &mut rng,
    )?;
    let granted = execute_note_and_apply(&mock_chain, &account, grant).await?;
    assert!(is_role_member(&granted, &minter, member)?);

    // the member (note sender) renounces the role itself
    let renounce = rbac_action_note(
        member,
        granted.id(),
        RbacAction::RenounceRole { role: minter.clone() },
        &mut rng,
    )?;
    let renounced = execute_note_and_apply(&mock_chain, &granted, renounce).await?;
    assert!(!is_role_member(&renounced, &minter, member)?);
    Ok(())
}

/// A note whose selector matches no known action is rejected by the script's dispatch guard.
#[tokio::test]
async fn unknown_selector_fails() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // selector 99 is not a known action
    let note = malformed_rbac_action_note(admin, vec![Felt::from(99u32)], &mut rng)?;
    let result = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_RBAC_ACTION_UNKNOWN_SELECTOR);
    Ok(())
}

/// A note whose storage item count does not match its selector is rejected by the count guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // GrantRole selector (0) but only one storage item instead of the expected four
    let note = malformed_rbac_action_note(admin, vec![Felt::from(0u32)], &mut rng)?;
    let result = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_RBAC_ACTION_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS);
    Ok(())
}
