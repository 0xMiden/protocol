extern crate alloc;

use alloc::vec::Vec;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Felt;
use miden_protocol::account::{Account, AccountId, AccountType};
use miden_protocol::note::Note;
use miden_standards::errors::standards::{
    ERR_RBAC_CONFIG_TARGET_ACCOUNT_MISMATCH,
    ERR_RBAC_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_RBAC_CONFIG_UNKNOWN_SELECTOR,
};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint, RbacConfig, RbacConfigNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{MockChain, assert_transaction_executor_error};

// The RBAC account and storage-getter helpers are shared with the parent `rbac` suite, which
// owns the exhaustive tests of the underlying component. This suite only checks that the
// RbacConfig note dispatches each action and rejects malformed notes.
use super::{create_rbac_chain, get_role_config, is_role_member, role, test_account_id};

// HELPERS
// ================================================================================================

/// Builds an [`RbacConfigNote`] for `config` sent by `sender` and targeting `account`.
fn rbac_config_note(
    sender: AccountId,
    account: AccountId,
    config: RbacConfig,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = RbacConfigNote::builder()
        .sender(sender)
        .account(account)
        .config(config)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the RbacConfig script with hand-crafted storage, bypassing the builder
/// so malformed inputs can be exercised.
/// It carries a `NetworkAccountTarget` for the consuming account, like a real config note,
/// so the note passes the script's target check and reaches the guard under test.
fn malformed_rbac_config_note(
    sender: AccountId,
    target: AccountId,
    storage: Vec<Felt>,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(RbacConfigNote::script())
        .note_storage(storage)?
        .attachment(NetworkAccountTarget::new(target, NoteExecutionHint::Always)?)
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

    let grant = rbac_config_note(
        admin,
        account.id(),
        RbacConfig::GrantRole { role: minter.clone(), account: member },
        &mut rng,
    )?;
    let granted = execute_note_and_apply(&mock_chain, &account, grant).await?;
    assert!(is_role_member(&granted, &minter, member)?);

    let revoke = rbac_config_note(
        admin,
        granted.id(),
        RbacConfig::RevokeRole { role: minter.clone(), account: member },
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

    let note = rbac_config_note(
        admin,
        account.id(),
        RbacConfig::SetRoleAdmin {
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

    let grant = rbac_config_note(
        admin,
        account.id(),
        RbacConfig::GrantRole { role: minter.clone(), account: member },
        &mut rng,
    )?;
    let granted = execute_note_and_apply(&mock_chain, &account, grant).await?;
    assert!(is_role_member(&granted, &minter, member)?);

    // the member (note sender) renounces the role itself
    let renounce = rbac_config_note(
        member,
        granted.id(),
        RbacConfig::RenounceRole { role: minter.clone() },
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
    let note = malformed_rbac_config_note(admin, account.id(), vec![Felt::from(99u32)], &mut rng)?;
    let result = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_RBAC_CONFIG_UNKNOWN_SELECTOR);
    Ok(())
}

/// A note whose storage item count does not match its selector is rejected by the count guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // GrantRole selector (0) but only one storage item instead of the expected four
    let note = malformed_rbac_config_note(admin, account.id(), vec![Felt::from(0u32)], &mut rng)?;
    let result = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_RBAC_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS);
    Ok(())
}

/// The note is bound to its target account, so a decoy account cannot consume a note meant for
/// another account. The decoy carries the same `RoleBasedAccessControl` setup with the same admin,
/// so the sender-based authorization inside `rbac::grant_role` would pass; consuming a note
/// targeted at a different account aborts at the target check before any role change runs. Without
/// the binding the decoy would succeed and burn the note, denying it to its intended target.
#[tokio::test]
async fn decoy_account_cannot_consume_note_of_another_account() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let member = test_account_id(42);

    let (decoy, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // The note's intended target. It need not be built: the note only references its ID.
    let target = AccountId::builder().account_type(AccountType::Public).build_with_seed([9; 32]);

    let note = rbac_config_note(
        admin,
        target,
        RbacConfig::GrantRole { role: role("MINTER"), account: member },
        &mut rng,
    )?;

    let result = mock_chain
        .build_transaction(decoy.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_RBAC_CONFIG_TARGET_ACCOUNT_MISMATCH);
    Ok(())
}
