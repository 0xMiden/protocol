extern crate alloc;

use alloc::collections::BTreeMap;
use core::slice;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountType,
    RoleSymbol,
    StorageMapKey,
};
use miden_protocol::note::Note;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{AccessControl, RoleBasedAccessControl};
use miden_standards::errors::standards::{
    ERR_ROLE_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_ROLE_CONFIG_UNKNOWN_SELECTOR,
    ERR_SENDER_NOT_ROLE_ADMIN,
};
use miden_standards::note::{RoleConfigAction, RoleConfigNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

// HELPERS
// ================================================================================================

fn create_rbac_account_with_admin(admin: AccountId) -> anyhow::Result<Account> {
    let account = AccountBuilder::new([9; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_components(AccessControl::Rbac { admin, roles: BTreeMap::new() })
        .build_existing()?;

    Ok(account)
}

fn create_rbac_chain(admin: AccountId) -> anyhow::Result<(Account, MockChain)> {
    let account = create_rbac_account_with_admin(admin)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    Ok((account, builder.build()?))
}

fn test_account_id(seed: u8) -> AccountId {
    AccountId::builder()
        .account_type(AccountType::Private)
        .build_with_seed([seed; 32])
}

fn role(name: &str) -> RoleSymbol {
    RoleSymbol::new(name).expect("role symbol should be valid")
}

fn role_config_key(role: &RoleSymbol) -> StorageMapKey {
    StorageMapKey::from_raw(Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(role)]))
}

fn role_membership_key(role: &RoleSymbol, account_id: AccountId) -> StorageMapKey {
    StorageMapKey::from_raw(Word::from([
        Felt::ZERO,
        Felt::from(role),
        account_id.suffix(),
        account_id.prefix().as_felt(),
    ]))
}

/// Returns the role's `(member_count, admin_role_symbol)` from on-chain storage.
fn get_role_config(account: &Account, role: &RoleSymbol) -> anyhow::Result<(Felt, Felt)> {
    let word = account
        .storage()
        .get_map_item(RoleBasedAccessControl::role_config_slot(), role_config_key(role))?;
    Ok((word[0], word[1]))
}

fn is_role_member(
    account: &Account,
    role: &RoleSymbol,
    account_id: AccountId,
) -> anyhow::Result<bool> {
    let word = account.storage().get_map_item(
        RoleBasedAccessControl::role_membership_slot(),
        role_membership_key(role, account_id),
    )?;
    Ok(word[0].as_canonical_u64() != 0)
}

/// Builds a [`RoleConfigNote`] for `action` sent by `sender` and targeting `account`.
fn role_config_note(
    sender: AccountId,
    account: AccountId,
    action: RoleConfigAction,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = RoleConfigNote::builder()
        .sender(sender)
        .account(account)
        .action(action)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the RoleConfig script with hand-crafted storage, bypassing the builder
/// so malformed inputs can be exercised.
fn malformed_role_config_note(
    sender: AccountId,
    storage: Vec<Felt>,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(RoleConfigNote::script())
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
        .build_tx_context(account.clone(), &[], slice::from_ref(note))?
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_patch(executed.account_patch())?;

    Ok(updated)
}

// TESTS
// ================================================================================================

/// The admin grants a role; the account becomes a member.
#[tokio::test]
async fn grant_role_sets_membership() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let member = test_account_id(42);
    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let note = role_config_note(
        admin,
        account.id(),
        RoleConfigAction::GrantRole { role: minter.clone(), account: member },
        &mut rng,
    )?;
    let granted = execute_note_and_apply(&mock_chain, &account, &note).await?;

    assert!(is_role_member(&granted, &minter, member)?);
    let (member_count, _) = get_role_config(&granted, &minter)?;
    assert_eq!(member_count, Felt::ONE);
    Ok(())
}

/// A grant sent by a non-admin is rejected by the rbac procedure.
#[tokio::test]
async fn grant_role_from_non_admin_fails() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let non_admin = test_account_id(50);
    let member = test_account_id(42);
    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let note = role_config_note(
        non_admin,
        account.id(),
        RoleConfigAction::GrantRole { role: minter, account: member },
        &mut rng,
    )?;

    let tx = mock_chain
        .build_tx_context(account.clone(), &[], slice::from_ref(&note))?
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ROLE_ADMIN);
    Ok(())
}

/// The admin revokes a previously granted role; the account is no longer a member.
#[tokio::test]
async fn revoke_role_clears_membership() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let member = test_account_id(42);
    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let grant = role_config_note(
        admin,
        account.id(),
        RoleConfigAction::GrantRole { role: minter.clone(), account: member },
        &mut rng,
    )?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant).await?;
    assert!(is_role_member(&granted, &minter, member)?);

    let revoke = role_config_note(
        admin,
        granted.id(),
        RoleConfigAction::RevokeRole { role: minter.clone(), account: member },
        &mut rng,
    )?;
    let revoked = execute_note_and_apply(&mock_chain, &granted, &revoke).await?;

    assert!(!is_role_member(&revoked, &minter, member)?);
    Ok(())
}

/// The admin delegates a role's admin to another role; the role config records the new admin.
#[tokio::test]
async fn set_role_admin_delegates_admin_role() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let minter = role("MINTER");
    let mint_admin = role("MINT_ADMIN");

    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let note = role_config_note(
        admin,
        account.id(),
        RoleConfigAction::SetRoleAdmin {
            role: minter.clone(),
            admin_role: Some(mint_admin.clone()),
        },
        &mut rng,
    )?;
    let updated = execute_note_and_apply(&mock_chain, &account, &note).await?;

    let (_, admin_role_symbol) = get_role_config(&updated, &minter)?;
    assert_eq!(admin_role_symbol, mint_admin.as_element());
    Ok(())
}

/// A role holder renounces its role; it is no longer a member.
#[tokio::test]
async fn renounce_role_clears_membership() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let member = test_account_id(42);
    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let grant = role_config_note(
        admin,
        account.id(),
        RoleConfigAction::GrantRole { role: minter.clone(), account: member },
        &mut rng,
    )?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant).await?;
    assert!(is_role_member(&granted, &minter, member)?);

    // the member (note sender) renounces the role itself
    let renounce = role_config_note(
        member,
        granted.id(),
        RoleConfigAction::RenounceRole { role: minter.clone() },
        &mut rng,
    )?;
    let renounced = execute_note_and_apply(&mock_chain, &granted, &renounce).await?;

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
    let note = malformed_role_config_note(admin, vec![Felt::from(99u32)], &mut rng)?;

    let tx = mock_chain
        .build_tx_context(account.clone(), &[], slice::from_ref(&note))?
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_ROLE_CONFIG_UNKNOWN_SELECTOR);
    Ok(())
}

/// A note whose storage item count does not match its selector is rejected by the count guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let (account, mock_chain) = create_rbac_chain(admin)?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // GrantRole selector (0) but only one storage item instead of the expected four
    let note = malformed_role_config_note(admin, vec![Felt::from(0u32)], &mut rng)?;

    let tx = mock_chain
        .build_tx_context(account.clone(), &[], slice::from_ref(&note))?
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_ROLE_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS);
    Ok(())
}
