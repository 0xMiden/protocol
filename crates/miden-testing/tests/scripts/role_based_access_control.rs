extern crate alloc;

use alloc::string::String;
use core::slice;

use anyhow::Context;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::asset::RoleSymbol;
use miden_protocol::errors::AccountIdError;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::RoleBasedAccessControl;
use miden_standards::errors::standards::{
    ERR_ACCOUNT_NOT_IN_ROLE,
    ERR_ACTIVE_ROLE_OUT_OF_BOUNDS,
    ERR_ADMIN_TRANSFER_IN_PROGRESS,
    ERR_ROLE_MEMBER_OUT_OF_BOUNDS,
    ERR_ROLE_SYMBOL_ZERO,
    ERR_SENDER_NOT_ADMIN,
    ERR_SENDER_NOT_ADMIN_OR_ROLE_ADMIN,
    ERR_SENDER_NOT_NOMINATED_ADMIN,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

// HELPERS
// ================================================================================================

fn create_rbac_account(rbac: RoleBasedAccessControl) -> anyhow::Result<Account> {
    let account = AccountBuilder::new([9; 32])
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(rbac)
        .build_existing()?;

    Ok(account)
}

fn create_rbac_chain(admin: AccountId) -> anyhow::Result<(Account, MockChain)> {
    let account = create_rbac_account(RoleBasedAccessControl::new(admin))?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    Ok((account, builder.build()?))
}

fn test_account_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    )
}

fn role(name: &str) -> RoleSymbol {
    RoleSymbol::new(name).expect("role symbol should be valid")
}

fn role_config_key(role: &RoleSymbol) -> Word {
    Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(role)])
}

fn active_role_key(index: u64) -> Word {
    Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::new(index)])
}

fn role_member_key(role: &RoleSymbol, index: u64) -> Word {
    Word::from([Felt::ZERO, Felt::ZERO, Felt::from(role), Felt::new(index)])
}

fn role_member_index_key(role: &RoleSymbol, account_id: AccountId) -> Word {
    Word::from([Felt::ZERO, Felt::from(role), account_id.suffix(), account_id.prefix().as_felt()])
}

fn account_id_from_felt_pair(
    suffix: Felt,
    prefix: Felt,
) -> Result<Option<AccountId>, AccountIdError> {
    if suffix == Felt::ZERO && prefix == Felt::ZERO {
        Ok(None)
    } else {
        AccountId::try_from_elements(suffix, prefix).map(Some)
    }
}

fn get_admins(account: &Account) -> anyhow::Result<(Option<AccountId>, Option<AccountId>)> {
    let word = account.storage().get_item(RoleBasedAccessControl::admin_config_slot())?;

    Ok((
        account_id_from_felt_pair(word[0], word[1])?,
        account_id_from_felt_pair(word[2], word[3])?,
    ))
}

fn get_role_config(account: &Account, role: &RoleSymbol) -> anyhow::Result<Word> {
    Ok(account
        .storage()
        .get_map_item(RoleBasedAccessControl::role_configs_slot(), role_config_key(role))?)
}

fn get_active_role_count(account: &Account) -> anyhow::Result<u64> {
    Ok(account.storage().get_item(RoleBasedAccessControl::state_slot())?[0].as_canonical_u64())
}

fn get_active_role(account: &Account, index: u64) -> anyhow::Result<RoleSymbol> {
    let word = account
        .storage()
        .get_map_item(RoleBasedAccessControl::active_roles_slot(), active_role_key(index))?;
    Ok(RoleSymbol::try_from(word[0])?)
}

fn get_role_member(account: &Account, role: &RoleSymbol, index: u64) -> anyhow::Result<AccountId> {
    let word = account
        .storage()
        .get_map_item(RoleBasedAccessControl::role_members_slot(), role_member_key(role, index))?;
    Ok(AccountId::try_from_elements(word[0], word[1])?)
}

fn get_role_member_index(
    account: &Account,
    role: &RoleSymbol,
    account_id: AccountId,
) -> anyhow::Result<u64> {
    Ok(account.storage().get_map_item(
        RoleBasedAccessControl::role_member_index_slot(),
        role_member_index_key(role, account_id),
    )?[0]
        .as_canonical_u64())
}

fn build_note(sender: AccountId, code: impl Into<String>, rng_seed: u32) -> anyhow::Result<Note> {
    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .code(code.into())
        .build()?)
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
    updated.apply_delta(executed.account_delta())?;

    Ok(updated)
}

// SCRIPTS
// ================================================================================================

fn transfer_admin_script(new_admin: AccountId) -> String {
    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.14 push.0 end
            push.{new_admin_prefix}
            push.{new_admin_suffix}
            call.role_based_access_control::transfer_admin
            dropw dropw dropw dropw
        end
        "#,
        new_admin_prefix = new_admin.prefix().as_felt(),
        new_admin_suffix = Felt::new(new_admin.suffix().as_canonical_u64()),
    )
}

fn accept_admin_script() -> &'static str {
    r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.16 push.0 end
            call.role_based_access_control::accept_admin
            dropw dropw dropw dropw
        end
    "#
}

fn renounce_admin_script() -> &'static str {
    r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.16 push.0 end
            call.role_based_access_control::renounce_admin
            dropw dropw dropw dropw
        end
    "#
}

fn set_role_admin_script(role: &RoleSymbol, admin_role: Option<&RoleSymbol>) -> String {
    let admin_role = admin_role.map(Felt::from).unwrap_or(Felt::ZERO);
    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.14 push.0 end
            push.{admin_role}
            push.{role}
            call.role_based_access_control::set_role_admin
            dropw dropw dropw dropw
        end
        "#,
        admin_role = admin_role,
        role = Felt::from(role),
    )
}

fn grant_role_script(role: &RoleSymbol, account_id: AccountId) -> String {
    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.13 push.0 end
            push.{account_prefix}
            push.{account_suffix}
            push.{role}
            call.role_based_access_control::grant_role
            dropw dropw dropw dropw
        end
        "#,
        account_prefix = account_id.prefix().as_felt(),
        account_suffix = Felt::new(account_id.suffix().as_canonical_u64()),
        role = Felt::from(role),
    )
}

fn revoke_role_script(role: &RoleSymbol, account_id: AccountId) -> String {
    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.13 push.0 end
            push.{account_prefix}
            push.{account_suffix}
            push.{role}
            call.role_based_access_control::revoke_role
            dropw dropw dropw dropw
        end
        "#,
        account_prefix = account_id.prefix().as_felt(),
        account_suffix = Felt::new(account_id.suffix().as_canonical_u64()),
        role = Felt::from(role),
    )
}

fn renounce_role_script(role: &RoleSymbol) -> String {
    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.15 push.0 end
            push.{role}
            call.role_based_access_control::renounce_role
            dropw dropw dropw dropw
        end
        "#,
        role = Felt::from(role),
    )
}

fn assert_role_member_count_script(role: &RoleSymbol, expected_count: u64) -> String {
    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.15 push.0 end
            push.{role}
            call.role_based_access_control::get_role_member_count
            eq.{expected_count} assert
            dropw dropw dropw
            drop drop drop
        end
        "#,
        role = Felt::from(role),
        expected_count = expected_count,
    )
}

fn assert_role_admin_script(role: &RoleSymbol, expected_admin_role: Option<&RoleSymbol>) -> String {
    let expected_admin_role = expected_admin_role.map(Felt::from).unwrap_or(Felt::ZERO);

    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.15 push.0 end
            push.{role}
            call.role_based_access_control::get_role_admin
            eq.{expected_admin_role} assert
            dropw dropw dropw
            drop drop drop
        end
        "#,
        role = Felt::from(role),
        expected_admin_role = expected_admin_role,
    )
}

fn assert_role_exists_script(role: &RoleSymbol, expected_exists: bool) -> String {
    let expected_exists = u8::from(expected_exists);

    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.15 push.0 end
            push.{role}
            call.role_based_access_control::role_exists
            eq.{expected_exists} assert
            dropw dropw dropw
            drop drop drop
        end
        "#,
        role = Felt::from(role),
        expected_exists = expected_exists,
    )
}

fn assert_has_role_script(
    role: &RoleSymbol,
    account_id: AccountId,
    expected_has_role: bool,
) -> String {
    let expected_has_role = u8::from(expected_has_role);

    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.13 push.0 end
            push.{account_prefix}
            push.{account_suffix}
            push.{role}
            call.role_based_access_control::has_role
            eq.{expected_has_role} assert
            dropw dropw dropw
            drop drop drop
        end
        "#,
        account_prefix = account_id.prefix().as_felt(),
        account_suffix = Felt::new(account_id.suffix().as_canonical_u64()),
        role = Felt::from(role),
        expected_has_role = expected_has_role,
    )
}

fn assert_admin_script(expected_admin: Option<AccountId>) -> String {
    let (expected_suffix, expected_prefix) = expected_admin
        .map(|account_id| {
            (Felt::new(account_id.suffix().as_canonical_u64()), account_id.prefix().as_felt())
        })
        .unwrap_or((Felt::ZERO, Felt::ZERO));

    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.16 push.0 end
            call.role_based_access_control::get_admin
            eq.{expected_suffix} assert
            eq.{expected_prefix} assert
            dropw dropw dropw
            drop drop
        end
        "#,
        expected_prefix = expected_prefix,
        expected_suffix = expected_suffix,
    )
}

fn assert_nominated_admin_script(expected_admin: Option<AccountId>) -> String {
    let (expected_suffix, expected_prefix) = expected_admin
        .map(|account_id| {
            (Felt::new(account_id.suffix().as_canonical_u64()), account_id.prefix().as_felt())
        })
        .unwrap_or((Felt::ZERO, Felt::ZERO));

    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.16 push.0 end
            call.role_based_access_control::get_nominated_admin
            eq.{expected_suffix} assert
            eq.{expected_prefix} assert
            dropw dropw dropw
            drop drop
        end
        "#,
        expected_prefix = expected_prefix,
        expected_suffix = expected_suffix,
    )
}

fn set_role_admin_raw_script(role: Felt, admin_role: Felt) -> String {
    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.14 push.0 end
            push.{admin_role}
            push.{role}
            call.role_based_access_control::set_role_admin
            dropw dropw dropw dropw
        end
        "#,
        admin_role = admin_role,
        role = role,
    )
}

fn get_role_member_script(role: &RoleSymbol, index: u64) -> String {
    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.14 push.0 end
            push.{index}
            push.{role}
            call.role_based_access_control::get_role_member
            dropw dropw dropw dropw
        end
        "#,
        index = index,
        role = Felt::from(role),
    )
}

fn get_active_role_script(index: u64) -> String {
    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.15 push.0 end
            push.{index}
            call.role_based_access_control::get_active_role
            dropw dropw dropw dropw
        end
        "#,
        index = index,
    )
}

fn assert_sender_has_role_script(role: &RoleSymbol) -> String {
    format!(
        r#"
        use miden::standards::access::role_based_access_control

        begin
            repeat.15 push.0 end
            push.{role}
            call.role_based_access_control::assert_sender_has_role
            dropw dropw dropw dropw
        end
        "#,
        role = Felt::from(role),
    )
}

// TESTS
// ================================================================================================

#[tokio::test]
async fn test_rbac_admin_transfer_accept_and_renounce() -> anyhow::Result<()> {
    let admin = test_account_id(1);
    let new_admin = test_account_id(2);
    let outsider = test_account_id(3);

    let account = create_rbac_account(RoleBasedAccessControl::new(admin))?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let transfer_note = build_note(admin, transfer_admin_script(new_admin), 101)?;
    let tx = mock_chain
        .build_tx_context(account.clone(), &[], slice::from_ref(&transfer_note))?
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_delta(executed.account_delta())?;

    let (current_admin, nominated_admin) = get_admins(&updated)?;
    assert_eq!(current_admin, Some(admin));
    assert_eq!(nominated_admin, Some(new_admin));

    let wrong_accept_note = build_note(outsider, accept_admin_script(), 102)?;
    let tx = mock_chain
        .build_tx_context(updated.clone(), &[], slice::from_ref(&wrong_accept_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_NOMINATED_ADMIN);

    let accept_note = build_note(new_admin, accept_admin_script(), 103)?;
    let tx = mock_chain
        .build_tx_context(updated.clone(), &[], slice::from_ref(&accept_note))?
        .build()?;
    let executed = tx.execute().await?;

    let mut accepted = updated.clone();
    accepted.apply_delta(executed.account_delta())?;

    let (current_admin, nominated_admin) = get_admins(&accepted)?;
    assert_eq!(current_admin, Some(new_admin));
    assert_eq!(nominated_admin, None);

    let renounce_note = build_note(new_admin, renounce_admin_script(), 104)?;
    let tx = mock_chain
        .build_tx_context(accepted.clone(), &[], slice::from_ref(&renounce_note))?
        .build()?;
    let executed = tx.execute().await?;

    let mut renounced = accepted.clone();
    renounced.apply_delta(executed.account_delta())?;

    let (current_admin, nominated_admin) = get_admins(&renounced)?;
    assert_eq!(current_admin, None);
    assert_eq!(nominated_admin, None);

    Ok(())
}

#[tokio::test]
async fn test_rbac_root_admin_role_management_and_lookup() -> anyhow::Result<()> {
    let admin = test_account_id(11);
    let member = test_account_id(12);
    let minter = role("MINTER");
    let minter_admin = role("MINTER_ADMIN");

    let account = create_rbac_account(RoleBasedAccessControl::new(admin))?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let set_role_admin_note =
        build_note(admin, set_role_admin_script(&minter, Some(&minter_admin)), 201)?;
    let tx = mock_chain
        .build_tx_context(account.clone(), &[], slice::from_ref(&set_role_admin_note))?
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_delta(executed.account_delta())?;

    let minter_config = get_role_config(&updated, &minter)?;
    let minter_admin_config = get_role_config(&updated, &minter_admin)?;
    assert_eq!(minter_config[0], Felt::ZERO);
    assert_eq!(minter_config[1], Felt::from(&minter_admin));
    assert_eq!(minter_config[2], Felt::ZERO);
    assert_eq!(minter_config[3], Felt::new(1));
    assert_eq!(minter_admin_config[3], Felt::new(1));
    assert_eq!(get_active_role_count(&updated)?, 0);

    let grant_role_note = build_note(admin, grant_role_script(&minter, member), 202)?;
    let tx = mock_chain
        .build_tx_context(updated.clone(), &[], slice::from_ref(&grant_role_note))?
        .build()?;
    let executed = tx.execute().await?;

    let mut granted = updated.clone();
    granted.apply_delta(executed.account_delta())?;

    let minter_config = get_role_config(&granted, &minter)?;
    assert_eq!(minter_config[0], Felt::new(1));
    assert_eq!(minter_config[2], Felt::new(1));
    assert_eq!(get_active_role_count(&granted)?, 1);
    assert_eq!(get_active_role(&granted, 0)?, minter);
    assert_eq!(get_role_member(&granted, &minter, 0)?, member);
    assert_eq!(get_role_member_index(&granted, &minter, member)?, 1);

    let revoke_role_note = build_note(admin, revoke_role_script(&minter, member), 203)?;
    let tx = mock_chain
        .build_tx_context(granted.clone(), &[], slice::from_ref(&revoke_role_note))?
        .build()?;
    let executed = tx.execute().await?;

    let mut revoked = granted.clone();
    revoked.apply_delta(executed.account_delta())?;

    let minter_config = get_role_config(&revoked, &minter)?;
    assert_eq!(minter_config[0], Felt::ZERO);
    assert_eq!(minter_config[2], Felt::ZERO);
    assert_eq!(minter_config[3], Felt::new(1));
    assert_eq!(get_active_role_count(&revoked)?, 0);
    assert_eq!(get_role_member_index(&revoked, &minter, member)?, 0);

    Ok(())
}

#[tokio::test]
async fn test_rbac_delegated_admin_and_swap_remove() -> anyhow::Result<()> {
    let admin = test_account_id(21);
    let delegate = test_account_id(22);
    let alice = test_account_id(23);
    let bob = test_account_id(24);
    let burner_holder = test_account_id(25);

    let minter = role("MINTER");
    let minter_admin = role("MINTER_ADMIN");
    let burner = role("BURNER");

    let account = create_rbac_account(RoleBasedAccessControl::new(admin))?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let set_role_admin_note =
        build_note(admin, set_role_admin_script(&minter, Some(&minter_admin)), 304)?;
    let tx = mock_chain
        .build_tx_context(account.clone(), &[], slice::from_ref(&set_role_admin_note))?
        .build()?;
    let executed = tx.execute().await.context("set_role_admin for MINTER failed")?;
    let mut updated = account.clone();
    updated.apply_delta(executed.account_delta())?;

    let delegate_grant_note = build_note(admin, grant_role_script(&minter_admin, delegate), 305)?;
    let tx = mock_chain
        .build_tx_context(updated.clone(), &[], slice::from_ref(&delegate_grant_note))?
        .build()?;
    let executed = tx.execute().await.context("grant MINTER_ADMIN to delegate failed")?;
    updated.apply_delta(executed.account_delta())?;

    assert_eq!(get_role_member_index(&updated, &minter_admin, delegate)?, 1);

    let delegated_role_check_note =
        build_note(delegate, assert_sender_has_role_script(&minter_admin), 307)?;
    let tx = mock_chain
        .build_tx_context(updated.clone(), &[], slice::from_ref(&delegated_role_check_note))?
        .build()?;
    tx.execute()
        .await
        .context("delegate assert_sender_has_role for MINTER_ADMIN failed")?;

    assert_eq!(get_role_config(&updated, &minter)?[1], Felt::from(&minter_admin));

    for (seed, target) in [(308, alice), (309, bob)] {
        let note = build_note(delegate, grant_role_script(&minter, target), seed)?;
        let tx = mock_chain
            .build_tx_context(updated.clone(), &[], slice::from_ref(&note))?
            .build()?;
        let executed = tx
            .execute()
            .await
            .with_context(|| format!("delegate grant MINTER failed for target {}", target))?;
        updated.apply_delta(executed.account_delta())?;
        if seed == 308 {
            assert_eq!(get_role_config(&updated, &minter)?[1], Felt::from(&minter_admin));
            assert_eq!(get_role_member_index(&updated, &minter_admin, delegate)?, 1);
        }
    }

    let burner_grant_note = build_note(admin, grant_role_script(&burner, burner_holder), 310)?;
    let tx = mock_chain
        .build_tx_context(updated.clone(), &[], slice::from_ref(&burner_grant_note))?
        .build()?;
    let executed = tx.execute().await.context("grant BURNER failed")?;
    updated.apply_delta(executed.account_delta())?;

    assert_eq!(get_active_role_count(&updated)?, 3);
    assert_eq!(get_active_role(&updated, 0)?, minter_admin);
    assert_eq!(get_active_role(&updated, 1)?, minter);
    assert_eq!(get_active_role(&updated, 2)?, burner);
    assert_eq!(get_role_member(&updated, &minter, 0)?, alice);
    assert_eq!(get_role_member(&updated, &minter, 1)?, bob);

    let revoke_alice_note = build_note(delegate, revoke_role_script(&minter, alice), 311)?;
    let tx = mock_chain
        .build_tx_context(updated.clone(), &[], slice::from_ref(&revoke_alice_note))?
        .build()?;
    let executed = tx.execute().await.context("delegate revoke MINTER from alice failed")?;
    updated.apply_delta(executed.account_delta())?;

    assert_eq!(get_role_member(&updated, &minter, 0)?, bob);
    assert_eq!(get_role_member_index(&updated, &minter, alice)?, 0);
    assert_eq!(get_role_member_index(&updated, &minter, bob)?, 1);

    let revoke_bob_note = build_note(delegate, revoke_role_script(&minter, bob), 312)?;
    let tx = mock_chain
        .build_tx_context(updated.clone(), &[], slice::from_ref(&revoke_bob_note))?
        .build()?;
    let executed = tx.execute().await.context("delegate revoke MINTER from bob failed")?;
    updated.apply_delta(executed.account_delta())?;

    assert_eq!(get_active_role_count(&updated)?, 2);
    assert_eq!(get_active_role(&updated, 0)?, minter_admin);
    assert_eq!(get_active_role(&updated, 1)?, burner);
    assert_eq!(get_role_config(&updated, &minter)?[0], Felt::ZERO);
    assert_eq!(get_role_config(&updated, &burner)?[0], Felt::new(1));

    Ok(())
}

#[tokio::test]
async fn test_rbac_renounce_role_and_permission_checks() -> anyhow::Result<()> {
    let admin = test_account_id(31);
    let member = test_account_id(32);
    let outsider = test_account_id(33);
    let pauser = role("PAUSER");

    let account = create_rbac_account(RoleBasedAccessControl::new(admin))?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let non_admin_grant_note = build_note(outsider, grant_role_script(&pauser, member), 401)?;
    let tx = mock_chain
        .build_tx_context(account.clone(), &[], slice::from_ref(&non_admin_grant_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ADMIN_OR_ROLE_ADMIN);

    let admin_grant_note = build_note(admin, grant_role_script(&pauser, member), 402)?;
    let tx = mock_chain
        .build_tx_context(account.clone(), &[], slice::from_ref(&admin_grant_note))?
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_delta(executed.account_delta())?;
    assert_eq!(get_active_role_count(&updated)?, 1);

    let renounce_note = build_note(member, renounce_role_script(&pauser), 403)?;
    let tx = mock_chain
        .build_tx_context(updated.clone(), &[], slice::from_ref(&renounce_note))?
        .build()?;
    let executed = tx.execute().await?;

    let mut renounced = updated.clone();
    renounced.apply_delta(executed.account_delta())?;
    assert_eq!(get_active_role_count(&renounced)?, 0);
    assert_eq!(get_role_member_index(&renounced, &pauser, member)?, 0);

    let bad_revoke_note = build_note(admin, revoke_role_script(&pauser, member), 404)?;
    let tx = mock_chain
        .build_tx_context(renounced.clone(), &[], slice::from_ref(&bad_revoke_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_NOT_IN_ROLE);

    let bad_transfer_note = build_note(outsider, transfer_admin_script(member), 405)?;
    let tx = mock_chain
        .build_tx_context(renounced, &[], slice::from_ref(&bad_transfer_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ADMIN);

    Ok(())
}

#[tokio::test]
async fn test_rbac_grant_role_appends_member_and_sets_reverse_index() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let member = test_account_id(42);
    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_note = build_note(admin, grant_role_script(&minter, member), 601)?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    assert_eq!(get_role_member(&granted, &minter, 0)?, member);
    assert_eq!(get_role_member_index(&granted, &minter, member)?, 1);

    Ok(())
}

#[tokio::test]
async fn test_rbac_first_member_activates_role() -> anyhow::Result<()> {
    let admin = test_account_id(43);
    let member = test_account_id(44);
    let burner = role("BURNER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_note = build_note(admin, grant_role_script(&burner, member), 602)?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let burner_config = get_role_config(&granted, &burner)?;
    assert_eq!(burner_config[0], Felt::new(1));
    assert_eq!(burner_config[2], Felt::new(1));
    assert_eq!(get_active_role_count(&granted)?, 1);
    assert_eq!(get_active_role(&granted, 0)?, burner);

    Ok(())
}

#[tokio::test]
async fn test_rbac_additional_members_do_not_duplicate_active_role() -> anyhow::Result<()> {
    let admin = test_account_id(45);
    let alice = test_account_id(46);
    let bob = test_account_id(47);
    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let first_grant = build_note(admin, grant_role_script(&pauser, alice), 603)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &first_grant).await?;

    let second_grant = build_note(admin, grant_role_script(&pauser, bob), 604)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &second_grant).await?;

    let pauser_config = get_role_config(&updated, &pauser)?;
    assert_eq!(pauser_config[0], Felt::new(2));
    assert_eq!(get_active_role_count(&updated)?, 1);
    assert_eq!(get_active_role(&updated, 0)?, pauser);

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_role_member_count_returns_zero_for_missing_role() -> anyhow::Result<()> {
    let admin = test_account_id(48);
    let missing_role = role("MISSING");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let query_note = build_note(admin, assert_role_member_count_script(&missing_role, 0), 605)?;
    let _ = execute_note_and_apply(&mock_chain, &account, &query_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_role_admin_returns_zero_when_unset() -> anyhow::Result<()> {
    let admin = test_account_id(49);
    let root_managed_role = role("ROOT_MANAGED");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let query_note = build_note(admin, assert_role_admin_script(&root_managed_role, None), 606)?;
    let _ = execute_note_and_apply(&mock_chain, &account, &query_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_role_member_out_of_bounds_fails() -> anyhow::Result<()> {
    let admin = test_account_id(50);
    let member = test_account_id(51);
    let user = role("USER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_note = build_note(admin, grant_role_script(&user, member), 607)?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let query_note = build_note(admin, get_role_member_script(&user, 1), 608)?;
    let tx = mock_chain
        .build_tx_context(granted, &[], slice::from_ref(&query_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ROLE_MEMBER_OUT_OF_BOUNDS);

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_active_role_out_of_bounds_fails() -> anyhow::Result<()> {
    let admin = test_account_id(52);
    let member = test_account_id(53);
    let manager = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_note = build_note(admin, grant_role_script(&manager, member), 609)?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let query_note = build_note(admin, get_active_role_script(1), 610)?;
    let tx = mock_chain
        .build_tx_context(granted, &[], slice::from_ref(&query_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ACTIVE_ROLE_OUT_OF_BOUNDS);

    Ok(())
}

#[tokio::test]
async fn test_rbac_non_admin_cannot_revoke_role() -> anyhow::Result<()> {
    let admin = test_account_id(54);
    let outsider = test_account_id(55);
    let member = test_account_id(56);
    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_note = build_note(admin, grant_role_script(&minter, member), 611)?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let revoke_note = build_note(outsider, revoke_role_script(&minter, member), 612)?;
    let tx = mock_chain
        .build_tx_context(granted, &[], slice::from_ref(&revoke_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ADMIN_OR_ROLE_ADMIN);

    Ok(())
}

#[tokio::test]
async fn test_rbac_non_member_cannot_renounce_role() -> anyhow::Result<()> {
    let admin = test_account_id(57);
    let outsider = test_account_id(58);
    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let renounce_note = build_note(outsider, renounce_role_script(&pauser), 613)?;
    let tx = mock_chain
        .build_tx_context(account, &[], slice::from_ref(&renounce_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_NOT_IN_ROLE);

    Ok(())
}

#[tokio::test]
async fn test_rbac_revoke_role_clears_removed_account_reverse_index() -> anyhow::Result<()> {
    let admin = test_account_id(59);
    let member = test_account_id(60);
    let burner = role("BURNER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_note = build_note(admin, grant_role_script(&burner, member), 614)?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let revoke_note = build_note(admin, revoke_role_script(&burner, member), 615)?;
    let revoked = execute_note_and_apply(&mock_chain, &granted, &revoke_note).await?;

    assert_eq!(get_role_member_index(&revoked, &burner, member)?, 0);

    Ok(())
}

#[tokio::test]
async fn test_rbac_revoke_non_last_member_moves_last_member_into_removed_index()
-> anyhow::Result<()> {
    let admin = test_account_id(61);
    let alice = test_account_id(62);
    let bob = test_account_id(63);
    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_alice = build_note(admin, grant_role_script(&minter, alice), 616)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_alice).await?;

    let grant_bob = build_note(admin, grant_role_script(&minter, bob), 617)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_bob).await?;

    let revoke_alice = build_note(admin, revoke_role_script(&minter, alice), 618)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_alice).await?;

    assert_eq!(get_role_member(&updated, &minter, 0)?, bob);
    assert_eq!(get_role_member_index(&updated, &minter, alice)?, 0);
    assert_eq!(get_role_member_index(&updated, &minter, bob)?, 1);

    Ok(())
}

#[tokio::test]
async fn test_rbac_revoke_last_member_keeps_remaining_enumeration_consistent() -> anyhow::Result<()>
{
    let admin = test_account_id(64);
    let alice = test_account_id(65);
    let bob = test_account_id(66);
    let burner = role("BURNER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_alice = build_note(admin, grant_role_script(&burner, alice), 619)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_alice).await?;

    let grant_bob = build_note(admin, grant_role_script(&burner, bob), 620)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_bob).await?;

    let revoke_bob = build_note(admin, revoke_role_script(&burner, bob), 621)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_bob).await?;

    let burner_config = get_role_config(&updated, &burner)?;
    assert_eq!(burner_config[0], Felt::new(1));
    assert_eq!(get_role_member(&updated, &burner, 0)?, alice);
    assert_eq!(get_role_member_index(&updated, &burner, alice)?, 1);

    Ok(())
}

#[tokio::test]
async fn test_rbac_revoke_last_role_member_deactivates_role() -> anyhow::Result<()> {
    let admin = test_account_id(67);
    let member = test_account_id(68);
    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_note = build_note(admin, grant_role_script(&pauser, member), 622)?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let revoke_note = build_note(admin, revoke_role_script(&pauser, member), 623)?;
    let revoked = execute_note_and_apply(&mock_chain, &granted, &revoke_note).await?;

    let pauser_config = get_role_config(&revoked, &pauser)?;
    assert_eq!(pauser_config[0], Felt::ZERO);
    assert_eq!(pauser_config[2], Felt::ZERO);
    assert_eq!(get_active_role_count(&revoked)?, 0);

    Ok(())
}

#[tokio::test]
async fn test_rbac_regrant_role_reactivates_role_after_becoming_empty() -> anyhow::Result<()> {
    let admin = test_account_id(69);
    let member = test_account_id(70);
    let user = role("USER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_note = build_note(admin, grant_role_script(&user, member), 624)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let revoke_note = build_note(admin, revoke_role_script(&user, member), 625)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_note).await?;

    let regrant_note = build_note(admin, grant_role_script(&user, member), 626)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &regrant_note).await?;

    let user_config = get_role_config(&updated, &user)?;
    assert_eq!(user_config[0], Felt::new(1));
    assert_eq!(user_config[2], Felt::new(1));
    assert_eq!(get_active_role_count(&updated)?, 1);
    assert_eq!(get_active_role(&updated, 0)?, user);
    assert_eq!(get_role_member_index(&updated, &user, member)?, 1);

    Ok(())
}

#[tokio::test]
async fn test_rbac_active_role_slot_is_reused_after_role_deactivation() -> anyhow::Result<()> {
    let admin = test_account_id(71);
    let alice = test_account_id(72);
    let bob = test_account_id(73);
    let carol = test_account_id(74);
    let minter = role("MINTER");
    let burner = role("BURNER");
    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_minter = build_note(admin, grant_role_script(&minter, alice), 627)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_minter).await?;

    let grant_burner = build_note(admin, grant_role_script(&burner, bob), 628)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_burner).await?;

    let revoke_minter = build_note(admin, revoke_role_script(&minter, alice), 629)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_minter).await?;

    assert_eq!(get_active_role_count(&updated)?, 1);
    assert_eq!(get_active_role(&updated, 0)?, burner);
    assert_eq!(get_role_config(&updated, &burner)?[2], Felt::new(1));

    let grant_pauser = build_note(admin, grant_role_script(&pauser, carol), 630)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_pauser).await?;

    assert_eq!(get_active_role_count(&updated)?, 2);
    assert_eq!(get_active_role(&updated, 0)?, burner);
    assert_eq!(get_active_role(&updated, 1)?, pauser);
    assert_eq!(get_role_config(&updated, &pauser)?[2], Felt::new(2));

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_role_admin_returns_set_role() -> anyhow::Result<()> {
    let admin = test_account_id(75);
    let minter = role("MINTER");
    let minter_admin = role("MINTER_ADMIN");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let set_role_admin_note =
        build_note(admin, set_role_admin_script(&minter, Some(&minter_admin)), 631)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_role_admin_note).await?;

    let query_note =
        build_note(admin, assert_role_admin_script(&minter, Some(&minter_admin)), 632)?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &query_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_transfer_admin_to_self_cancels_pending_transfer() -> anyhow::Result<()> {
    let admin = test_account_id(76);
    let new_admin = test_account_id(77);

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let transfer_note = build_note(admin, transfer_admin_script(new_admin), 633)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &transfer_note).await?;

    let cancel_note = build_note(admin, transfer_admin_script(admin), 634)?;
    let cancelled = execute_note_and_apply(&mock_chain, &updated, &cancel_note).await?;

    let query_note = build_note(admin, assert_nominated_admin_script(None), 635)?;
    let _ = execute_note_and_apply(&mock_chain, &cancelled, &query_note).await?;

    let (current_admin, nominated_admin) = get_admins(&cancelled)?;
    assert_eq!(current_admin, Some(admin));
    assert_eq!(nominated_admin, None);

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_admin_returns_zero_when_admin_is_unset() -> anyhow::Result<()> {
    let admin = test_account_id(78);

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let renounce_note = build_note(admin, renounce_admin_script(), 636)?;
    let renounced = execute_note_and_apply(&mock_chain, &account, &renounce_note).await?;

    let query_note = build_note(admin, assert_admin_script(None), 637)?;
    let _ = execute_note_and_apply(&mock_chain, &renounced, &query_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_transfer_admin_fails_when_admin_is_unset() -> anyhow::Result<()> {
    let admin = test_account_id(79);
    let new_admin = test_account_id(80);

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let renounce_note = build_note(admin, renounce_admin_script(), 638)?;
    let renounced = execute_note_and_apply(&mock_chain, &account, &renounce_note).await?;

    let transfer_note = build_note(admin, transfer_admin_script(new_admin), 639)?;
    let tx = mock_chain
        .build_tx_context(renounced, &[], slice::from_ref(&transfer_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ADMIN);

    Ok(())
}

#[tokio::test]
async fn test_rbac_renounce_admin_fails_while_transfer_is_pending() -> anyhow::Result<()> {
    let admin = test_account_id(81);
    let new_admin = test_account_id(82);

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let transfer_note = build_note(admin, transfer_admin_script(new_admin), 640)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &transfer_note).await?;

    let renounce_note = build_note(admin, renounce_admin_script(), 641)?;
    let tx = mock_chain
        .build_tx_context(updated, &[], slice::from_ref(&renounce_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ADMIN_TRANSFER_IN_PROGRESS);

    Ok(())
}

#[tokio::test]
async fn test_rbac_role_admin_can_manage_role_without_root_admin() -> anyhow::Result<()> {
    let admin = test_account_id(83);
    let manager = test_account_id(84);
    let user = test_account_id(85);
    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let set_role_admin_note =
        build_note(admin, set_role_admin_script(&user_role, Some(&manager_role)), 642)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_role_admin_note).await?;

    let grant_manager_note = build_note(admin, grant_role_script(&manager_role, manager), 643)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_manager_note).await?;

    let renounce_admin_note = build_note(admin, renounce_admin_script(), 644)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &renounce_admin_note).await?;

    let grant_user_note = build_note(manager, grant_role_script(&user_role, user), 645)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_user_note).await?;
    assert_eq!(get_role_member_index(&updated, &user_role, user)?, 1);

    let revoke_user_note = build_note(manager, revoke_role_script(&user_role, user), 646)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_user_note).await?;
    assert_eq!(get_role_member_index(&updated, &user_role, user)?, 0);

    Ok(())
}

#[tokio::test]
async fn test_rbac_role_exists_and_has_role_queries() -> anyhow::Result<()> {
    let admin = test_account_id(86);
    let member = test_account_id(87);
    let outsider = test_account_id(88);
    let user_role = role("USER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let role_missing_note = build_note(admin, assert_role_exists_script(&user_role, false), 647)?;
    let _ = execute_note_and_apply(&mock_chain, &account, &role_missing_note).await?;

    let non_member_note =
        build_note(admin, assert_has_role_script(&user_role, member, false), 648)?;
    let _ = execute_note_and_apply(&mock_chain, &account, &non_member_note).await?;

    let grant_note = build_note(admin, grant_role_script(&user_role, member), 649)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let role_exists_note = build_note(admin, assert_role_exists_script(&user_role, true), 650)?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &role_exists_note).await?;

    let member_note = build_note(admin, assert_has_role_script(&user_role, member, true), 651)?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &member_note).await?;

    let outsider_note =
        build_note(admin, assert_has_role_script(&user_role, outsider, false), 652)?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &outsider_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_non_admin_cannot_set_role_admin() -> anyhow::Result<()> {
    let admin = test_account_id(89);
    let outsider = test_account_id(90);
    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let note = build_note(outsider, set_role_admin_script(&user_role, Some(&manager_role)), 653)?;
    let tx = mock_chain.build_tx_context(account, &[], slice::from_ref(&note))?.build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ADMIN);

    Ok(())
}

#[tokio::test]
async fn test_rbac_set_role_admin_can_clear_delegated_admin_to_root_admin() -> anyhow::Result<()> {
    let admin = test_account_id(91);
    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let set_admin_note =
        build_note(admin, set_role_admin_script(&user_role, Some(&manager_role)), 654)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_admin_note).await?;

    let clear_admin_note = build_note(admin, set_role_admin_script(&user_role, None), 655)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &clear_admin_note).await?;

    let query_note = build_note(admin, assert_role_admin_script(&user_role, None), 656)?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &query_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_set_role_admin_rejects_zero_role_symbol() -> anyhow::Result<()> {
    let admin = test_account_id(92);
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let note =
        build_note(admin, set_role_admin_raw_script(Felt::ZERO, Felt::from(&manager_role)), 657)?;
    let tx = mock_chain.build_tx_context(account, &[], slice::from_ref(&note))?.build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ROLE_SYMBOL_ZERO);

    Ok(())
}

#[tokio::test]
async fn test_rbac_set_role_admin_creates_missing_role_configs_without_activating_roles()
-> anyhow::Result<()> {
    let admin = test_account_id(93);
    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let note = build_note(admin, set_role_admin_script(&user_role, Some(&manager_role)), 658)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &note).await?;

    assert_eq!(get_active_role_count(&updated)?, 0);
    assert_eq!(get_role_config(&updated, &user_role)?[3], Felt::new(1));
    assert_eq!(get_role_config(&updated, &manager_role)?[3], Felt::new(1));
    assert_eq!(get_role_config(&updated, &user_role)?[0], Felt::ZERO);
    assert_eq!(get_role_config(&updated, &manager_role)?[0], Felt::ZERO);

    Ok(())
}

#[tokio::test]
async fn test_rbac_accept_admin_clears_nominated_admin() -> anyhow::Result<()> {
    let admin = test_account_id(94);
    let new_admin = test_account_id(95);

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let transfer_note = build_note(admin, transfer_admin_script(new_admin), 659)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &transfer_note).await?;

    let accept_note = build_note(new_admin, accept_admin_script(), 660)?;
    let accepted = execute_note_and_apply(&mock_chain, &updated, &accept_note).await?;

    let query_note = build_note(new_admin, assert_nominated_admin_script(None), 661)?;
    let _ = execute_note_and_apply(&mock_chain, &accepted, &query_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_granting_admin_role_does_not_change_target_role_admin_config()
-> anyhow::Result<()> {
    let admin = test_account_id(96);
    let delegate = test_account_id(97);
    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let set_admin_note =
        build_note(admin, set_role_admin_script(&user_role, Some(&manager_role)), 662)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_admin_note).await?;
    assert_eq!(get_role_config(&updated, &user_role)?[1], Felt::from(&manager_role));

    let grant_manager_note = build_note(admin, grant_role_script(&manager_role, delegate), 663)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_manager_note).await?;

    let user_role_config = get_role_config(&updated, &user_role)?;
    assert_eq!(user_role_config[1], Felt::from(&manager_role));
    assert_eq!(user_role_config[0], Felt::ZERO);

    Ok(())
}

#[tokio::test]
async fn test_rbac_revoke_non_last_active_role_moves_last_active_role_into_freed_slot()
-> anyhow::Result<()> {
    let admin = test_account_id(98);
    let alice = test_account_id(99);
    let bob = test_account_id(100);
    let carol = test_account_id(101);
    let minter = role("MINTER");
    let burner = role("BURNER");
    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_minter = build_note(admin, grant_role_script(&minter, alice), 664)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_minter).await?;

    let grant_burner = build_note(admin, grant_role_script(&burner, bob), 665)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_burner).await?;

    let grant_pauser = build_note(admin, grant_role_script(&pauser, carol), 666)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_pauser).await?;

    assert_eq!(get_active_role(&updated, 0)?, minter);
    assert_eq!(get_active_role(&updated, 1)?, burner);
    assert_eq!(get_active_role(&updated, 2)?, pauser);

    let revoke_burner = build_note(admin, revoke_role_script(&burner, bob), 667)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_burner).await?;

    assert_eq!(get_active_role_count(&updated)?, 2);
    assert_eq!(get_active_role(&updated, 0)?, minter);
    assert_eq!(get_active_role(&updated, 1)?, pauser);
    assert_eq!(get_role_config(&updated, &pauser)?[2], Felt::new(2));
    assert_eq!(get_role_config(&updated, &burner)?[2], Felt::ZERO);

    Ok(())
}
