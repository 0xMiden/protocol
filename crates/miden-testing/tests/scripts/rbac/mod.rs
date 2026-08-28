extern crate alloc;

mod config;

use alloc::collections::BTreeMap;
use alloc::string::String;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountType,
    RoleSymbol,
    StorageMapKey,
};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{AccessControl, RoleBasedAccessControl, RoleConfig};
use miden_standards::errors::standards::{
    ERR_ACCOUNT_NOT_IN_ROLE,
    ERR_INVALID_ROLE_SYMBOL,
    ERR_ROLE_SYMBOL_ZERO,
    ERR_SENDER_NOT_ROLE_ADMIN,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use rstest::rstest;

// HELPERS
// ================================================================================================

fn create_rbac_account_with_admin(admin: AccountId) -> anyhow::Result<Account> {
    let account = AccountBuilder::new([9; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_components(AccessControl::Rbac { admin, procedure_roles: BTreeMap::new() })
        .build_existing()?;

    Ok(account)
}

// Shared with the child `config` note suite.
pub(super) fn create_rbac_chain(admin: AccountId) -> anyhow::Result<(Account, MockChain)> {
    let account = create_rbac_account_with_admin(admin)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    Ok((account, builder.build()?))
}

pub(super) fn test_account_id(seed: u8) -> AccountId {
    AccountId::builder()
        .account_type(AccountType::Private)
        .build_with_seed([seed; 32])
}

pub(super) fn role(name: &str) -> RoleSymbol {
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
pub(super) fn get_role_config(
    account: &Account,
    role: &RoleSymbol,
) -> anyhow::Result<(Felt, Felt)> {
    let word = account
        .storage()
        .get_map_item(RoleBasedAccessControl::role_config_slot(), role_config_key(role))?;
    Ok((word[0], word[1]))
}

/// Returns the number of accounts holding the role, per on-chain storage.
pub(super) fn get_role_member_count(account: &Account, role: &RoleSymbol) -> anyhow::Result<Felt> {
    Ok(get_role_config(account, role)?.0)
}

/// Returns the role's delegated admin role symbol, or `Felt::ZERO` when it is unset, per on-chain
/// storage.
pub(super) fn get_role_admin(account: &Account, role: &RoleSymbol) -> anyhow::Result<Felt> {
    Ok(get_role_config(account, role)?.1)
}

pub(crate) fn is_role_member(
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

pub(super) fn build_note(sender: AccountId, code: impl Into<String>) -> anyhow::Result<Note> {
    let seed: [u32; 4] = rand::random();
    let mut rng = RandomCoin::new(Word::from(seed));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .code(code.into())
        .build()?)
}

/// Builds a note authored by `sender` that grants `role` to `account_id` via `rbac::grant_role`.
pub(super) fn build_grant_role_note(
    sender: AccountId,
    role: &RoleSymbol,
    account_id: AccountId,
) -> anyhow::Result<Note> {
    build_note(sender, grant_role_script(role, account_id))
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

// SCRIPTS
// ================================================================================================

fn set_role_admin_script(role: &RoleSymbol, admin_role: Option<&RoleSymbol>) -> String {
    let admin_role = admin_role.map(Felt::from).unwrap_or(Felt::ZERO);
    format!(
        r#"
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.14 push.0 end
            push.{admin_role}
            push.{role}
            call.rbac::set_role_admin
            dropw dropw dropw dropw
        end
        "#,
        role = Felt::from(role),
    )
}

fn grant_role_script(role: &RoleSymbol, account_id: AccountId) -> String {
    format!(
        r#"
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.13 push.0 end
            push.{account_prefix}
            push.{account_suffix}
            push.{role}
            call.rbac::grant_role
            dropw dropw dropw dropw
        end
        "#,
        account_prefix = account_id.prefix().as_felt(),
        account_suffix = account_id.suffix(),
        role = Felt::from(role),
    )
}

fn revoke_role_script(role: &RoleSymbol, account_id: AccountId) -> String {
    format!(
        r#"
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.13 push.0 end
            push.{account_prefix}
            push.{account_suffix}
            push.{role}
            call.rbac::revoke_role
            dropw dropw dropw dropw
        end
        "#,
        account_prefix = account_id.prefix().as_felt(),
        account_suffix = account_id.suffix(),
        role = Felt::from(role),
    )
}

fn renounce_role_script(role: &RoleSymbol) -> String {
    format!(
        r#"
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.15 push.0 end
            push.{role}
            call.rbac::renounce_role
            dropw dropw dropw dropw
        end
        "#,
        role = Felt::from(role),
    )
}

fn assert_role_member_count_script(role: &RoleSymbol, expected_count: u64) -> String {
    format!(
        r#"
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.15 push.0 end
            push.{role}
            call.rbac::get_role_member_count
            eq.{expected_count} assert.err="role member count mismatch"
            dropw dropw dropw
            drop drop drop
        end
        "#,
        role = Felt::from(role),
    )
}

fn assert_role_has_members_script(role: &RoleSymbol, expected_has_members: bool) -> String {
    let expected_has_members = u8::from(expected_has_members);

    format!(
        r#"
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.15 push.0 end
            push.{role}
            call.rbac::get_role_member_count
            neq.0
            eq.{expected_has_members} assert.err="role population mismatch"
            dropw dropw dropw
            drop drop drop
        end
        "#,
        role = Felt::from(role),
    )
}

fn assert_role_admin_script(role: &RoleSymbol, expected_admin_role: Option<&RoleSymbol>) -> String {
    let expected_admin_role = expected_admin_role.map(Felt::from).unwrap_or(Felt::ZERO);

    format!(
        r#"
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.15 push.0 end
            push.{role}
            call.rbac::get_role_admin
            eq.{expected_admin_role} assert.err="role admin mismatch"
            dropw dropw dropw
            drop drop drop
        end
        "#,
        role = Felt::from(role),
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
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.13 push.0 end
            push.{account_prefix}
            push.{account_suffix}
            push.{role}
            call.rbac::has_role
            eq.{expected_has_role} assert.err="account role membership mismatch"
            dropw dropw dropw
            drop drop drop
        end
        "#,
        account_prefix = account_id.prefix().as_felt(),
        account_suffix = account_id.suffix(),
        role = Felt::from(role),
    )
}

fn set_role_admin_raw_script(role: Felt, admin_role: Felt) -> String {
    format!(
        r#"
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.14 push.0 end
            push.{admin_role}
            push.{role}
            call.rbac::set_role_admin
            dropw dropw dropw dropw
        end
        "#,
    )
}

fn grant_role_raw_script(role: Felt, account_id: AccountId) -> String {
    format!(
        r#"
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.13 push.0 end
            push.{account_prefix}
            push.{account_suffix}
            push.{role}
            call.rbac::grant_role
            dropw dropw dropw dropw
        end
        "#,
        account_prefix = account_id.prefix().as_felt(),
        account_suffix = account_id.suffix(),
    )
}

// TESTS
// ================================================================================================

/// End-to-end role management through the delegated-admin path: the `ADMIN` bootstrap member
/// delegates `MINTER` to `MINTER_ADMIN`, seeds a `MINTER_ADMIN` member, and that
/// delegate — not ADMIN — grants and revokes `MINTER`.
#[tokio::test]
async fn test_rbac_role_management_and_lookup() -> anyhow::Result<()> {
    let admin = test_account_id(11);
    let admin_member = test_account_id(13);
    let member = test_account_id(12);

    let minter = role("MINTER");
    let minter_admin = role("MINTER_ADMIN");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    // Admin (a member of ADMIN, the default admin of every role) delegates MINTER's admin.
    let set_role_admin_note =
        build_note(admin, set_role_admin_script(&minter, Some(&minter_admin)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_role_admin_note).await?;

    let (member_count, admin_role) = get_role_config(&updated, &minter)?;
    assert_eq!(member_count, Felt::from(0u32));
    assert_eq!(admin_role, Felt::from(&minter_admin));

    // MINTER_ADMIN is itself undelegated, so ADMIN seeds its first member.
    let grant_admin_note = build_note(admin, grant_role_script(&minter_admin, admin_member))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_admin_note).await?;

    // The MINTER_ADMIN member — not ADMIN — grants MINTER.
    let grant_role_note = build_note(admin_member, grant_role_script(&minter, member))?;
    let granted = execute_note_and_apply(&mock_chain, &updated, &grant_role_note).await?;

    let (member_count, admin_role) = get_role_config(&granted, &minter)?;
    assert_eq!(member_count, Felt::from(1u32));
    assert_eq!(admin_role, Felt::from(&minter_admin));
    assert!(is_role_member(&granted, &minter, member)?);

    let revoke_role_note = build_note(admin_member, revoke_role_script(&minter, member))?;
    let revoked = execute_note_and_apply(&mock_chain, &granted, &revoke_role_note).await?;

    let (member_count, admin_role) = get_role_config(&revoked, &minter)?;
    assert_eq!(member_count, Felt::from(0u32));
    assert_eq!(admin_role, Felt::from(&minter_admin));
    assert!(!is_role_member(&revoked, &minter, member)?);

    Ok(())
}

#[tokio::test]
async fn test_rbac_renounce_role_and_permission_checks() -> anyhow::Result<()> {
    let admin = test_account_id(31);
    let member = test_account_id(32);
    let outsider = test_account_id(33);

    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_pauser_to_member = grant_role_script(&pauser, member);

    let non_admin_grant_note = build_note(outsider, grant_pauser_to_member.clone())?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(non_admin_grant_note)
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ROLE_ADMIN);

    let admin_grant_note = build_note(admin, grant_pauser_to_member)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &admin_grant_note).await?;
    assert!(is_role_member(&updated, &pauser, member)?);

    let renounce_note = build_note(member, renounce_role_script(&pauser))?;
    let renounced = execute_note_and_apply(&mock_chain, &updated, &renounce_note).await?;
    assert!(!is_role_member(&renounced, &pauser, member)?);

    let bad_revoke_note = build_note(admin, revoke_role_script(&pauser, member))?;
    let tx = mock_chain
        .build_transaction(renounced)
        .unauthenticated_input_note(bad_revoke_note)
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_NOT_IN_ROLE);

    Ok(())
}

#[tokio::test]
async fn test_rbac_grant_role_sets_membership() -> anyhow::Result<()> {
    let admin = test_account_id(41);
    let member = test_account_id(42);

    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_note = build_note(admin, grant_role_script(&minter, member))?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    assert!(is_role_member(&granted, &minter, member)?);
    let member_count = get_role_member_count(&granted, &minter)?;
    assert_eq!(member_count, Felt::ONE);

    Ok(())
}

#[tokio::test]
async fn test_rbac_grant_existing_member_is_noop() -> anyhow::Result<()> {
    let admin = test_account_id(43);
    let member = test_account_id(44);

    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_minter_to_member = grant_role_script(&minter, member);

    let grant_note = build_note(admin, grant_minter_to_member.clone())?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let regrant_note = build_note(admin, grant_minter_to_member)?;
    let regranted = execute_note_and_apply(&mock_chain, &granted, &regrant_note).await?;

    let member_count = get_role_member_count(&regranted, &minter)?;
    assert_eq!(member_count, Felt::from(1u32));
    assert!(is_role_member(&regranted, &minter, member)?);

    Ok(())
}

#[tokio::test]
async fn test_rbac_member_count_tracks_grants_and_revokes() -> anyhow::Result<()> {
    let admin = test_account_id(45);
    let alice = test_account_id(46);
    let bob = test_account_id(47);

    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let first_grant = build_note(admin, grant_role_script(&pauser, alice))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &first_grant).await?;
    assert_eq!(get_role_member_count(&updated, &pauser)?, Felt::from(1u32));

    let second_grant = build_note(admin, grant_role_script(&pauser, bob))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &second_grant).await?;
    assert_eq!(get_role_member_count(&updated, &pauser)?, Felt::from(2u32));

    let revoke_alice = build_note(admin, revoke_role_script(&pauser, alice))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_alice).await?;
    assert_eq!(get_role_member_count(&updated, &pauser)?, Felt::from(1u32));
    assert!(!is_role_member(&updated, &pauser, alice)?);
    assert!(is_role_member(&updated, &pauser, bob)?);

    let revoke_bob = build_note(admin, revoke_role_script(&pauser, bob))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_bob).await?;
    assert_eq!(get_role_member_count(&updated, &pauser)?, Felt::from(0u32));
    assert!(!is_role_member(&updated, &pauser, bob)?);

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_role_member_count_returns_zero_for_missing_role() -> anyhow::Result<()> {
    let admin = test_account_id(48);

    let missing_role = role("MISSING");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let query_note = build_note(admin, assert_role_member_count_script(&missing_role, 0))?;
    let _ = execute_note_and_apply(&mock_chain, &account, &query_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_role_admin_returns_zero_when_unset() -> anyhow::Result<()> {
    let admin = test_account_id(49);

    let admin_managed_role = role("ADMIN_MGD");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let query_note = build_note(admin, assert_role_admin_script(&admin_managed_role, None))?;
    let _ = execute_note_and_apply(&mock_chain, &account, &query_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_non_admin_cannot_revoke_role() -> anyhow::Result<()> {
    let admin = test_account_id(54);
    let outsider = test_account_id(55);
    let member = test_account_id(56);

    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_note = build_note(admin, grant_role_script(&minter, member))?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let revoke_note = build_note(outsider, revoke_role_script(&minter, member))?;
    let tx = mock_chain
        .build_transaction(granted)
        .unauthenticated_input_note(revoke_note)
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ROLE_ADMIN);

    Ok(())
}

#[tokio::test]
async fn test_rbac_non_member_cannot_renounce_role() -> anyhow::Result<()> {
    let admin = test_account_id(57);
    let outsider = test_account_id(58);

    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let renounce_note = build_note(outsider, renounce_role_script(&pauser))?;
    let tx = mock_chain
        .build_transaction(account)
        .unauthenticated_input_note(renounce_note)
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_NOT_IN_ROLE);

    Ok(())
}

#[tokio::test]
async fn test_rbac_revoke_role_clears_membership() -> anyhow::Result<()> {
    let admin = test_account_id(59);
    let member = test_account_id(60);

    let burner = role("BURNER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let grant_note = build_note(admin, grant_role_script(&burner, member))?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;
    assert!(is_role_member(&granted, &burner, member)?);

    let revoke_note = build_note(admin, revoke_role_script(&burner, member))?;
    let revoked = execute_note_and_apply(&mock_chain, &granted, &revoke_note).await?;
    assert!(!is_role_member(&revoked, &burner, member)?);
    assert_eq!(get_role_member_count(&revoked, &burner)?, Felt::from(0u32));

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_role_admin_returns_set_role() -> anyhow::Result<()> {
    let admin = test_account_id(75);

    let minter = role("MINTER");
    let minter_admin = role("MINTER_ADMIN");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let set_role_admin_note =
        build_note(admin, set_role_admin_script(&minter, Some(&minter_admin)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_role_admin_note).await?;

    let query_note = build_note(admin, assert_role_admin_script(&minter, Some(&minter_admin)))?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &query_note).await?;

    Ok(())
}

/// After the sole ADMIN renounces `ADMIN`, a delegated role admin can still manage its
/// delegated role: exclusive delegation means MANAGER's authority over USER does not depend on
/// `ADMIN` existing.
#[tokio::test]
async fn test_rbac_role_admin_can_manage_role_after_admin_renounces() -> anyhow::Result<()> {
    let admin = test_account_id(83);
    let manager = test_account_id(84);
    let user = test_account_id(85);

    let admin_role = RoleBasedAccessControl::admin_role();
    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    // ADMIN delegates USER to MANAGER and seeds a MANAGER member.
    let set_role_admin_note =
        build_note(admin, set_role_admin_script(&user_role, Some(&manager_role)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_role_admin_note).await?;

    let grant_manager_note = build_note(admin, grant_role_script(&manager_role, manager))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_manager_note).await?;

    // The sole ADMIN renounces ADMIN, so ADMIN no longer has any member.
    let renounce_note = build_note(admin, renounce_role_script(&admin_role))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &renounce_note).await?;
    assert!(!is_role_member(&updated, &admin_role, admin)?);

    // MANAGER can still grant and revoke USER — its authority is not tied to ADMIN.
    let grant_user_note = build_note(manager, grant_role_script(&user_role, user))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_user_note).await?;
    assert!(is_role_member(&updated, &user_role, user)?);

    let revoke_user_note = build_note(manager, revoke_role_script(&user_role, user))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_user_note).await?;
    assert!(!is_role_member(&updated, &user_role, user)?);

    Ok(())
}

#[tokio::test]
async fn test_rbac_member_count_and_has_role_queries() -> anyhow::Result<()> {
    let admin = test_account_id(86);
    let member = test_account_id(87);
    let outsider = test_account_id(88);

    let user_role = role("USER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let role_missing_note = build_note(admin, assert_role_has_members_script(&user_role, false))?;
    let _ = execute_note_and_apply(&mock_chain, &account, &role_missing_note).await?;

    let non_member_note = build_note(admin, assert_has_role_script(&user_role, member, false))?;
    let _ = execute_note_and_apply(&mock_chain, &account, &non_member_note).await?;

    let grant_note = build_note(admin, grant_role_script(&user_role, member))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let role_populated_note = build_note(admin, assert_role_has_members_script(&user_role, true))?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &role_populated_note).await?;

    let member_note = build_note(admin, assert_has_role_script(&user_role, member, true))?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &member_note).await?;

    let outsider_note = build_note(admin, assert_has_role_script(&user_role, outsider, false))?;
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

    // USER is undelegated, so its effective admin is ADMIN. The outsider is not an ADMIN member.
    let note = build_note(outsider, set_role_admin_script(&user_role, Some(&manager_role)))?;
    let tx = mock_chain.build_transaction(account).unauthenticated_input_note(note).build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ROLE_ADMIN);

    Ok(())
}

/// On-chain a role is only ever a felt, so the entrypoints enforce the encoding the Rust
/// `RoleSymbol` accepts: without that, a role could be granted and authorized on-chain under a felt
/// that no reader can decode back into a symbol.
///
/// `27` announces a length of zero (it is the first multiple of the alphabet size), and
/// `MAX_ENCODED_VALUE + 1` runs past the longest encodable symbol; neither names a role.
#[rstest]
#[case::announces_no_characters(Felt::new(27).unwrap())]
#[case::past_the_longest_symbol(Felt::new(4052555153018976253).unwrap())]
#[tokio::test]
async fn test_rbac_grant_role_rejects_non_canonical_role_symbol(
    #[case] role_symbol: Felt,
) -> anyhow::Result<()> {
    let admin = test_account_id(130);
    let member = test_account_id(131);

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let note = build_note(admin, grant_role_raw_script(role_symbol, member))?;
    let tx = mock_chain.build_transaction(account).unauthenticated_input_note(note).build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_INVALID_ROLE_SYMBOL);

    Ok(())
}

/// The shortest and the longest encodable symbols stay grantable: the encoding check must not
/// narrow the role space the `RoleSymbol` type allows.
#[rstest]
#[case::shortest("A")]
#[case::longest("____________")]
#[tokio::test]
async fn test_rbac_grant_role_accepts_the_encoding_extremes(
    #[case] symbol: &str,
) -> anyhow::Result<()> {
    let admin = test_account_id(132);
    let member = test_account_id(133);

    let edge_role = role(symbol);
    let (account, mock_chain) = create_rbac_chain(admin)?;

    let note = build_note(admin, grant_role_script(&edge_role, member))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &note).await?;
    assert!(is_role_member(&updated, &edge_role, member)?);

    Ok(())
}

/// A delegated admin is a role like any other, so `set_role_admin` holds its symbol to the same
/// encoding. Zero stays accepted: it clears the delegation.
#[tokio::test]
async fn test_rbac_set_role_admin_rejects_non_canonical_admin_role_symbol() -> anyhow::Result<()> {
    let admin = test_account_id(134);

    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let note =
        build_note(admin, set_role_admin_raw_script(Felt::from(&minter), Felt::new(27).unwrap()))?;
    let tx = mock_chain.build_transaction(account).unauthenticated_input_note(note).build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_INVALID_ROLE_SYMBOL);

    Ok(())
}

#[tokio::test]
async fn test_rbac_set_role_admin_rejects_zero_role_symbol() -> anyhow::Result<()> {
    let admin = test_account_id(92);

    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let note = build_note(admin, set_role_admin_raw_script(Felt::ZERO, Felt::from(&manager_role)))?;
    let tx = mock_chain.build_transaction(account).unauthenticated_input_note(note).build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ROLE_SYMBOL_ZERO);

    Ok(())
}

#[tokio::test]
async fn test_rbac_set_role_admin_does_not_create_role() -> anyhow::Result<()> {
    let admin = test_account_id(93);

    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    let note = build_note(admin, set_role_admin_script(&user_role, Some(&manager_role)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &note).await?;

    let (user_count, user_admin) = get_role_config(&updated, &user_role)?;
    assert_eq!(user_count, Felt::from(0u32));
    assert_eq!(user_admin, Felt::from(&manager_role));
    let manager_count = get_role_member_count(&updated, &manager_role)?;
    assert_eq!(manager_count, Felt::from(0u32));

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

    let set_admin_note = build_note(admin, set_role_admin_script(&user_role, Some(&manager_role)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_admin_note).await?;
    assert_eq!(get_role_admin(&updated, &user_role)?, Felt::from(&manager_role));

    let grant_manager_note = build_note(admin, grant_role_script(&manager_role, delegate))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_manager_note).await?;

    let (user_count, user_admin) = get_role_config(&updated, &user_role)?;
    assert_eq!(user_admin, Felt::from(&manager_role));
    assert_eq!(user_count, Felt::from(0u32));

    Ok(())
}

/// The action that a role's delegated admin performs exclusively, out of the general `ADMIN`
/// role's reach.
enum DelegatedAdminAction {
    /// Grant the delegated role to a member (`grant_role`).
    GrantRole,
    /// Clear the delegation, reverting the role to `ADMIN` management (`set_role_admin(_, None)`).
    ClearDelegation,
}

/// Regression test: once a role is delegated to a dedicated admin role, the general `ADMIN` role
/// is locked out of it entirely — it can neither manage membership (`grant_role`) nor re-point the
/// delegation (`set_role_admin`). The role becomes exclusively controlled by its delegated admin,
/// so a sensitive capability can be kept out of reach of the general administrator.
#[rstest]
#[case::grant_role(DelegatedAdminAction::GrantRole)]
#[case::clear_delegation(DelegatedAdminAction::ClearDelegation)]
#[tokio::test]
async fn test_rbac_delegation_locks_out_admin(
    #[case] action: DelegatedAdminAction,
) -> anyhow::Result<()> {
    let admin = test_account_id(101); // seeded as the sole ADMIN member
    let delegated_admin = test_account_id(102);
    let member = test_account_id(103);

    let minter = role("MINTER");
    let mint_admin = role("MINT_ADMIN");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    // ADMIN delegates MINTER to MINT_ADMIN and seeds a MINT_ADMIN member.
    let set_admin_note = build_note(admin, set_role_admin_script(&minter, Some(&mint_admin)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_admin_note).await?;
    let grant_admin_note = build_note(admin, grant_role_script(&mint_admin, delegated_admin))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_admin_note).await?;

    // The guarded action MINTER's effective admin controls; both grant and re-delegation are
    // gated on the delegated admin, so neither is reachable by the general ADMIN role.
    let action_script = match action {
        DelegatedAdminAction::GrantRole => grant_role_script(&minter, member),
        DelegatedAdminAction::ClearDelegation => set_role_admin_script(&minter, None),
    };

    // The ADMIN member (admin) can no longer perform it — MINTER is out of ADMIN's reach.
    let admin_note = build_note(admin, action_script.clone())?;
    let result = mock_chain
        .build_transaction(updated.clone())
        .unauthenticated_input_note(admin_note)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ROLE_ADMIN);

    // Only the delegated MINT_ADMIN member can, and the action takes effect.
    let admin_note = build_note(delegated_admin, action_script)?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &admin_note).await?;
    match action {
        DelegatedAdminAction::GrantRole => assert!(is_role_member(&updated, &minter, member)?),
        DelegatedAdminAction::ClearDelegation => {
            let query_note = build_note(admin, assert_role_admin_script(&minter, None))?;
            execute_note_and_apply(&mock_chain, &updated, &query_note).await?;
        },
    }

    Ok(())
}

/// The `ADMIN` role is an ordinary self-administered role: its membership can be handed off,
/// after which the previous holder loses all administrative authority. There is no hard-wired
/// super-admin key.
#[tokio::test]
async fn test_rbac_admin_membership_can_be_handed_off() -> anyhow::Result<()> {
    let admin = test_account_id(104); // initial ADMIN member
    let new_admin = test_account_id(105);
    let member = test_account_id(106);

    let admin_role = RoleBasedAccessControl::admin_role();
    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    // Admin grants ADMIN to new_admin (ADMIN administers itself), then new_admin revokes admin.
    let grant_admin_note = build_note(admin, grant_role_script(&admin_role, new_admin))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_admin_note).await?;
    assert!(is_role_member(&updated, &admin_role, new_admin)?);

    let revoke_admin_note = build_note(new_admin, revoke_role_script(&admin_role, admin))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_admin_note).await?;
    assert!(!is_role_member(&updated, &admin_role, admin)?);

    // The former ADMIN can no longer administer roles.
    let admin_grant_note = build_note(admin, grant_role_script(&pauser, member))?;
    let result = mock_chain
        .build_transaction(updated.clone())
        .unauthenticated_input_note(admin_grant_note)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ROLE_ADMIN);

    // The new ADMIN can.
    let new_admin_grant_note = build_note(new_admin, grant_role_script(&pauser, member))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &new_admin_grant_note).await?;
    assert!(is_role_member(&updated, &pauser, member)?);

    Ok(())
}

/// The `admin` passed to `AccessControl::Rbac` is seeded as the initial member of the
/// self-administered `ADMIN` role, which bootstraps role administration.
#[tokio::test]
async fn test_rbac_admin_seeded_as_initial_member() -> anyhow::Result<()> {
    let admin = test_account_id(107);
    let admin_role = RoleBasedAccessControl::admin_role();

    let account = create_rbac_account_with_admin(admin)?;

    assert!(is_role_member(&account, &admin_role, admin)?);
    let (member_count, admin_of_admin) = get_role_config(&account, &admin_role)?;
    assert_eq!(member_count, Felt::from(1u32));
    // ADMIN administers itself: its delegated admin is left unset (0).
    assert_eq!(admin_of_admin, Felt::ZERO);

    Ok(())
}

/// `ADMIN` is renounceable through the standard API. While another admin remains the role stays
/// manageable; once the last admin renounces, `ADMIN` has no members and the roles it administers
/// can no longer be managed.
#[tokio::test]
async fn test_rbac_admin_can_renounce_admin_role() -> anyhow::Result<()> {
    let admin1 = test_account_id(120);
    let admin2 = test_account_id(121);
    let member = test_account_id(122);
    let orphan = test_account_id(123);

    let admin_role = RoleBasedAccessControl::admin_role();
    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(admin1)?;

    // admin1 grants ADMIN to admin2, so ADMIN has two members (ADMIN administers itself).
    let grant_admin2_note = build_note(admin1, grant_role_script(&admin_role, admin2))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_admin2_note).await?;
    assert!(is_role_member(&updated, &admin_role, admin2)?);

    // admin1 renounces ADMIN while admin2 remains.
    let renounce_admin1_note = build_note(admin1, renounce_role_script(&admin_role))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &renounce_admin1_note).await?;
    assert!(!is_role_member(&updated, &admin_role, admin1)?);

    // ADMIN is still manageable: the remaining admin can grant a role.
    let admin2_grant_note = build_note(admin2, grant_role_script(&pauser, member))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &admin2_grant_note).await?;
    assert!(is_role_member(&updated, &pauser, member)?);

    // The last admin renounces ADMIN, leaving it with no members.
    let renounce_admin2_note = build_note(admin2, renounce_role_script(&admin_role))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &renounce_admin2_note).await?;
    assert!(!is_role_member(&updated, &admin_role, admin2)?);
    assert_eq!(get_role_member_count(&updated, &admin_role)?, Felt::from(0u32));

    // ADMIN is now unmanageable: granting an ADMIN-administered role fails for everyone.
    let orphan_grant_note = build_note(admin2, grant_role_script(&pauser, orphan))?;
    let result = mock_chain
        .build_transaction(updated.clone())
        .unauthenticated_input_note(orphan_grant_note)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ROLE_ADMIN);

    Ok(())
}

/// The component builder seeds the `ADMIN` role plus arbitrary operator roles at construction,
/// each with its own delegated admin.
#[test]
fn test_rbac_builder_seeds_admin_and_operator_roles() -> anyhow::Result<()> {
    let admin = test_account_id(201);
    let minter = test_account_id(202);
    let burner = test_account_id(203);

    let admin_role = RoleBasedAccessControl::admin_role();
    let minter_role = role("MINTER");
    let burner_role = role("BURNER");

    let account = AccountBuilder::new([9; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(
            RoleBasedAccessControl::builder()
                .role(RoleConfig::new(admin_role.clone()).with_member(admin))
                .role(RoleConfig::new(minter_role.clone()).with_member(minter))
                .role(RoleConfig::new(burner_role.clone()).with_member(burner))
                .build()?,
        )
        .build_existing()?;

    // ADMIN is seeded and administers itself (delegated admin unset).
    assert!(is_role_member(&account, &admin_role, admin)?);
    assert_eq!(get_role_config(&account, &admin_role)?, (Felt::ONE, Felt::ZERO));

    // Operator roles are seeded with their delegated admin unset (0 -> administered by ADMIN).
    assert!(is_role_member(&account, &minter_role, minter)?);
    assert_eq!(get_role_config(&account, &minter_role)?, (Felt::ONE, Felt::ZERO));
    assert!(is_role_member(&account, &burner_role, burner)?);

    Ok(())
}

/// A role seeded with a delegated admin is administered by that role from genesis: `ADMIN` cannot
/// grant or revoke it, while the delegated admin's members can.
#[tokio::test]
async fn test_rbac_seeded_delegated_admin_excludes_admin() -> anyhow::Result<()> {
    let admin = test_account_id(211);
    let manager = test_account_id(212);
    let pauser = test_account_id(213);

    let admin_role = RoleBasedAccessControl::admin_role();
    let manager_role = role("DOM_MANAGER");
    let pauser_role = role("DOM_PAUSER");

    let account = AccountBuilder::new([11; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(
            RoleBasedAccessControl::builder()
                .role(RoleConfig::new(admin_role).with_member(admin))
                .role(
                    RoleConfig::new(manager_role.clone())
                        .with_member(manager)
                        .with_admin(manager_role.clone()),
                )
                .role(RoleConfig::new(pauser_role.clone()).with_admin(manager_role.clone()))
                .build()?,
        )
        .build_existing()?;

    // DOM_PAUSER has no members yet, but its delegated admin is already in place.
    assert_eq!(
        get_role_config(&account, &pauser_role)?,
        (Felt::ZERO, manager_role.as_element())
    );

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    // ADMIN cannot grant DOM_PAUSER: the role is out of its reach from genesis.
    let admin_grant = build_note(admin, grant_role_script(&pauser_role, pauser))?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(admin_grant)
        .build()?;
    assert_transaction_executor_error!(tx.execute().await, ERR_SENDER_NOT_ROLE_ADMIN);

    // A DOM_MANAGER member can.
    let manager_grant = build_note(manager, grant_role_script(&pauser_role, pauser))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &manager_grant).await?;
    assert!(is_role_member(&updated, &pauser_role, pauser)?);

    Ok(())
}

/// A role delegated to itself stays manageable by its own members after the sole `ADMIN`
/// renounces: `set_role_admin(MANAGER, MANAGER)` (step 2 of the decentralized-configuration
/// recipe in the component docs) keeps `MANAGER`'s membership rotatable once `ADMIN` is empty.
#[tokio::test]
async fn test_rbac_self_administered_role_survives_admin_renounce() -> anyhow::Result<()> {
    let admin = test_account_id(124);
    let manager = test_account_id(125);
    let second_manager = test_account_id(126);

    let admin_role = RoleBasedAccessControl::admin_role();
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    // Seed MANAGER, then make it self-administering.
    let grant_manager_note = build_note(admin, grant_role_script(&manager_role, manager))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_manager_note).await?;

    let self_admin_note =
        build_note(admin, set_role_admin_script(&manager_role, Some(&manager_role)))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &self_admin_note).await?;

    // The sole ADMIN renounces ADMIN.
    let renounce_note = build_note(admin, renounce_role_script(&admin_role))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &renounce_note).await?;
    assert!(!is_role_member(&updated, &admin_role, admin)?);

    // MANAGER can still rotate its own membership.
    let grant_second_note = build_note(manager, grant_role_script(&manager_role, second_manager))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_second_note).await?;
    assert!(is_role_member(&updated, &manager_role, second_manager)?);

    Ok(())
}

/// Delegating to a memberless role does not put the delegated role out of `ADMIN`'s reach: a
/// memberless role can authorize nothing, so authority falls back to `ADMIN` until the delegate
/// gains its first member, at which point it takes over exclusively.
#[tokio::test]
async fn test_rbac_admin_retains_authority_while_delegated_admin_is_memberless()
-> anyhow::Result<()> {
    let admin = test_account_id(210);
    let mint_admin_member = test_account_id(211);
    let member = test_account_id(212);
    let second_member = test_account_id(213);

    let minter = role("MINTER");
    let mint_admin = role("MINT_ADMIN");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    // MINTER is delegated to MINT_ADMIN, which has no members — an unpopulated or mistyped role.
    let set_admin_note = build_note(admin, set_role_admin_script(&minter, Some(&mint_admin)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_admin_note).await?;
    assert_eq!(get_role_member_count(&updated, &mint_admin)?, Felt::ZERO);

    // ADMIN keeps authority over MINTER while MINTER's delegated admin is memberless.
    let grant_minter_note = build_note(admin, grant_role_script(&minter, member))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_minter_note).await?;
    assert!(is_role_member(&updated, &minter, member)?);

    // Once MINT_ADMIN gains a member it administers MINTER exclusively, locking ADMIN out again.
    let grant_admin_note = build_note(admin, grant_role_script(&mint_admin, mint_admin_member))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_admin_note).await?;

    let admin_grant_note = build_note(admin, grant_role_script(&minter, second_member))?;
    let result = mock_chain
        .build_transaction(updated.clone())
        .unauthenticated_input_note(admin_grant_note)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ROLE_ADMIN);

    let delegate_grant_note =
        build_note(mint_admin_member, grant_role_script(&minter, second_member))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &delegate_grant_note).await?;
    assert!(is_role_member(&updated, &minter, second_member)?);

    Ok(())
}

/// Regression test: a delegated role does not become permanently unmanageable when its admin chain
/// empties out. Authority over the roles a memberless role administers falls back to `ADMIN`, which
/// can then manage the delegated role, re-point its delegation, and repopulate the dead admin role.
#[tokio::test]
async fn test_rbac_admin_recovers_role_from_dead_admin_chain() -> anyhow::Result<()> {
    let admin = test_account_id(214);
    let mint_admin_member = test_account_id(215);
    let member = test_account_id(216);

    let minter = role("MINTER");
    let mint_admin = role("MINT_ADMIN");

    let (account, mock_chain) = create_rbac_chain(admin)?;

    // ADMIN delegates MINTER to MINT_ADMIN and seeds MINT_ADMIN, so MINTER is exclusively
    // MINT_ADMIN's and out of ADMIN's reach.
    let set_admin_note = build_note(admin, set_role_admin_script(&minter, Some(&mint_admin)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_admin_note).await?;
    let grant_admin_note = build_note(admin, grant_role_script(&mint_admin, mint_admin_member))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_admin_note).await?;

    // MINT_ADMIN administers itself, so once it empties no live role administers it either.
    let self_admin_note = build_note(admin, set_role_admin_script(&mint_admin, Some(&mint_admin)))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &self_admin_note).await?;

    // MINT_ADMIN's last member renounces, so MINTER's effective admin is memberless.
    let renounce_note = build_note(mint_admin_member, renounce_role_script(&mint_admin))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &renounce_note).await?;
    assert_eq!(get_role_member_count(&updated, &mint_admin)?, Felt::ZERO);

    // ADMIN regains authority over MINTER: it can manage membership...
    let grant_minter_note = build_note(admin, grant_role_script(&minter, member))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_minter_note).await?;
    assert!(is_role_member(&updated, &minter, member)?);

    // ...and re-point the delegation back to itself.
    let clear_note = build_note(admin, set_role_admin_script(&minter, None))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &clear_note).await?;
    assert_eq!(get_role_admin(&updated, &minter)?, Felt::ZERO);

    // The dead admin role is recoverable too: its own effective admin is memberless, so ADMIN can
    // repopulate it.
    let regrant_note = build_note(admin, grant_role_script(&mint_admin, mint_admin_member))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &regrant_note).await?;
    assert!(is_role_member(&updated, &mint_admin, mint_admin_member)?);

    Ok(())
}
