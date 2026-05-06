extern crate alloc;

use alloc::string::String;
use core::slice;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
    RoleSymbol,
};
use miden_protocol::errors::AccountIdError;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{AccessControl, Ownable2Step, RoleBasedAccessControl};
use miden_standards::errors::standards::{
    ERR_ACCOUNT_NOT_IN_ROLE,
    ERR_ROLE_SYMBOL_ZERO,
    ERR_SENDER_NOT_OWNER,
    ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

// HELPERS
// ================================================================================================

fn create_rbac_account_with_owner(owner: AccountId) -> anyhow::Result<Account> {
    let account = AccountBuilder::new([9; 32])
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_components(AccessControl::Rbac { owner })
        .build_existing()?;

    Ok(account)
}

fn create_rbac_chain(owner: AccountId) -> anyhow::Result<(Account, MockChain)> {
    let account = create_rbac_account_with_owner(owner)?;
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

fn role_membership_key(role: &RoleSymbol, account_id: AccountId) -> Word {
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

fn get_owner(account: &Account) -> anyhow::Result<Option<AccountId>> {
    let word = account.storage().get_item(Ownable2Step::slot_name())?;
    Ok(account_id_from_felt_pair(word[0], word[1])?)
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

fn build_note(sender: AccountId, code: impl Into<String>) -> anyhow::Result<Note> {
    let seed: [u64; 4] = rand::random();
    let mut rng = RandomCoin::new(Word::from(seed.map(Felt::new)));
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

fn renounce_ownership_script() -> &'static str {
    r#"
        use miden::standards::access::ownable2step

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.ownable2step::renounce_ownership
            dropw dropw dropw dropw
        end
    "#
}

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

fn assert_sender_has_role_script(role: &RoleSymbol) -> String {
    format!(
        r#"
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.15 push.0 end
            push.{role}
            call.rbac::assert_sender_has_role
            dropw dropw dropw dropw
        end
        "#,
        role = Felt::from(role),
    )
}

// TESTS
// ================================================================================================

#[tokio::test]
async fn test_rbac_owner_role_management_and_lookup() -> anyhow::Result<()> {
    let owner = test_account_id(11);
    let member = test_account_id(12);

    let minter = role("MINTER");
    let minter_admin = role("MINTER_ADMIN");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let set_role_admin_note =
        build_note(owner, set_role_admin_script(&minter, Some(&minter_admin)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_role_admin_note).await?;

    let (member_count, admin_role) = get_role_config(&updated, &minter)?;
    assert_eq!(member_count, Felt::from(0u32));
    assert_eq!(admin_role, Felt::from(&minter_admin));

    let grant_role_note = build_note(owner, grant_role_script(&minter, member))?;
    let granted = execute_note_and_apply(&mock_chain, &updated, &grant_role_note).await?;

    let (member_count, admin_role) = get_role_config(&granted, &minter)?;
    assert_eq!(member_count, Felt::from(1u32));
    assert_eq!(admin_role, Felt::from(&minter_admin));
    assert!(is_role_member(&granted, &minter, member)?);

    let revoke_role_note = build_note(owner, revoke_role_script(&minter, member))?;
    let revoked = execute_note_and_apply(&mock_chain, &granted, &revoke_role_note).await?;

    let (member_count, admin_role) = get_role_config(&revoked, &minter)?;
    assert_eq!(member_count, Felt::from(0u32));
    assert_eq!(admin_role, Felt::from(&minter_admin));
    assert!(!is_role_member(&revoked, &minter, member)?);

    Ok(())
}

#[tokio::test]
async fn test_rbac_renounce_role_and_permission_checks() -> anyhow::Result<()> {
    let owner = test_account_id(31);
    let member = test_account_id(32);
    let outsider = test_account_id(33);

    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let grant_pauser_to_member = grant_role_script(&pauser, member);

    let non_owner_grant_note = build_note(outsider, grant_pauser_to_member.clone())?;
    let tx = mock_chain
        .build_tx_context(account.clone(), &[], slice::from_ref(&non_owner_grant_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN);

    let owner_grant_note = build_note(owner, grant_pauser_to_member)?;
    let updated = execute_note_and_apply(&mock_chain, &account, &owner_grant_note).await?;
    assert!(is_role_member(&updated, &pauser, member)?);

    let renounce_note = build_note(member, renounce_role_script(&pauser))?;
    let renounced = execute_note_and_apply(&mock_chain, &updated, &renounce_note).await?;
    assert!(!is_role_member(&renounced, &pauser, member)?);

    let bad_revoke_note = build_note(owner, revoke_role_script(&pauser, member))?;
    let tx = mock_chain
        .build_tx_context(renounced, &[], slice::from_ref(&bad_revoke_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_NOT_IN_ROLE);

    Ok(())
}

#[tokio::test]
async fn test_rbac_grant_role_sets_membership() -> anyhow::Result<()> {
    let owner = test_account_id(41);
    let member = test_account_id(42);

    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let grant_note = build_note(owner, grant_role_script(&minter, member))?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    assert!(is_role_member(&granted, &minter, member)?);
    let (member_count, _) = get_role_config(&granted, &minter)?;
    assert_eq!(member_count, Felt::ONE);

    Ok(())
}

#[tokio::test]
async fn test_rbac_grant_existing_member_is_noop() -> anyhow::Result<()> {
    let owner = test_account_id(43);
    let member = test_account_id(44);

    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let grant_minter_to_member = grant_role_script(&minter, member);

    let grant_note = build_note(owner, grant_minter_to_member.clone())?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let regrant_note = build_note(owner, grant_minter_to_member)?;
    let regranted = execute_note_and_apply(&mock_chain, &granted, &regrant_note).await?;

    // Member count must remain at 1; granting an existing member is idempotent.
    let (member_count, _) = get_role_config(&regranted, &minter)?;
    assert_eq!(member_count, Felt::from(1u32));
    assert!(is_role_member(&regranted, &minter, member)?);

    Ok(())
}

#[tokio::test]
async fn test_rbac_member_count_tracks_grants_and_revokes() -> anyhow::Result<()> {
    let owner = test_account_id(45);
    let alice = test_account_id(46);
    let bob = test_account_id(47);

    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let first_grant = build_note(owner, grant_role_script(&pauser, alice))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &first_grant).await?;
    assert_eq!(get_role_config(&updated, &pauser)?.0, Felt::from(1u32));

    let second_grant = build_note(owner, grant_role_script(&pauser, bob))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &second_grant).await?;
    assert_eq!(get_role_config(&updated, &pauser)?.0, Felt::from(2u32));

    let revoke_alice = build_note(owner, revoke_role_script(&pauser, alice))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_alice).await?;
    assert_eq!(get_role_config(&updated, &pauser)?.0, Felt::from(1u32));
    assert!(!is_role_member(&updated, &pauser, alice)?);
    assert!(is_role_member(&updated, &pauser, bob)?);

    let revoke_bob = build_note(owner, revoke_role_script(&pauser, bob))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &revoke_bob).await?;
    assert_eq!(get_role_config(&updated, &pauser)?.0, Felt::from(0u32));
    assert!(!is_role_member(&updated, &pauser, bob)?);

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_role_member_count_returns_zero_for_missing_role() -> anyhow::Result<()> {
    let owner = test_account_id(48);

    let missing_role = role("MISSING");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let query_note = build_note(owner, assert_role_member_count_script(&missing_role, 0))?;
    let _ = execute_note_and_apply(&mock_chain, &account, &query_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_role_admin_returns_zero_when_unset() -> anyhow::Result<()> {
    let owner = test_account_id(49);

    let owner_managed_role = role("OWNER_MGD");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let query_note = build_note(owner, assert_role_admin_script(&owner_managed_role, None))?;
    let _ = execute_note_and_apply(&mock_chain, &account, &query_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_non_owner_cannot_revoke_role() -> anyhow::Result<()> {
    let owner = test_account_id(54);
    let outsider = test_account_id(55);
    let member = test_account_id(56);

    let minter = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let grant_note = build_note(owner, grant_role_script(&minter, member))?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let revoke_note = build_note(outsider, revoke_role_script(&minter, member))?;
    let tx = mock_chain
        .build_tx_context(granted, &[], slice::from_ref(&revoke_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN);

    Ok(())
}

#[tokio::test]
async fn test_rbac_non_member_cannot_renounce_role() -> anyhow::Result<()> {
    let owner = test_account_id(57);
    let outsider = test_account_id(58);

    let pauser = role("PAUSER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let renounce_note = build_note(outsider, renounce_role_script(&pauser))?;
    let tx = mock_chain
        .build_tx_context(account, &[], slice::from_ref(&renounce_note))?
        .build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_NOT_IN_ROLE);

    Ok(())
}

#[tokio::test]
async fn test_rbac_revoke_role_clears_membership() -> anyhow::Result<()> {
    let owner = test_account_id(59);
    let member = test_account_id(60);

    let burner = role("BURNER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let grant_note = build_note(owner, grant_role_script(&burner, member))?;
    let granted = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;
    assert!(is_role_member(&granted, &burner, member)?);

    let revoke_note = build_note(owner, revoke_role_script(&burner, member))?;
    let revoked = execute_note_and_apply(&mock_chain, &granted, &revoke_note).await?;
    assert!(!is_role_member(&revoked, &burner, member)?);
    assert_eq!(get_role_config(&revoked, &burner)?.0, Felt::from(0u32));

    Ok(())
}

#[tokio::test]
async fn test_rbac_get_role_admin_returns_set_role() -> anyhow::Result<()> {
    let owner = test_account_id(75);

    let minter = role("MINTER");
    let minter_admin = role("MINTER_ADMIN");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let set_role_admin_note =
        build_note(owner, set_role_admin_script(&minter, Some(&minter_admin)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_role_admin_note).await?;

    let query_note = build_note(owner, assert_role_admin_script(&minter, Some(&minter_admin)))?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &query_note).await?;

    Ok(())
}

/// After the owner renounces, role admins should still be able to manage their delegated
/// roles.
#[tokio::test]
async fn test_rbac_role_admin_can_manage_role_after_owner_renounces() -> anyhow::Result<()> {
    let owner = test_account_id(83);
    let manager = test_account_id(84);
    let user = test_account_id(85);

    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let set_role_admin_note =
        build_note(owner, set_role_admin_script(&user_role, Some(&manager_role)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_role_admin_note).await?;

    let grant_manager_note = build_note(owner, grant_role_script(&manager_role, manager))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_manager_note).await?;

    let renounce_note = build_note(owner, renounce_ownership_script())?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &renounce_note).await?;

    assert_eq!(get_owner(&updated)?, None);

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
    let owner = test_account_id(86);
    let member = test_account_id(87);
    let outsider = test_account_id(88);

    let user_role = role("USER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let role_missing_note = build_note(owner, assert_role_has_members_script(&user_role, false))?;
    let _ = execute_note_and_apply(&mock_chain, &account, &role_missing_note).await?;

    let non_member_note = build_note(owner, assert_has_role_script(&user_role, member, false))?;
    let _ = execute_note_and_apply(&mock_chain, &account, &non_member_note).await?;

    let grant_note = build_note(owner, grant_role_script(&user_role, member))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    let role_populated_note = build_note(owner, assert_role_has_members_script(&user_role, true))?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &role_populated_note).await?;

    let member_note = build_note(owner, assert_has_role_script(&user_role, member, true))?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &member_note).await?;

    let outsider_note = build_note(owner, assert_has_role_script(&user_role, outsider, false))?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &outsider_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_assert_sender_has_role() -> anyhow::Result<()> {
    let owner = test_account_id(120);
    let minter = test_account_id(121);
    let outsider = test_account_id(122);

    let minter_role = role("MINTER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let grant_note = build_note(owner, grant_role_script(&minter_role, minter))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &grant_note).await?;

    // Member can pass the assertion.
    let member_check = build_note(minter, assert_sender_has_role_script(&minter_role))?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &member_check).await?;

    // Outsider cannot.
    let outsider_check = build_note(outsider, assert_sender_has_role_script(&minter_role))?;
    let tx = mock_chain
        .build_tx_context(updated, &[], slice::from_ref(&outsider_check))?
        .build()?;
    let result = tx.execute().await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_rbac_non_owner_cannot_set_role_admin() -> anyhow::Result<()> {
    let owner = test_account_id(89);
    let outsider = test_account_id(90);

    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let note = build_note(outsider, set_role_admin_script(&user_role, Some(&manager_role)))?;
    let tx = mock_chain.build_tx_context(account, &[], slice::from_ref(&note))?.build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

#[tokio::test]
async fn test_rbac_set_role_admin_can_clear_delegated_admin_to_owner() -> anyhow::Result<()> {
    let owner = test_account_id(91);

    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let set_admin_note = build_note(owner, set_role_admin_script(&user_role, Some(&manager_role)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_admin_note).await?;

    let clear_admin_note = build_note(owner, set_role_admin_script(&user_role, None))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &clear_admin_note).await?;

    let query_note = build_note(owner, assert_role_admin_script(&user_role, None))?;
    let _ = execute_note_and_apply(&mock_chain, &updated, &query_note).await?;

    Ok(())
}

#[tokio::test]
async fn test_rbac_set_role_admin_rejects_zero_role_symbol() -> anyhow::Result<()> {
    let owner = test_account_id(92);

    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let note = build_note(owner, set_role_admin_raw_script(Felt::ZERO, Felt::from(&manager_role)))?;
    let tx = mock_chain.build_tx_context(account, &[], slice::from_ref(&note))?.build()?;
    let result = tx.execute().await;
    assert_transaction_executor_error!(result, ERR_ROLE_SYMBOL_ZERO);

    Ok(())
}

#[tokio::test]
async fn test_rbac_set_role_admin_does_not_create_role() -> anyhow::Result<()> {
    let owner = test_account_id(93);

    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let note = build_note(owner, set_role_admin_script(&user_role, Some(&manager_role)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &note).await?;

    let (user_count, user_admin) = get_role_config(&updated, &user_role)?;
    assert_eq!(user_count, Felt::from(0u32));
    assert_eq!(user_admin, Felt::from(&manager_role));
    let (manager_count, _) = get_role_config(&updated, &manager_role)?;
    assert_eq!(manager_count, Felt::from(0u32));

    Ok(())
}

#[tokio::test]
async fn test_rbac_granting_admin_role_does_not_change_target_role_admin_config()
-> anyhow::Result<()> {
    let owner = test_account_id(96);
    let delegate = test_account_id(97);

    let user_role = role("USER");
    let manager_role = role("MANAGER");

    let (account, mock_chain) = create_rbac_chain(owner)?;

    let set_admin_note = build_note(owner, set_role_admin_script(&user_role, Some(&manager_role)))?;
    let updated = execute_note_and_apply(&mock_chain, &account, &set_admin_note).await?;
    assert_eq!(get_role_config(&updated, &user_role)?.1, Felt::from(&manager_role));

    let grant_manager_note = build_note(owner, grant_role_script(&manager_role, delegate))?;
    let updated = execute_note_and_apply(&mock_chain, &updated, &grant_manager_note).await?;

    let (user_count, user_admin) = get_role_config(&updated, &user_role)?;
    assert_eq!(user_admin, Felt::from(&manager_role));
    assert_eq!(user_count, Felt::from(0u32));

    Ok(())
}
