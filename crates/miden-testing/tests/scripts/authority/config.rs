extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountProcedureRoot,
    AccountType,
    RoleSymbol,
};
use miden_protocol::errors::protocol::ERR_NOTE_TOO_MANY_STORAGE_ITEMS;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS};
use miden_standards::account::access::{AccessControl, Authority};
use miden_standards::errors::standards::{
    ERR_AUTHORITY_CONFIG_NOTE_IS_NOT_PUBLIC,
    ERR_AUTHORITY_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_AUTHORITY_CONFIG_UNKNOWN_VARIANT,
    ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT,
    ERR_PROCEDURE_ROLES_REQUIRE_RBAC,
    ERR_SENDER_LACKS_ROLE,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::note::config::{AuthorityConfig, AuthorityConfigNote};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use crate::into_private_note;

// HELPERS
// ================================================================================================

/// Builds an account whose `Authority` is gated by `owner` via `Authority::OwnerControlled`
/// (installed by `AccessControl::Ownable2Step`).
fn create_owner_controlled_account(owner: AccountId) -> anyhow::Result<Account> {
    let account = AccountBuilder::new([44; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_components(AccessControl::Ownable2Step { owner })
        .build_existing()?;
    Ok(account)
}

/// Builds an account whose `Authority` is `RbacControlled`, with `admin` seeded as the initial
/// `ADMIN` role member and no procedure roles mapped.
fn create_rbac_controlled_account(admin: AccountId) -> anyhow::Result<Account> {
    let account = AccountBuilder::new([45; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_components(AccessControl::Rbac { admin, procedure_roles: BTreeMap::new() })
        .build_existing()?;
    Ok(account)
}

fn is_frozen(account: &Account) -> anyhow::Result<bool> {
    Ok(Authority::try_read_frozen(account.storage())?)
}

/// Returns the role mapped to `procedure_root` in the account's procedure-roles map.
fn procedure_role(
    account: &Account,
    procedure_root: &AccountProcedureRoot,
) -> anyhow::Result<Option<RoleSymbol>> {
    match Authority::try_from_storage(account.storage())? {
        Authority::RbacControlled { procedure_roles } => {
            Ok(procedure_roles.get(procedure_root).cloned())
        },
        other => anyhow::bail!("expected an RBAC-controlled authority, got {other:?}"),
    }
}

/// Builds an [`AuthorityConfigNote`] for `config` sent by `sender` and targeting `account`.
fn authority_config_note(
    sender: AccountId,
    account: AccountId,
    config: AuthorityConfig,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = AuthorityConfigNote::builder()
        .sender(sender)
        .target(account)
        .config(config)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the AuthorityConfig script with hand-crafted storage, bypassing the
/// builder so malformed inputs can be exercised.
///
/// It carries a `NetworkAccountTarget` for the consuming account, like a real config note, so
/// the note passes the script's target check and reaches the guard under test.
fn malformed_authority_config_note(
    sender: AccountId,
    target: AccountId,
    storage: Vec<Felt>,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(AuthorityConfigNote::script())
        .note_storage(storage)?
        .attachment(NetworkAccountTarget::new(target, NoteExecutionHint::Always)?)
        .build()?;
    Ok(note)
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

// TESTS
// ================================================================================================

/// The note dispatches the Freeze and Unfreeze actions: the owner freezes the account's
/// authority-gated surface, then unfreezes it.
#[tokio::test]
async fn freeze_then_unfreeze_dispatch() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_owner_controlled_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let freeze = authority_config_note(owner, account.id(), AuthorityConfig::Freeze, &mut rng)?;
    let frozen = execute_note_and_apply(&mock_chain, &account, &freeze).await?;
    assert!(is_frozen(&frozen)?);

    let unfreeze = authority_config_note(owner, frozen.id(), AuthorityConfig::Unfreeze, &mut rng)?;
    let unfrozen = execute_note_and_apply(&mock_chain, &frozen, &unfreeze).await?;
    assert!(!is_frozen(&unfrozen)?);
    Ok(())
}

/// Authorization is bound to the note sender: a non-owner's Freeze note is rejected by
/// `authority::freeze` before the frozen flag changes.
#[tokio::test]
async fn non_owner_cannot_freeze() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);
    let non_owner = AccountIdBuilder::new().build_with_seed([2; 32]);

    let account = create_owner_controlled_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let note = authority_config_note(non_owner, account.id(), AuthorityConfig::Freeze, &mut rng)?;
    let result = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);
    Ok(())
}

/// The note dispatches the SetProcedureRole action: the admin maps `freeze` to the `FREEZER`
/// role, which takes effect at once (the admin, holding only `ADMIN`, can no longer freeze), then
/// unmaps it so `freeze` falls back to `ADMIN` again.
#[tokio::test]
async fn set_procedure_role_dispatch() -> anyhow::Result<()> {
    let admin = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_rbac_controlled_account(admin)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let freeze_root = Authority::freeze_root();
    let freezer = RoleSymbol::new("FREEZER")?;

    let map = authority_config_note(
        admin,
        account.id(),
        AuthorityConfig::SetProcedureRole {
            procedure_root: freeze_root,
            role: Some(freezer.clone()),
        },
        &mut rng,
    )?;
    let mapped = execute_note_and_apply(&mock_chain, &account, &map).await?;
    assert_eq!(procedure_role(&mapped, &freeze_root)?, Some(freezer));

    // `freeze` no longer falls back to ADMIN, so the admin cannot operate it.
    let freeze = authority_config_note(admin, mapped.id(), AuthorityConfig::Freeze, &mut rng)?;
    let result = mock_chain
        .build_transaction(mapped.clone())
        .unauthenticated_input_note(freeze)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);

    let unmap = authority_config_note(
        admin,
        mapped.id(),
        AuthorityConfig::SetProcedureRole { procedure_root: freeze_root, role: None },
        &mut rng,
    )?;
    let unmapped = execute_note_and_apply(&mock_chain, &mapped, &unmap).await?;
    assert_eq!(procedure_role(&unmapped, &freeze_root)?, None);

    // Unmapped, `freeze` falls back to ADMIN again.
    let freeze = authority_config_note(admin, unmapped.id(), AuthorityConfig::Freeze, &mut rng)?;
    let frozen = execute_note_and_apply(&mock_chain, &unmapped, &freeze).await?;
    assert!(is_frozen(&frozen)?);
    Ok(())
}

/// `SetProcedureRole` requires an RBAC-controlled authority, so an owner-controlled account rejects
/// it even when the owner sends it.
#[tokio::test]
async fn set_procedure_role_requires_rbac_controlled_authority() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_owner_controlled_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let note = authority_config_note(
        owner,
        account.id(),
        AuthorityConfig::SetProcedureRole {
            procedure_root: Authority::freeze_root(),
            role: Some(RoleSymbol::new("FREEZER")?),
        },
        &mut rng,
    )?;
    let result = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PROCEDURE_ROLES_REQUIRE_RBAC);
    Ok(())
}

/// A note whose variant matches no known action is rejected by the script's dispatch guard.
#[tokio::test]
async fn unknown_variant_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_owner_controlled_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // variant 99 is not a known action
    let note =
        malformed_authority_config_note(owner, account.id(), vec![Felt::from(99u32)], &mut rng)?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_AUTHORITY_CONFIG_UNKNOWN_VARIANT);
    Ok(())
}

/// A note whose storage item count does not match its variant is rejected by the count guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_owner_controlled_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // a Freeze variant followed by a stray item instead of the single expected variant item
    let storage = vec![Felt::ZERO, Felt::ONE];
    let note = malformed_authority_config_note(owner, account.id(), storage, &mut rng)?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(
        result,
        ERR_AUTHORITY_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
    );
    Ok(())
}

/// A note carrying more storage items than any action accepts is rejected before its storage is
/// loaded, so the work an oversized note can impose on whoever attempts to consume it is bounded by
/// the longest layout the script accepts rather than by `MAX_NOTE_STORAGE_ITEMS`.
#[tokio::test]
async fn oversized_storage_is_rejected_before_the_storage_is_loaded() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_owner_controlled_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let storage = vec![Felt::from(0u32); MAX_NOTE_STORAGE_ITEMS];
    let note = malformed_authority_config_note(owner, account.id(), storage, &mut rng)?;
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_NOTE_TOO_MANY_STORAGE_ITEMS);
    Ok(())
}

/// The note is bound to its target account, so a decoy account cannot consume a note meant for
/// another account. The decoy carries the same owner-controlled `Authority`, so the sender-based
/// authorization would pass; consuming a note targeted at a different account aborts at the target
/// check before the frozen flag changes.
#[tokio::test]
async fn decoy_account_cannot_consume_note_of_another_account() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let decoy = create_owner_controlled_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(decoy.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // The note's intended target. It need not be built: the note only references its ID.
    let target = AccountId::builder().account_type(AccountType::Public).build_with_seed([9; 32]);

    let note = authority_config_note(owner, target, AuthorityConfig::Freeze, &mut rng)?;
    let result = mock_chain
        .build_transaction(decoy.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT
    );
    Ok(())
}

/// A private note carrying the same script and storage as a legitimate config note is rejected
/// before the frozen flag changes.
#[tokio::test]
async fn private_note_cannot_dispatch_the_action() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_owner_controlled_account(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let note = authority_config_note(owner, account.id(), AuthorityConfig::Freeze, &mut rng)?;
    let result = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(into_private_note(note))
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTHORITY_CONFIG_NOTE_IS_NOT_PUBLIC);
    Ok(())
}
