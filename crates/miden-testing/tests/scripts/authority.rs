//! Tests for the `Authority` global emergency switch (`target_closed`).
//!
//! When the owner calls `set_target_closed`, `assert_authorized` panics for every
//! authority-gated procedure (pause, metadata setters, policy setters, ...) regardless of role or
//! owner membership, atomically freezing the account's management surface. `set_target_opened`
//! is gated directly on the owner check (not `assert_authorized`), so it bypasses the closed flag
//! and the owner can always reopen a closed account.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountIdVersion,
    AccountType,
    RoleSymbol,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::pausable::PausableManager;
use miden_standards::account::access::{AccessControl, Authority};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::errors::standards::{ERR_AUTHORITY_CLOSED, ERR_SENDER_NOT_OWNER};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

static OWNER_ID: LazyLock<AccountId> = LazyLock::new(|| test_account_id(11));
static NON_OWNER_ID: LazyLock<AccountId> = LazyLock::new(|| test_account_id(99));

fn test_account_id(seed: u8) -> AccountId {
    AccountId::dummy([seed; 15], AccountIdVersion::Version1, AccountType::Private)
}

// FAUCET BUILDERS
// ================================================================================================

/// Builds a fungible faucet with `Pausable + PausableManager + Ownable2Step(owner)`, with a
/// mutable `max_supply` so the metadata setter path can be exercised too.
fn add_owner_faucet(
    builder: &mut MockChainBuilder,
    owner: AccountId,
    seed: u8,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .is_max_supply_mutable(true)
        .build()?;

    let account_builder = AccountBuilder::new([seed; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(PausableManager);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds an RBAC faucet whose `pause` is gated by the `PAUSER` role.
fn add_rbac_faucet(
    builder: &mut MockChainBuilder,
    owner: AccountId,
    roles: BTreeMap<miden_protocol::account::AccountProcedureRoot, RoleSymbol>,
    seed: u8,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([seed; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_components(AccessControl::Rbac { owner, roles })
        .with_component(PausableManager);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// NOTE BUILDERS
// ================================================================================================

fn build_note(sender: AccountId, code: impl Into<String>) -> anyhow::Result<Note> {
    let seed: [u32; 4] = rand::random();
    let mut rng = RandomCoin::new(Word::from(seed));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .code(code.into())
        .build()?)
}

/// Builds a note that calls `authority::set_target_closed`.
fn build_close_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::access::authority

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.authority::set_target_closed
            dropw dropw dropw dropw
        end
        "#,
    )
}

/// Builds a note that calls `authority::set_target_opened`.
fn build_open_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::access::authority

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.authority::set_target_opened
            dropw dropw dropw dropw
        end
        "#,
    )
}

/// Builds a note that calls `pausable::manager::pause` (an authority-gated procedure).
fn build_pause_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::access::pausable::manager

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.manager::pause
            dropw dropw dropw dropw
        end
        "#,
    )
}

/// Builds a note that calls `set_max_supply`, an authority-gated metadata setter.
fn build_set_max_supply_note(sender: AccountId, new_max_supply: u64) -> anyhow::Result<Note> {
    build_note(
        sender,
        format!(
            r#"
        @note_script
        pub proc main
            push.{new_max_supply}
            swap drop
            call.::miden::standards::faucets::fungible::set_max_supply
        end
        "#,
        ),
    )
}

/// Builds a note that grants `role` to `account_id` via `rbac::grant_role`.
fn build_grant_role_note(
    sender: AccountId,
    role: &RoleSymbol,
    account_id: AccountId,
) -> anyhow::Result<Note> {
    build_note(
        sender,
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
        ),
    )
}

// HELPERS
// ================================================================================================

async fn execute_note_on_faucet(
    mock_chain: &mut MockChain,
    faucet_id: AccountId,
    note: &Note,
) -> anyhow::Result<()> {
    let executed = mock_chain
        .build_tx_context(faucet_id, &[note.id()], &[])?
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    Ok(())
}

/// Returns whether the faucet's authority `target_closed` flag (word[1]) is set.
fn is_authority_closed(mock_chain: &MockChain, faucet_id: AccountId) -> anyhow::Result<bool> {
    let account = mock_chain.committed_account(faucet_id)?;
    let word = account.storage().get_item(Authority::authority_slot())?;
    Ok(word[1] != Felt::ZERO)
}

fn role(name: &str) -> RoleSymbol {
    RoleSymbol::new(name).expect("role symbol should be valid")
}

// TESTS — OWNER-CONTROLLED EMERGENCY SWITCH
// ================================================================================================

#[tokio::test]
async fn owner_closes_then_gated_procedure_is_blocked() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_owner_faucet(&mut builder, *OWNER_ID, 60)?;

    let close_note = build_close_note(*OWNER_ID)?;
    let pause_note = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(close_note.clone()));
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Owner closes the authority surface.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &close_note).await?;
    assert!(is_authority_closed(&mock_chain, faucet.id())?);

    // The owner's own pause call is now blocked because the surface is closed.
    let result = mock_chain
        .build_tx_context(faucet.id(), &[pause_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTHORITY_CLOSED);

    Ok(())
}

#[tokio::test]
async fn closed_blocks_authority_gated_metadata_setter() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_owner_faucet(&mut builder, *OWNER_ID, 61)?;

    let close_note = build_close_note(*OWNER_ID)?;
    let set_max_supply_note = build_set_max_supply_note(*OWNER_ID, 500_000)?;
    builder.add_output_note(RawOutputNote::Full(close_note.clone()));
    builder.add_output_note(RawOutputNote::Full(set_max_supply_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &close_note).await?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[set_max_supply_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTHORITY_CLOSED);

    Ok(())
}

#[tokio::test]
async fn non_owner_cannot_close() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_owner_faucet(&mut builder, *OWNER_ID, 62)?;

    let attacker_close_note = build_close_note(*NON_OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(attacker_close_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[attacker_close_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

#[tokio::test]
async fn owner_reopens_after_close_and_surface_works_again() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_owner_faucet(&mut builder, *OWNER_ID, 63)?;

    let close_note = build_close_note(*OWNER_ID)?;
    let open_note = build_open_note(*OWNER_ID)?;
    let pause_note = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(close_note.clone()));
    builder.add_output_note(RawOutputNote::Full(open_note.clone()));
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Close, then reopen. set_target_opened bypasses the closed flag, so the owner can never be
    // locked out.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &close_note).await?;
    assert!(is_authority_closed(&mock_chain, faucet.id())?);

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &open_note).await?;
    assert!(!is_authority_closed(&mock_chain, faucet.id())?);

    // Gated procedures work again after reopening.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    Ok(())
}

// TESTS — RBAC EMERGENCY SWITCH
// ================================================================================================

#[tokio::test]
async fn closed_blocks_role_holder_and_close_is_owner_only() -> anyhow::Result<()> {
    let pauser = test_account_id(20);

    let roles = BTreeMap::from([(PausableManager::pause_root(), role("PAUSER"))]);

    let mut builder = MockChain::builder();
    let faucet = add_rbac_faucet(&mut builder, *OWNER_ID, roles, 64)?;

    let grant_pauser = build_grant_role_note(*OWNER_ID, &role("PAUSER"), pauser)?;
    let pause_note_before = build_pause_note(pauser)?;
    let pauser_close_note = build_close_note(pauser)?;
    let owner_close_note = build_close_note(*OWNER_ID)?;
    let pause_note_after = build_pause_note(pauser)?;
    for note in [
        &grant_pauser,
        &pause_note_before,
        &pauser_close_note,
        &owner_close_note,
        &pause_note_after,
    ] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &grant_pauser).await?;

    // The PAUSER can pause while the surface is open.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note_before).await?;

    // A role holder is not the owner, so cannot operate the emergency switch.
    let pauser_close_result = mock_chain
        .build_tx_context(faucet.id(), &[pauser_close_note.id()], &[])?
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(pauser_close_result, ERR_SENDER_NOT_OWNER);

    // The owner closes the surface.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &owner_close_note).await?;
    assert!(is_authority_closed(&mock_chain, faucet.id())?);

    // Now even the PAUSER's role-authorized pause is blocked by the closed flag.
    let pause_after_result = mock_chain
        .build_tx_context(faucet.id(), &[pause_note_after.id()], &[])?
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(pause_after_result, ERR_AUTHORITY_CLOSED);

    Ok(())
}
