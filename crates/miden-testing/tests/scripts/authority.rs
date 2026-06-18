//! Tests for the `Authority` global emergency switch (`freeze` / `unfreeze`).

use std::collections::BTreeMap;

use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountProcedureRoot,
    AccountType,
    RoleSymbol,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::pausable::{Pausable, PausableManager};
use miden_standards::account::access::{AccessControl, Authority};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::errors::standards::{ERR_AUTHORITY_FROZEN, ERR_SENDER_NOT_OWNER};
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

use super::pausable::{
    NON_OWNER_ID,
    OWNER_ID,
    build_grant_role_note,
    build_note,
    build_pause_note,
    build_set_max_supply_note,
    execute_note_on_faucet,
    role,
    test_account_id,
};

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
        .with_component(Pausable::unpaused())
        .with_component(PausableManager);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds an RBAC faucet whose `pause` is gated by the `PAUSER` role.
fn add_rbac_faucet(
    builder: &mut MockChainBuilder,
    owner: AccountId,
    roles: BTreeMap<AccountProcedureRoot, RoleSymbol>,
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
        .with_component(Pausable::unpaused())
        .with_component(PausableManager);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// NOTE BUILDERS
// ================================================================================================

/// Builds a note that calls `authority::freeze`.
fn build_freeze_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::access::authority

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.authority::freeze
            dropw dropw dropw dropw
        end
        "#,
    )
}

/// Builds a note that calls `authority::unfreeze`.
fn build_unfreeze_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::access::authority

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.authority::unfreeze
            dropw dropw dropw dropw
        end
        "#,
    )
}

// HELPERS
// ================================================================================================

/// Returns whether the faucet's authority surface is currently frozen.
fn is_frozen(mock_chain: &MockChain, faucet_id: AccountId) -> anyhow::Result<bool> {
    let account = mock_chain.committed_account(faucet_id)?;
    Ok(Authority::try_read_frozen(account.storage())?)
}

// TESTS — OWNER-CONTROLLED EMERGENCY SWITCH
// ================================================================================================

#[tokio::test]
async fn owner_freezes_then_gated_procedure_is_blocked() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_owner_faucet(&mut builder, *OWNER_ID, 60)?;

    let freeze_note = build_freeze_note(*OWNER_ID)?;
    let pause_note = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(freeze_note.clone()));
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Owner freezes the authority surface.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &freeze_note).await?;
    assert!(is_frozen(&mock_chain, faucet.id())?);

    // The owner's own pause call is now blocked because the surface is frozen.
    let result = mock_chain
        .build_tx_context(faucet.id(), &[pause_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTHORITY_FROZEN);

    Ok(())
}

#[tokio::test]
async fn frozen_blocks_authority_gated_metadata_setter() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_owner_faucet(&mut builder, *OWNER_ID, 61)?;

    let freeze_note = build_freeze_note(*OWNER_ID)?;
    let set_max_supply_note = build_set_max_supply_note(*OWNER_ID, 500_000)?;
    builder.add_output_note(RawOutputNote::Full(freeze_note.clone()));
    builder.add_output_note(RawOutputNote::Full(set_max_supply_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &freeze_note).await?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[set_max_supply_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTHORITY_FROZEN);

    Ok(())
}

#[tokio::test]
async fn non_owner_cannot_freeze() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_owner_faucet(&mut builder, *OWNER_ID, 62)?;

    let attacker_freeze_note = build_freeze_note(*NON_OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(attacker_freeze_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[attacker_freeze_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

#[tokio::test]
async fn owner_unfreezes_and_surface_works_again() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_owner_faucet(&mut builder, *OWNER_ID, 63)?;

    let freeze_note = build_freeze_note(*OWNER_ID)?;
    let unfreeze_note = build_unfreeze_note(*OWNER_ID)?;
    let pause_note = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(freeze_note.clone()));
    builder.add_output_note(RawOutputNote::Full(unfreeze_note.clone()));
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Freeze, then unfreeze. `unfreeze` bypasses the frozen flag, so the owner can never be
    // locked out.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &freeze_note).await?;
    assert!(is_frozen(&mock_chain, faucet.id())?);

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &unfreeze_note).await?;
    assert!(!is_frozen(&mock_chain, faucet.id())?);

    // Gated procedures work again after unfreezing.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    Ok(())
}

// TESTS — RBAC EMERGENCY SWITCH
// ================================================================================================

#[tokio::test]
async fn frozen_blocks_role_holder_and_freeze_is_owner_only() -> anyhow::Result<()> {
    let pauser = test_account_id(20);

    let roles = BTreeMap::from([(PausableManager::pause_root(), role("PAUSER"))]);

    let mut builder = MockChain::builder();
    let faucet = add_rbac_faucet(&mut builder, *OWNER_ID, roles, 64)?;

    let grant_pauser = build_grant_role_note(*OWNER_ID, &role("PAUSER"), pauser)?;
    let pause_note_before = build_pause_note(pauser)?;
    let pauser_freeze_note = build_freeze_note(pauser)?;
    let owner_freeze_note = build_freeze_note(*OWNER_ID)?;
    let pause_note_after = build_pause_note(pauser)?;
    for note in [
        &grant_pauser,
        &pause_note_before,
        &pauser_freeze_note,
        &owner_freeze_note,
        &pause_note_after,
    ] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &grant_pauser).await?;

    // The PAUSER can pause while the surface is unfrozen.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note_before).await?;

    // A role holder is not the owner, so cannot operate the emergency switch.
    let pauser_freeze_result = mock_chain
        .build_tx_context(faucet.id(), &[pauser_freeze_note.id()], &[])?
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(pauser_freeze_result, ERR_SENDER_NOT_OWNER);

    // The owner freezes the surface.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &owner_freeze_note).await?;
    assert!(is_frozen(&mock_chain, faucet.id())?);

    // Now even the PAUSER's role-authorized pause is blocked by the frozen flag.
    let pause_after_result = mock_chain
        .build_tx_context(faucet.id(), &[pause_note_after.id()], &[])?
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(pause_after_result, ERR_AUTHORITY_FROZEN);

    Ok(())
}
