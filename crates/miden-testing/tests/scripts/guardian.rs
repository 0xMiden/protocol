//! Tests for the standalone `Guardian` component (`get_guardian` / `set_guardian`).
//!
//! `set_guardian` is gated through `authority::assert_authorized`, so on an `Ownable2Step`
//! (`OwnerControlled`) account only the owner can set or clear the guardian.

use miden_protocol::Felt;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::{AccessControl, Guardian};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::errors::standards::ERR_SENDER_NOT_OWNER;
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
    build_note,
    execute_note_on_faucet,
    test_account_id,
};

// FAUCET BUILDER
// ================================================================================================

/// Builds a fungible faucet with `Guardian + Ownable2Step(owner)`. `set_guardian` is gated by the
/// owner via `Authority::OwnerControlled` (installed automatically by
/// `AccessControl::Ownable2Step`).
fn add_guardian_faucet(
    builder: &mut MockChainBuilder,
    owner: AccountId,
    guardian: Option<AccountId>,
    seed: u8,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let guardian_component = match guardian {
        Some(id) => Guardian::new(id),
        None => Guardian::unassigned(),
    };

    let account_builder = AccountBuilder::new([seed; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(guardian_component);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// NOTE BUILDERS
// ================================================================================================

/// Builds a note that calls `guardian::set_guardian` with the given account ID felts.
fn build_set_guardian_note(
    sender: AccountId,
    new_guardian_suffix: Felt,
    new_guardian_prefix: Felt,
) -> anyhow::Result<Note> {
    build_note(
        sender,
        format!(
            r#"
        use miden::standards::access::guardian

        @note_script
        pub proc main
            repeat.14 push.0 end
            push.{new_guardian_prefix}
            push.{new_guardian_suffix}
            call.guardian::set_guardian
            dropw dropw dropw dropw
        end
        "#
        ),
    )
}

// HELPERS
// ================================================================================================

/// Reads the configured guardian from the faucet's storage.
fn read_guardian(
    mock_chain: &MockChain,
    faucet_id: AccountId,
) -> anyhow::Result<Option<AccountId>> {
    let account = mock_chain.committed_account(faucet_id)?;
    Ok(Guardian::try_from_storage(account.storage())?.guardian())
}

// TESTS
// ================================================================================================

#[tokio::test]
async fn guardian_installs_with_initial_value() -> anyhow::Result<()> {
    let initial_guardian = test_account_id(30);

    let mut builder = MockChain::builder();
    let faucet = add_guardian_faucet(&mut builder, *OWNER_ID, Some(initial_guardian), 70)?;

    let mock_chain = builder.build()?;

    assert_eq!(read_guardian(&mock_chain, faucet.id())?, Some(initial_guardian));

    Ok(())
}

#[tokio::test]
async fn owner_sets_guardian() -> anyhow::Result<()> {
    let new_guardian = test_account_id(31);

    let mut builder = MockChain::builder();
    let faucet = add_guardian_faucet(&mut builder, *OWNER_ID, None, 71)?;

    let set_note =
        build_set_guardian_note(*OWNER_ID, new_guardian.suffix(), new_guardian.prefix().as_felt())?;
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &set_note).await?;

    assert_eq!(read_guardian(&mock_chain, faucet.id())?, Some(new_guardian));

    Ok(())
}

#[tokio::test]
async fn non_owner_cannot_set_guardian() -> anyhow::Result<()> {
    let new_guardian = test_account_id(32);

    let mut builder = MockChain::builder();
    let faucet = add_guardian_faucet(&mut builder, *OWNER_ID, None, 72)?;

    let attacker_note = build_set_guardian_note(
        *NON_OWNER_ID,
        new_guardian.suffix(),
        new_guardian.prefix().as_felt(),
    )?;
    builder.add_output_note(RawOutputNote::Full(attacker_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[attacker_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

#[tokio::test]
async fn owner_clears_guardian() -> anyhow::Result<()> {
    let initial_guardian = test_account_id(33);

    let mut builder = MockChain::builder();
    let faucet = add_guardian_faucet(&mut builder, *OWNER_ID, Some(initial_guardian), 73)?;

    // Clearing is done by setting the zero address `(0, 0)`.
    let clear_note = build_set_guardian_note(*OWNER_ID, Felt::ZERO, Felt::ZERO)?;
    builder.add_output_note(RawOutputNote::Full(clear_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &clear_note).await?;

    assert_eq!(read_guardian(&mock_chain, faucet.id())?, None);

    Ok(())
}
