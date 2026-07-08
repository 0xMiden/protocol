//! Tests for the standalone `Sentry` component (`get_sentry` / `set_sentry`).
//!
//! `set_sentry` is gated through `authority::assert_authorized`, so on an `Ownable2Step`
//! (`OwnerControlled`) account only the owner can set or clear the sentry.

use miden_protocol::Felt;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::{AccessControl, Sentry};
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

/// Builds a fungible faucet with `Sentry + Ownable2Step(owner)`. `set_sentry` is gated by the
/// owner via `Authority::OwnerControlled` (installed automatically by
/// `AccessControl::Ownable2Step`).
fn add_sentry_faucet(
    builder: &mut MockChainBuilder,
    owner: AccountId,
    sentry: Option<AccountId>,
    seed: u8,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let sentry_component = match sentry {
        Some(id) => Sentry::new(id),
        None => Sentry::unassigned(),
    };

    let account_builder = AccountBuilder::new([seed; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(sentry_component);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// NOTE BUILDERS
// ================================================================================================

/// Builds a note that calls `sentry::set_sentry` with the given account ID felts.
fn build_set_sentry_note(
    sender: AccountId,
    new_sentry_suffix: Felt,
    new_sentry_prefix: Felt,
) -> anyhow::Result<Note> {
    build_note(
        sender,
        format!(
            r#"
        use miden::standards::access::sentry

        @note_script
        pub proc main
            repeat.14 push.0 end
            push.{new_sentry_prefix}
            push.{new_sentry_suffix}
            call.sentry::set_sentry
            dropw dropw dropw dropw
        end
        "#
        ),
    )
}

// HELPERS
// ================================================================================================

/// Reads the configured sentry from the faucet's storage.
fn read_sentry(mock_chain: &MockChain, faucet_id: AccountId) -> anyhow::Result<Option<AccountId>> {
    let account = mock_chain.committed_account(faucet_id)?;
    Ok(Sentry::try_from_storage(account.storage())?.account_id())
}

// TESTS
// ================================================================================================

#[tokio::test]
async fn sentry_installs_with_initial_value() -> anyhow::Result<()> {
    let initial_sentry = test_account_id(30);

    let mut builder = MockChain::builder();
    let faucet = add_sentry_faucet(&mut builder, *OWNER_ID, Some(initial_sentry), 70)?;

    let mock_chain = builder.build()?;

    assert_eq!(read_sentry(&mock_chain, faucet.id())?, Some(initial_sentry));

    Ok(())
}

#[tokio::test]
async fn owner_sets_sentry() -> anyhow::Result<()> {
    let new_sentry = test_account_id(31);

    let mut builder = MockChain::builder();
    let faucet = add_sentry_faucet(&mut builder, *OWNER_ID, None, 71)?;

    let set_note =
        build_set_sentry_note(*OWNER_ID, new_sentry.suffix(), new_sentry.prefix().as_felt())?;
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &set_note).await?;

    assert_eq!(read_sentry(&mock_chain, faucet.id())?, Some(new_sentry));

    Ok(())
}

#[tokio::test]
async fn non_owner_cannot_set_sentry() -> anyhow::Result<()> {
    let new_sentry = test_account_id(32);

    let mut builder = MockChain::builder();
    let faucet = add_sentry_faucet(&mut builder, *OWNER_ID, None, 72)?;

    let attacker_note =
        build_set_sentry_note(*NON_OWNER_ID, new_sentry.suffix(), new_sentry.prefix().as_felt())?;
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
async fn owner_clears_sentry() -> anyhow::Result<()> {
    let initial_sentry = test_account_id(33);

    let mut builder = MockChain::builder();
    let faucet = add_sentry_faucet(&mut builder, *OWNER_ID, Some(initial_sentry), 73)?;

    // Clearing is done by setting the zero address `(0, 0)`.
    let clear_note = build_set_sentry_note(*OWNER_ID, Felt::ZERO, Felt::ZERO)?;
    builder.add_output_note(RawOutputNote::Full(clear_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &clear_note).await?;

    assert_eq!(read_sentry(&mock_chain, faucet.id())?, None);

    Ok(())
}
