//! Tests for the standalone `Warden` component (`get_warden` / `set_warden`).
//!
//! `set_warden` is gated through `authority::assert_authorized`, so on an `Ownable2Step`
//! (`OwnerControlled`) account only the owner can set or clear the warden.

use miden_protocol::Felt;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::{AccessControl, Warden};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::errors::standards::ERR_SENDER_NOT_OWNER;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

use super::pausable::{NON_OWNER_ID, OWNER_ID, execute_note_on_faucet};
use super::rbac::{build_note, test_account_id};

// FAUCET BUILDER
// ================================================================================================

/// Builds a fungible faucet with `Warden + Ownable2Step(owner)`. `set_warden` is gated by the
/// owner via `Authority::OwnerControlled` (installed automatically by
/// `AccessControl::Ownable2Step`).
fn add_warden_faucet(
    builder: &mut MockChainBuilder,
    owner: AccountId,
    warden: Option<AccountId>,
    seed: u8,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let warden_component = match warden {
        Some(id) => Warden::new(id),
        None => Warden::unassigned(),
    };

    let account_builder = AccountBuilder::new([seed; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(warden_component);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// NOTE BUILDERS
// ================================================================================================

/// Builds a note that calls `warden::set_warden` with the given account ID felts.
fn build_set_warden_note(
    sender: AccountId,
    new_warden_suffix: Felt,
    new_warden_prefix: Felt,
) -> anyhow::Result<Note> {
    build_note(
        sender,
        format!(
            r#"
        use miden::standards::access::warden

        @note_script
        pub proc main
            repeat.14 push.0 end
            push.{new_warden_prefix}
            push.{new_warden_suffix}
            call.warden::set_warden
            dropw dropw dropw dropw
        end
        "#
        ),
    )
}

// HELPERS
// ================================================================================================

/// Reads the configured warden from the faucet's storage.
fn read_warden(mock_chain: &MockChain, faucet_id: AccountId) -> anyhow::Result<Option<AccountId>> {
    let account = mock_chain.committed_account(faucet_id)?;
    Ok(Warden::try_from_storage(account.storage())?.account_id())
}

// TESTS
// ================================================================================================

#[tokio::test]
async fn warden_installs_with_initial_value() -> anyhow::Result<()> {
    let initial_warden = test_account_id(30);

    let mut builder = MockChain::builder();
    let faucet = add_warden_faucet(&mut builder, *OWNER_ID, Some(initial_warden), 70)?;

    let mock_chain = builder.build()?;

    assert_eq!(read_warden(&mock_chain, faucet.id())?, Some(initial_warden));

    Ok(())
}

#[tokio::test]
async fn owner_sets_warden() -> anyhow::Result<()> {
    let new_warden = test_account_id(31);

    let mut builder = MockChain::builder();
    let faucet = add_warden_faucet(&mut builder, *OWNER_ID, None, 71)?;

    let set_note =
        build_set_warden_note(*OWNER_ID, new_warden.suffix(), new_warden.prefix().as_felt())?;
    builder.add_output_note(RawOutputNote::Full(set_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &set_note).await?;

    assert_eq!(read_warden(&mock_chain, faucet.id())?, Some(new_warden));

    Ok(())
}

#[tokio::test]
async fn non_owner_cannot_set_warden() -> anyhow::Result<()> {
    let new_warden = test_account_id(32);

    let mut builder = MockChain::builder();
    let faucet = add_warden_faucet(&mut builder, *OWNER_ID, None, 72)?;

    let attacker_note =
        build_set_warden_note(*NON_OWNER_ID, new_warden.suffix(), new_warden.prefix().as_felt())?;
    builder.add_output_note(RawOutputNote::Full(attacker_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(faucet.id())
        .authenticated_input_note(attacker_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

#[tokio::test]
async fn owner_clears_warden() -> anyhow::Result<()> {
    let initial_warden = test_account_id(33);

    let mut builder = MockChain::builder();
    let faucet = add_warden_faucet(&mut builder, *OWNER_ID, Some(initial_warden), 73)?;

    // Clearing is done by setting the zero address `(0, 0)`.
    let clear_note = build_set_warden_note(*OWNER_ID, Felt::ZERO, Felt::ZERO)?;
    builder.add_output_note(RawOutputNote::Full(clear_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &clear_note).await?;

    assert_eq!(read_warden(&mock_chain, faucet.id())?, None);

    Ok(())
}
