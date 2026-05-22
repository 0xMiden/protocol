//! Tests for the `Pausable` storage component, `PausableManager` admin wrapper, and the
//! pause integration (mint / burn / transfer / metadata setters).
//!
//! A single `pause()` call by an authorized sender blocks mint, burn, transfer, and metadata
//! updates uniformly until a matching `unpause()` call.

extern crate alloc;

use alloc::string::String;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountIdVersion, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, AssetCallbackFlag, FungibleAsset};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::utils::sync::LazyLock;
use miden_standards::account::access::AccessControl;
use miden_standards::account::access::pausable::{PausableManager, PausableStorage};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyRegistration,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

const ERR_PAUSABLE_IS_PAUSED: MasmError = MasmError::from_static_str("the contract is paused");

const ERR_PAUSABLE_EXPECTED_PAUSE: MasmError =
    MasmError::from_static_str("the contract is not paused");

const ERR_SENDER_NOT_OWNER: MasmError = MasmError::from_static_str("note sender is not the owner");

static OWNER_ID: LazyLock<AccountId> = LazyLock::new(|| test_account_id(11));
static NON_OWNER_ID: LazyLock<AccountId> = LazyLock::new(|| test_account_id(99));

fn test_account_id(seed: u8) -> AccountId {
    AccountId::dummy([seed; 15], AccountIdVersion::Version1, AccountType::Private)
}

// FAUCET BUILDER
// ================================================================================================

/// Builds a fungible faucet with `Pausable + PausableManager + Ownable2Step(owner)`. Pause /
/// unpause are gated by the owner via `Authority::OwnerControlled` (installed automatically by
/// `AccessControl::Ownable2Step`).
fn add_faucet_with_pause(
    builder: &mut MockChainBuilder,
    owner: AccountId,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([43u8; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_components(AccessControl::Ownable2Step { owner })
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

/// Builds an owner-authored note that calls `pausable::manager::pause`.
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

/// Builds an owner-authored note that calls `pausable::manager::unpause`.
fn build_unpause_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::access::pausable::manager

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.manager::unpause
            dropw dropw dropw dropw
        end
        "#,
    )
}

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

// TESTS — PAUSABLE MANAGER (Authority dispatch)
// ================================================================================================

#[tokio::test]
async fn pausable_manager_pause_succeeds_when_sender_is_owner() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pause(&mut builder, *OWNER_ID)?;

    let pause_note = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    Ok(())
}

#[tokio::test]
async fn pausable_manager_pause_fails_when_sender_not_owner() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pause(&mut builder, *OWNER_ID)?;

    // Authority::OwnerControlled (installed by AccessControl::Ownable2Step) rejects non-owner
    // senders for any procedure that calls `exec.authority::assert_authorized`.
    let attacker_note = build_pause_note(*NON_OWNER_ID)?;
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
async fn pausable_manager_unpause_fails_when_sender_not_owner() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pause(&mut builder, *OWNER_ID)?;

    // Pre-stage both notes: legitimate owner pause + attacker unpause.
    let pause_note = build_pause_note(*OWNER_ID)?;
    let attacker_unpause_note = build_unpause_note(*NON_OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    builder.add_output_note(RawOutputNote::Full(attacker_unpause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[attacker_unpause_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

#[tokio::test]
async fn pausable_manager_pause_then_unpause_then_pause_again() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pause(&mut builder, *OWNER_ID)?;

    let pause_note_1 = build_pause_note(*OWNER_ID)?;
    let unpause_note = build_unpause_note(*OWNER_ID)?;
    let pause_note_2 = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note_1.clone()));
    builder.add_output_note(RawOutputNote::Full(unpause_note.clone()));
    builder.add_output_note(RawOutputNote::Full(pause_note_2.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note_1).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &unpause_note).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note_2).await?;

    Ok(())
}

#[tokio::test]
async fn pausable_manager_unpause_while_unpaused_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pause(&mut builder, *OWNER_ID)?;

    let unpause_note = build_unpause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(unpause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[unpause_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_EXPECTED_PAUSE);

    Ok(())
}

#[tokio::test]
async fn pausable_manager_pause_while_paused_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pause(&mut builder, *OWNER_ID)?;

    let pause_note_1 = build_pause_note(*OWNER_ID)?;
    let pause_note_2 = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note_1.clone()));
    builder.add_output_note(RawOutputNote::Full(pause_note_2.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note_1).await?;

    // Second pause attempt fails because `exec.pausable::pause` body asserts the account is
    // NOT currently paused before flipping the flag.
    let result = mock_chain
        .build_tx_context(faucet.id(), &[pause_note_2.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_IS_PAUSED);

    Ok(())
}

// SANITY TESTS — PausableStorage helper
// ================================================================================================

#[test]
fn pausable_storage_default_is_unpaused() {
    let storage = PausableStorage::default();
    assert!(!storage.state());
    assert_eq!(storage.to_word(), Word::default());
}

#[test]
fn pausable_storage_paused_writes_canonical_word() {
    let storage = PausableStorage::paused();
    assert!(storage.state());
    assert_eq!(storage.to_word(), Word::from([1u32, 0, 0, 0]));
}

// TESTS — PAUSE (mint / burn / transfer policies)
// ================================================================================================
fn add_faucet_with_pause_and_policies(
    builder: &mut MockChainBuilder,
    owner: AccountId,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([44u8; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(PausableManager)
        .with_components(
            TokenPolicyManager::new()
                .with_mint_policy(MintPolicyConfig::AllowAll, PolicyRegistration::Active)?
                .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)?
                .with_send_policy(TransferPolicy::Blocklist, PolicyRegistration::Active)?
                .with_receive_policy(TransferPolicy::Blocklist, PolicyRegistration::Active)?,
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

#[tokio::test]
async fn pausable_transfer_succeeds_when_unpaused() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pause_and_policies(&mut builder, *OWNER_ID)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    mock_chain
        .build_tx_context(target.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

#[tokio::test]
async fn pausable_transfer_fails_when_paused() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pause_and_policies(&mut builder, *OWNER_ID)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let pause_note = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_IS_PAUSED);

    Ok(())
}

#[tokio::test]
async fn pausable_transfer_resumes_after_unpause() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pause_and_policies(&mut builder, *OWNER_ID)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let pause_note = build_pause_note(*OWNER_ID)?;
    let unpause_note = build_unpause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    builder.add_output_note(RawOutputNote::Full(unpause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &unpause_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    mock_chain
        .build_tx_context(target.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

// TESTS — MINT / BURN / METADATA SETTER PAUSE
// ================================================================================================

#[tokio::test]
async fn pausable_mint_fails_when_paused() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let _target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pause_and_policies(&mut builder, *OWNER_ID)?;

    let pause_note = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Pause the faucet first.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    // Build a mint tx-script targeting the now-paused faucet.
    let recipient_word = Word::from([0u32, 1, 2, 3]);
    let tx_script_code = format!(
        r#"
        begin
            padw padw push.0
            push.{recipient}
            push.{note_type}
            push.{tag}
            push.{amount}
            call.::miden::standards::faucets::fungible::mint_and_send
            dropw dropw dropw dropw
        end
        "#,
        recipient = recipient_word,
        note_type = NoteType::Private as u8,
        tag = u32::from(NoteTag::default()),
        amount = 100u64,
    );
    let tx_script =
        miden_standards::code_builder::CodeBuilder::default().compile_tx_script(&tx_script_code)?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    // execute_mint_policy calls exec.pausable::assert_not_paused before dispatch → panic.
    assert_transaction_executor_error!(result, ERR_PAUSABLE_IS_PAUSED);

    Ok(())
}

#[tokio::test]
async fn pausable_burn_fails_when_paused() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pause_and_policies(&mut builder, *OWNER_ID)?;

    // Pre-stage a burn note carrying an asset issued by this faucet.
    let burn_asset = FungibleAsset::new(faucet.id(), 50)?;
    let burn_note_script_code = r#"
        @note_script
        pub proc main
            dropw
            call.::miden::standards::faucets::fungible::receive_and_burn
        end
    "#;
    let burn_note_script = miden_standards::code_builder::CodeBuilder::default()
        .compile_note_script(burn_note_script_code)?;
    let mut rng = RandomCoin::new(Word::from([1u32, 2, 3, 4]));
    let burn_note = NoteBuilder::new(faucet.id(), &mut rng)
        .note_type(NoteType::Private)
        .add_assets([Asset::Fungible(burn_asset)])
        .script(burn_note_script)
        .build()?;
    builder.add_output_note(RawOutputNote::Full(burn_note.clone()));

    let pause_note = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[burn_note.id()], &[])?
        .build()?
        .execute()
        .await;

    // execute_burn_policy → exec.pausable::assert_not_paused → panic.
    assert_transaction_executor_error!(result, ERR_PAUSABLE_IS_PAUSED);

    Ok(())
}

/// Builds a faucet with mutable `max_supply` so that `set_max_supply` can be called via the
/// metadata setter path (which we want to verify is pause-gated).
fn add_faucet_mutable_max_supply_with_pause(
    builder: &mut MockChainBuilder,
    owner: AccountId,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .is_max_supply_mutable(true)
        .build()?;

    let account_builder = AccountBuilder::new([45u8; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(PausableManager);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

#[tokio::test]
async fn pausable_set_max_supply_fails_when_paused() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_mutable_max_supply_with_pause(&mut builder, *OWNER_ID)?;

    // Owner-authored note that calls set_max_supply.
    let set_max_supply_note_code = format!(
        r#"
        @note_script
        pub proc main
            push.{new_max_supply}
            swap drop
            call.::miden::standards::faucets::fungible::set_max_supply
        end
        "#,
        new_max_supply = 500_000u64,
    );
    let set_max_supply_note_script = miden_standards::code_builder::CodeBuilder::default()
        .compile_note_script(&set_max_supply_note_code)?;
    let mut rng = RandomCoin::new(Word::from([9u32, 8, 7, 6]));
    let set_max_supply_note = NoteBuilder::new(*OWNER_ID, &mut rng)
        .note_type(NoteType::Private)
        .script(set_max_supply_note_script)
        .build()?;
    builder.add_output_note(RawOutputNote::Full(set_max_supply_note.clone()));

    let pause_note = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Pause first.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    // Now try to update max_supply — should fail because set_max_supply has
    // `exec.pausable::assert_not_paused` after the authority check.
    let result = mock_chain
        .build_tx_context(faucet.id(), &[set_max_supply_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_IS_PAUSED);

    Ok(())
}

// TESTS — PAUSABLE MANAGER WITH AUTH-CONTROLLED ACCESS CONTROL
// ================================================================================================

/// Same as `add_faucet_with_pause` but uses `AccessControl::AuthControlled`.
fn add_faucet_with_pause_auth_controlled(
    builder: &mut MockChainBuilder,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([46u8; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_components(AccessControl::AuthControlled)
        .with_component(PausableManager);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

#[tokio::test]
async fn pausable_manager_works_with_auth_controlled() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pause_auth_controlled(&mut builder)?;

    // Any sender works because Authority::AuthControlled defers auth entirely to the account's
    // own auth scheme (here Auth::IncrNonce, which accepts unconditionally).
    let pause_note = build_pause_note(*NON_OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    Ok(())
}
