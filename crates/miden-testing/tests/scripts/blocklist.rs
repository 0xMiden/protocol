//! Tests for the [`miden_standards::account::policies::BasicBlocklist`] transfer policy
//! component (storage + `check_policy` predicate) and the
//! [`miden_standards::account::policies::OwnerControlledBlocklist`] owner-controlled admin
//! component, dispatched directly by the protocol callback slots via
//! [`miden_standards::account::policies::TokenPolicyManager`].

extern crate alloc;

use std::sync::Arc;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, AssetAmount, AssetCallbackFlag, FungibleAsset};
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Ownable2Step;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BasicBlocklist,
    BurnPolicyConfig,
    MintPolicyConfig,
    OwnerControlledBlocklist,
    PolicyAuthority,
    PolicyRegistration,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_ACCOUNT_IS_BLOCKED;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

// HELPERS
// ================================================================================================

fn dummy_owner() -> AccountId {
    AccountId::dummy(
        [9; 15],
        AccountIdVersion::Version1,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    )
}

/// Builds a fungible faucet with [`TransferPolicy::Blocklist`] on both send and receive,
/// plus the [`OwnerControlledBlocklist`] component (gated by `Ownable2Step::new(owner_id)`)
/// so that the owner can invoke `block_account` / `unblock_account` via owner-authored notes.
fn add_faucet_with_owner_blocklist_transfer(
    builder: &mut MockChainBuilder,
    owner_id: AccountId,
) -> anyhow::Result<Account> {
    add_faucet_with_owner_blocklist_transfer_initialized(builder, owner_id, [])
}

/// Same as [`add_faucet_with_owner_blocklist_transfer`] but seeds the `blocked_accounts`
/// storage map with the given accounts at deploy time via
/// [`BasicBlocklist::with_blocked_accounts`]. The transfer policy is wired up through
/// [`TransferPolicy::Custom`] so the manager does not also install an empty `BasicBlocklist`
/// (which would conflict with the seeded one).
fn add_faucet_with_owner_blocklist_transfer_initialized(
    builder: &mut MockChainBuilder,
    owner_id: AccountId,
    initial_blocked: impl IntoIterator<Item = AccountId>,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let basic_blocklist = BasicBlocklist::with_blocked_accounts(initial_blocked);

    let account_builder = AccountBuilder::new([43u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner_id))
        .with_components(
            TokenPolicyManager::new(PolicyAuthority::OwnerControlled)
                .with_mint_policy(MintPolicyConfig::AllowAll, PolicyRegistration::Active)?
                .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)?
                .with_send_policy(
                    TransferPolicy::Custom(BasicBlocklist::root()),
                    PolicyRegistration::Active,
                )?
                .with_receive_policy(
                    TransferPolicy::Custom(BasicBlocklist::root()),
                    PolicyRegistration::Active,
                )?,
        )
        .with_component(basic_blocklist)
        .with_component(OwnerControlledBlocklist);

    builder.add_account_from_builder(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )
}

fn account_id_felts(account_id: AccountId) -> (Felt, Felt) {
    let [prefix, suffix]: [Felt; 2] = account_id.into();
    (prefix, suffix)
}

/// Builds an owner-authored note whose script invokes
/// `owner_controlled::{block_account|unblock_account}` on the given target account.
fn build_owner_admin_note(
    owner_id: AccountId,
    target_id: AccountId,
    proc: &str,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let (prefix, suffix) = account_id_felts(target_id);
    let script_code = format!(
        r#"
        use miden::standards::faucets::policies::transfer::blocklist::owner_controlled

        @note_script
        pub proc main
            padw padw padw push.0.0

            push.{prefix}
            push.{suffix}
            call.owner_controlled::{proc}

            dropw dropw dropw dropw
        end
        "#
    );

    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    NoteBuilder::new(owner_id, &mut rng)
        .note_type(NoteType::Private)
        .code(script_code.as_str())
        .build()
        .map_err(Into::into)
}

/// Consumes an owner-authored admin note in a faucet transaction.
async fn consume_admin_note(
    mock_chain: &mut MockChain,
    faucet_id: AccountId,
    note: &Note,
) -> anyhow::Result<()> {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let executed = mock_chain
        .build_tx_context(faucet_id, &[note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    Ok(())
}

// TESTS
// ================================================================================================

#[tokio::test]
async fn block_receive_asset_succeeds_when_not_blocked() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Seeds [`BasicBlocklist`] with the recipient at deploy time and confirms the asset transfer
/// fails immediately — no `block_account` admin call is needed because the account starts in
/// the `blocked_accounts` map.
#[tokio::test]
async fn block_receive_asset_fails_when_account_pre_blocked() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer_initialized(
        &mut builder,
        owner_id,
        [target_account.id()],
    )?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[p2id_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_BLOCKED);

    Ok(())
}

#[tokio::test]
async fn block_receive_asset_fails_when_recipient_blocked() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let block_note = build_owner_admin_note(owner_id, target_account.id(), "block_account", 1)?;
    builder.add_output_note(RawOutputNote::Full(block_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &block_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[p2id_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_BLOCKED);

    Ok(())
}

#[tokio::test]
async fn block_add_asset_to_note_fails_when_sender_blocked() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);

    let block_note = build_owner_admin_note(owner_id, target_account.id(), "block_account", 2)?;
    builder.add_output_note(RawOutputNote::Full(block_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &block_note).await?;

    let recipient = Word::from([0u32, 1, 2, 3]);
    let script_code = format!(
        r#"
        use miden::protocol::output_note

        begin
            push.{recipient}
            push.{note_type}
            push.{tag}
            exec.output_note::create

            push.{asset_value}
            push.{asset_key}
            exec.output_note::add_asset
        end
        "#,
        recipient = recipient,
        note_type = NoteType::Private as u8,
        tag = NoteTag::default(),
        asset_value = Asset::Fungible(asset).to_value_word(),
        asset_key = Asset::Fungible(asset).to_key_word(),
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(&script_code)?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[], &[])?
        .tx_script(tx_script)
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_BLOCKED);

    Ok(())
}

#[tokio::test]
async fn block_then_unblock_then_receive_succeeds() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    let amount: u64 = 50;
    let fungible_asset =
        FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    let block_note = build_owner_admin_note(owner_id, target_account.id(), "block_account", 3)?;
    let unblock_note = build_owner_admin_note(owner_id, target_account.id(), "unblock_account", 4)?;
    builder.add_output_note(RawOutputNote::Full(block_note.clone()));
    builder.add_output_note(RawOutputNote::Full(unblock_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &block_note).await?;
    consume_admin_note(&mut mock_chain, faucet.id(), &unblock_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    mock_chain
        .build_tx_context(target_account.id(), &[p2id_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

#[tokio::test]
async fn block_already_blocked_is_noop() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    let block_note_1 = build_owner_admin_note(owner_id, target_account.id(), "block_account", 5)?;
    let block_note_2 = build_owner_admin_note(owner_id, target_account.id(), "block_account", 6)?;
    builder.add_output_note(RawOutputNote::Full(block_note_1.clone()));
    builder.add_output_note(RawOutputNote::Full(block_note_2.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &block_note_1).await?;

    // Second block on the same already-blocked user is a noop — succeeds silently.
    consume_admin_note(&mut mock_chain, faucet.id(), &block_note_2).await?;

    Ok(())
}

#[tokio::test]
async fn unblock_when_not_blocked_is_noop() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    let unblock_note = build_owner_admin_note(owner_id, target_account.id(), "unblock_account", 7)?;
    builder.add_output_note(RawOutputNote::Full(unblock_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Unblocking a non-blocked account is a noop — succeeds silently.
    consume_admin_note(&mut mock_chain, faucet.id(), &unblock_note).await?;

    Ok(())
}

#[tokio::test]
async fn block_does_not_affect_other_accounts() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let blocked_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let other_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    let amount: u64 = 25;
    let fungible_asset =
        FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        other_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    // Block a different account — the non-blocked one should still receive.
    let block_note = build_owner_admin_note(owner_id, blocked_account.id(), "block_account", 8)?;
    builder.add_output_note(RawOutputNote::Full(block_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &block_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    mock_chain
        .build_tx_context(other_account.id(), &[p2id_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Verifies that `mint_and_send` works on a `BasicFungibleFaucet` whose `TokenPolicyManager`
/// installs the asset-callback slots (here via [`TransferPolicy::Blocklist`]).
#[tokio::test]
async fn mint_and_send_on_blocklist_basic_faucet() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    let recipient = Word::from([0u32, 1, 2, 3]);
    let amount: u64 = 100;
    let tag = NoteTag::default();
    let note_type = NoteType::Private;

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
        recipient = recipient,
        note_type = note_type as u8,
        tag = u32::from(tag),
        amount = amount,
    );

    let tx_script = CodeBuilder::default().compile_tx_script(&tx_script_code)?;
    let executed = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 1);
    Ok(())
}
