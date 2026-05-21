//! Tests for the [`miden_standards::account::policies::BasicAllowlist`] transfer policy
//! component (storage + `check_policy` predicate) and the
//! [`miden_standards::account::policies::AllowlistOwnerControlled`] owner-controlled admin
//! component, dispatched directly by the protocol callback slots via
//! [`miden_standards::account::policies::TokenPolicyManager`].

extern crate alloc;

use std::sync::Arc;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountIdVersion, AccountType};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, AssetAmount, AssetCallbackFlag, FungibleAsset};
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    AllowlistOwnerControlled,
    AllowlistStorage,
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyRegistration,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_ACCOUNT_IS_NOT_ALLOWED;
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
    AccountId::dummy([9; 15], AccountIdVersion::Version1, AccountType::Private)
}

/// Builds a fungible faucet with [`TransferPolicy::Allowlist`] on both send and receive,
/// plus the [`AllowlistOwnerControlled`] component (gated by `Ownable2Step::new(owner_id)`)
/// so that the owner can invoke `allow_account` / `disallow_account` via owner-authored notes.
///
/// The faucet starts with an empty allowlist — every transfer (and every mint that emits a
/// note) will fail until the owner calls `allow_account` to add the relevant accounts.
fn add_faucet_with_owner_allowlist_transfer(
    builder: &mut MockChainBuilder,
    owner_id: AccountId,
) -> anyhow::Result<Account> {
    add_faucet_with_owner_allowlist_transfer_initialized(builder, owner_id, [])
}

/// Same as [`add_faucet_with_owner_allowlist_transfer`] but seeds the `allowed_accounts`
/// storage map with the given accounts.
fn add_faucet_with_owner_allowlist_transfer_initialized(
    builder: &mut MockChainBuilder,
    owner_id: AccountId,
    initial_allowed: impl IntoIterator<Item = AccountId>,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let allow_list = AllowlistStorage::with_allowed_accounts(initial_allowed);

    let account_builder = AccountBuilder::new([43u8; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner_id))
        .with_component(Authority::OwnerControlled)
        .with_components(
            TokenPolicyManager::new()
                .with_mint_policy(MintPolicyConfig::AllowAll, PolicyRegistration::Active)?
                .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)?
                .with_send_policy(
                    TransferPolicy::Allowlist { allow_list: allow_list.clone() },
                    PolicyRegistration::Active,
                )?
                .with_receive_policy(
                    TransferPolicy::Allowlist { allow_list },
                    PolicyRegistration::Active,
                )?,
        )
        .with_component(AllowlistOwnerControlled);

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
/// `owner_controlled::{allow_account|disallow_account}` on the given target account.
fn build_owner_admin_note(
    owner_id: AccountId,
    target_id: AccountId,
    proc: &str,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let (prefix, suffix) = account_id_felts(target_id);
    let script_code = format!(
        r#"
        use miden::standards::faucets::policies::transfer::allowlist::owner_controlled

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

/// Seeds [`BasicAllowlist`] with the recipient at deploy time and confirms the asset transfer
/// succeeds — no `allow_account` admin call is needed because the account starts in the
/// `allowed_accounts` map.
#[tokio::test]
async fn allow_receive_asset_succeeds_when_account_pre_allowed() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer_initialized(
        &mut builder,
        owner_id,
        [target_account.id()],
    )?;

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

#[tokio::test]
async fn allow_receive_asset_fails_when_recipient_not_allowed() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

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

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_NOT_ALLOWED);

    Ok(())
}

#[tokio::test]
async fn allow_then_receive_succeeds() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let allow_note = build_owner_admin_note(owner_id, target_account.id(), "allow_account", 1)?;
    builder.add_output_note(RawOutputNote::Full(allow_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &allow_note).await?;

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
async fn allow_add_asset_to_note_fails_when_sender_not_allowed() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);

    let mock_chain = builder.build()?;

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

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_NOT_ALLOWED);

    Ok(())
}

#[tokio::test]
async fn allow_then_disallow_blocks_subsequent_receive() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer_initialized(
        &mut builder,
        owner_id,
        [target_account.id()],
    )?;

    let amount: u64 = 50;
    let fungible_asset =
        FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    let disallow_note =
        build_owner_admin_note(owner_id, target_account.id(), "disallow_account", 3)?;
    builder.add_output_note(RawOutputNote::Full(disallow_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &disallow_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[p2id_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_NOT_ALLOWED);

    Ok(())
}

#[tokio::test]
async fn allow_already_allowed_is_noop() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    let allow_note_1 = build_owner_admin_note(owner_id, target_account.id(), "allow_account", 5)?;
    let allow_note_2 = build_owner_admin_note(owner_id, target_account.id(), "allow_account", 6)?;
    builder.add_output_note(RawOutputNote::Full(allow_note_1.clone()));
    builder.add_output_note(RawOutputNote::Full(allow_note_2.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &allow_note_1).await?;

    // Second allow on the same already-allowed user is a noop — succeeds silently.
    consume_admin_note(&mut mock_chain, faucet.id(), &allow_note_2).await?;

    Ok(())
}

#[tokio::test]
async fn disallow_when_not_allowed_is_noop() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    let disallow_note =
        build_owner_admin_note(owner_id, target_account.id(), "disallow_account", 7)?;
    builder.add_output_note(RawOutputNote::Full(disallow_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Disallowing a non-allowed account is a noop — succeeds silently.
    consume_admin_note(&mut mock_chain, faucet.id(), &disallow_note).await?;

    Ok(())
}

#[tokio::test]
async fn allow_does_not_affect_other_accounts() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let allowed_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let other_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    let amount: u64 = 25;
    let fungible_asset =
        FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        other_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    // Allow one account; the other should still be rejected (default-deny).
    let allow_note = build_owner_admin_note(owner_id, allowed_account.id(), "allow_account", 8)?;
    builder.add_output_note(RawOutputNote::Full(allow_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &allow_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(other_account.id(), &[p2id_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_NOT_ALLOWED);

    Ok(())
}

/// Verifies that `mint_and_send` works on a `BasicFungibleFaucet` whose `TokenPolicyManager`
/// installs the asset-callback slots (here via [`TransferPolicy::Allowlist`]) once the faucet
/// itself is allowlisted so it can satisfy the send policy when minting.
#[tokio::test]
async fn mint_and_send_on_allowlist_basic_faucet() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    // The send policy is invoked from `on_before_asset_added_to_note`, where the native
    // account is the note creator (the faucet itself when minting). Seed the faucet's own
    // ID into the allowlist via an admin note so the mint can proceed.
    let allow_faucet_note = build_owner_admin_note(owner_id, faucet.id(), "allow_account", 9)?;
    builder.add_output_note(RawOutputNote::Full(allow_faucet_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &allow_faucet_note).await?;

    let recipient = Word::from([0u32, 1, 2, 3]);
    let amount: u64 = 100;
    let tag = NoteTag::default();
    let note_type = NoteType::Private;

    let tx_script_code = format!(
        r#"
        begin
            push.0 push.0

            push.{recipient}
            push.{note_type}
            push.{tag}
            push.{amount}

            exec.::miden::protocol::faucet::create_fungible_asset

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
