//! Tests for the [`miden_standards::account::policies::BasicBlocklist`] transfer policy
//! component (storage + `check_policy` predicate) and the
//! [`miden_standards::account::policies::BlocklistManager`] authority-gated admin
//! component, dispatched directly by the protocol callback slots via
//! [`miden_standards::account::policies::TokenPolicyManager`].

extern crate alloc;

use alloc::collections::BTreeMap;
use std::sync::Arc;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountProcedureRoot,
    AccountType,
    AssetCallbackFlag,
    RoleSymbol,
};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{AccessControl, Authority, Ownable2Step, Pausable};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BlocklistManager,
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{ERR_ACCOUNT_IS_BLOCKED, ERR_SENDER_LACKS_ROLE};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

use super::rbac::{build_grant_role_note, role, test_account_id};

// HELPERS
// ================================================================================================

fn dummy_owner() -> AccountId {
    AccountId::builder().account_type(AccountType::Private).build_with_seed([9; 32])
}

/// Builds a fungible faucet with the basic blocklist transfer policy on both send and receive,
/// plus the [`BlocklistManager`] component. With `Authority::OwnerControlled` the admin
/// procedures are gated by the Ownable2Step owner, so the owner can invoke `block_account` /
/// `unblock_account` via owner-authored notes.
fn add_faucet_with_owner_blocklist_transfer(
    builder: &mut MockChainBuilder,
    owner_id: AccountId,
) -> anyhow::Result<Account> {
    add_faucet_with_owner_blocklist_transfer_initialized(builder, owner_id, [])
}

/// Same as [`add_faucet_with_owner_blocklist_transfer`] but seeds the `blocked_accounts`
/// storage map with the given accounts at deploy time via
/// [`TransferPolicy::with_basic_blocklist`]. The receive policy reuses the same root via
/// [`TransferPolicy::empty_basic_blocklist`]; the manager dedups companion components by
/// procedure root, so the seeded `BasicBlocklist` from the send policy is installed exactly
/// once.
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

    let account_builder = AccountBuilder::new([43u8; 32])
        .account_type(AccountType::Public)
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner_id))
        .with_component(Authority::OwnerControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .active_send_policy(TransferPolicy::with_basic_blocklist(initial_blocked))
                .active_receive_policy(TransferPolicy::empty_basic_blocklist())
                .build(),
        )
        .with_component(Pausable::unpaused())
        .with_component(BlocklistManager);

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

/// Builds a `sender`-authored note whose script invokes
/// `manager::{block_account|unblock_account}` on the given target account. The sender must be
/// authorized per the faucet's installed `Authority` component (the owner under
/// `OwnerControlled`, or a role holder under `RbacControlled`).
fn build_admin_note(
    sender: AccountId,
    target_id: AccountId,
    proc: &str,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let (prefix, suffix) = account_id_felts(target_id);
    let script_code = format!(
        r#"
        use miden::standards::faucets::policies::transfer::blocklist::manager

        @note_script
        pub proc main
            padw padw padw push.0.0

            push.{prefix}
            push.{suffix}
            call.manager::{proc}

            dropw dropw dropw dropw
        end
        "#
    );

    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    NoteBuilder::new(sender, &mut rng)
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
        .build_transaction(faucet_id)
        .authenticated_input_note(note.id())
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

    let asset = FungibleAsset::new(faucet.id(), 100)?;
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
        .build_transaction(target_account.id())
        .authenticated_input_note(note.id())
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

    let asset = FungibleAsset::new(faucet.id(), 100)?;
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(p2id_note.id())
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

    let asset = FungibleAsset::new(faucet.id(), 100)?;
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let block_note = build_admin_note(owner_id, target_account.id(), "block_account", 1)?;
    builder.add_output_note(RawOutputNote::Full(block_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &block_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(p2id_note.id())
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
    // Only `create_note` is needed here, so a `NoteCreator` account suffices instead of a full
    // basic wallet.
    let target_account = builder.add_existing_note_creator(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_blocklist_transfer(&mut builder, owner_id)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?;

    let block_note = build_admin_note(owner_id, target_account.id(), "block_account", 2)?;
    builder.add_output_note(RawOutputNote::Full(block_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &block_note).await?;

    let recipient = Word::from([0u32, 1, 2, 3]);
    let script_code = format!(
        r#"
        use miden::protocol::output_note

        @transaction_script
        pub proc main
            push.{recipient}
            push.{note_type}
            push.{tag}
            call.::miden::standards::note::note_creator::create_note
            movdn.15 dropw dropw dropw drop drop drop

            push.{asset_value}
            push.{asset_id}
            exec.output_note::add_asset
        end
        "#,
        recipient = recipient,
        note_type = NoteType::Private as u8,
        tag = NoteTag::default(),
        asset_value = Asset::Fungible(asset).to_value_word(),
        asset_id = Asset::Fungible(asset).to_id_word(),
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(&script_code)?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(target_account.id())
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
    let fungible_asset = FungibleAsset::new(faucet.id(), amount)?;
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    let block_note = build_admin_note(owner_id, target_account.id(), "block_account", 3)?;
    let unblock_note = build_admin_note(owner_id, target_account.id(), "unblock_account", 4)?;
    builder.add_output_note(RawOutputNote::Full(block_note.clone()));
    builder.add_output_note(RawOutputNote::Full(unblock_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &block_note).await?;
    consume_admin_note(&mut mock_chain, faucet.id(), &unblock_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(p2id_note.id())
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

    let block_note_1 = build_admin_note(owner_id, target_account.id(), "block_account", 5)?;
    let block_note_2 = build_admin_note(owner_id, target_account.id(), "block_account", 6)?;
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

    let unblock_note = build_admin_note(owner_id, target_account.id(), "unblock_account", 7)?;
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
    let fungible_asset = FungibleAsset::new(faucet.id(), amount)?;
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        other_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    // Block a different account — the non-blocked one should still receive.
    let block_note = build_admin_note(owner_id, blocked_account.id(), "block_account", 8)?;
    builder.add_output_note(RawOutputNote::Full(block_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &block_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    mock_chain
        .build_transaction(other_account.id())
        .authenticated_input_note(p2id_note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Verifies that `mint_and_send` works on a `BasicFungibleFaucet` whose `TokenPolicyManager`
/// installs the asset-callback slots (here via the basic blocklist transfer policy).
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

    // `mint_and_send` takes the full asset (ASSET_ID + ASSET_VALUE) the MINT note carries.
    let asset = FungibleAsset::new(faucet.id(), amount)?;
    let asset_id = asset.to_id_word();
    let asset_value = asset.to_value_word();

    let tx_script_code = format!(
        r#"
        @transaction_script
        pub proc main
            push.0.0

            push.{recipient}
            push.{note_type}
            push.{tag}
            push.{asset_value}
            push.{asset_id}

            call.::miden::standards::faucets::fungible::mint_and_send

            dropw dropw dropw dropw
        end
        "#,
        recipient = recipient,
        note_type = note_type as u8,
        tag = u32::from(tag),
        asset_value = asset_value,
        asset_id = asset_id,
    );

    let tx_script = CodeBuilder::default().compile_tx_script(&tx_script_code)?;
    let executed = mock_chain
        .build_transaction(faucet.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 1);
    Ok(())
}

// TESTS — BLOCKLIST MANAGER WITH PER-PROCEDURE RBAC ROLES
// ================================================================================================

/// Maps both `block_account` and `unblock_account` to a single `BLOCKLISTER` role, so one role
/// gates both operations.
fn blocklister_roles() -> BTreeMap<AccountProcedureRoot, RoleSymbol> {
    BTreeMap::from([
        (BlocklistManager::block_account_root(), role("BLOCKLISTER")),
        (BlocklistManager::unblock_account_root(), role("BLOCKLISTER")),
    ])
}

/// Builds a fungible faucet whose blocklist admin is gated by `Authority::RbacControlled`, with
/// both `block_account` and `unblock_account` mapped to the `BLOCKLISTER` role.
fn add_rbac_faucet_with_blocklist(
    builder: &mut MockChainBuilder,
    admin: AccountId,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([71u8; 32])
        .account_type(AccountType::Public)
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .with_component(faucet)
        .with_components(AccessControl::Rbac {
            admin,
            procedure_roles: blocklister_roles(),
        })
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .active_send_policy(TransferPolicy::empty_basic_blocklist())
                .active_receive_policy(TransferPolicy::empty_basic_blocklist())
                .build(),
        )
        .with_component(Pausable::unpaused())
        .with_component(BlocklistManager);

    builder.add_account_from_builder(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )
}

/// A single `BLOCKLISTER` role holder can both block and unblock accounts, and the effect is
/// observable through the transfer policy.
#[tokio::test]
async fn rbac_blocklister_can_block_and_unblock() -> anyhow::Result<()> {
    let admin = test_account_id(60);
    let blocklister = test_account_id(61);

    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_rbac_faucet_with_blocklist(&mut builder, admin)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?;
    let p2id_after_block = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;
    let p2id_after_unblock = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let grant = build_grant_role_note(admin, &role("BLOCKLISTER"), blocklister)?;
    let block = build_admin_note(blocklister, target_account.id(), "block_account", 41)?;
    let unblock = build_admin_note(blocklister, target_account.id(), "unblock_account", 42)?;
    for note in [&grant, &block, &unblock] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Admin grants BLOCKLISTER; the role holder then blocks the target.
    consume_admin_note(&mut mock_chain, faucet.id(), &grant).await?;
    consume_admin_note(&mut mock_chain, faucet.id(), &block).await?;

    // Blocked → receiving the asset fails.
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let result = mock_chain
        .build_tx_context(target_account.id(), &[p2id_after_block.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_BLOCKED);

    // The same role unblocks the target.
    consume_admin_note(&mut mock_chain, faucet.id(), &unblock).await?;

    // Unblocked → receiving the asset now succeeds.
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    mock_chain
        .build_tx_context(target_account.id(), &[p2id_after_unblock.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// A sender that does not hold the `BLOCKLISTER` role cannot invoke `block_account`.
#[tokio::test]
async fn rbac_block_fails_when_sender_lacks_role() -> anyhow::Result<()> {
    let admin = test_account_id(62);
    let stranger = test_account_id(63);

    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_rbac_faucet_with_blocklist(&mut builder, admin)?;

    let block = build_admin_note(stranger, target_account.id(), "block_account", 43)?;
    builder.add_output_note(RawOutputNote::Full(block.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[block.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);

    Ok(())
}
