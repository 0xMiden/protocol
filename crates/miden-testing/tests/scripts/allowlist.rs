//! Tests for the [`miden_standards::account::policies::BasicAllowlist`] transfer policy
//! component (storage + `check_policy` predicate) and the
//! [`miden_standards::account::policies::AllowlistManager`] authority-gated admin
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
    AllowlistManager,
    AllowlistStorage,
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{ERR_ACCOUNT_IS_NOT_ALLOWED, ERR_SENDER_LACKS_ROLE};
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

/// Builds a fungible faucet with [`TransferPolicy::with_basic_allowlist`] on both send and receive,
/// plus the [`AllowlistManager`] component. With `Authority::OwnerControlled` the admin
/// procedures are gated by the Ownable2Step owner, so the owner can invoke `allow_account` /
/// `disallow_account` via owner-authored notes.
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
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner_id))
        .with_component(Authority::OwnerControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .active_send_policy(TransferPolicy::with_basic_allowlist(allow_list.clone()))
                .active_receive_policy(TransferPolicy::with_basic_allowlist(allow_list))
                .build(),
        )
        .with_component(Pausable::unpaused())
        .with_component(AllowlistManager);

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
/// `manager::{allow_account|disallow_account}` on the given target account. The sender must be
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
        use miden::standards::faucets::policies::transfer::allowlist::manager

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

#[tokio::test]
async fn allow_receive_asset_fails_when_recipient_not_allowed() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

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

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_NOT_ALLOWED);

    Ok(())
}

#[tokio::test]
async fn allow_then_receive_succeeds() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?;
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let allow_note = build_admin_note(owner_id, target_account.id(), "allow_account", 1)?;
    builder.add_output_note(RawOutputNote::Full(allow_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &allow_note).await?;

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
async fn allow_add_asset_to_note_fails_when_sender_not_allowed() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    // Only `create_note` is needed here, so a `NoteCreator` account suffices instead of a full
    // basic wallet.
    let target_account = builder.add_existing_note_creator(Auth::IncrNonce)?;
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?;

    let mock_chain = builder.build()?;

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

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(&script_code)?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(target_account.id())
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
    let fungible_asset = FungibleAsset::new(faucet.id(), amount)?;
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    let disallow_note = build_admin_note(owner_id, target_account.id(), "disallow_account", 3)?;
    builder.add_output_note(RawOutputNote::Full(disallow_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &disallow_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(p2id_note.id())
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

    let allow_note_1 = build_admin_note(owner_id, target_account.id(), "allow_account", 5)?;
    let allow_note_2 = build_admin_note(owner_id, target_account.id(), "allow_account", 6)?;
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

    let disallow_note = build_admin_note(owner_id, target_account.id(), "disallow_account", 7)?;
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
    let fungible_asset = FungibleAsset::new(faucet.id(), amount)?;
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        other_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    // Allow one account; the other should still be rejected (default-deny).
    let allow_note = build_admin_note(owner_id, allowed_account.id(), "allow_account", 8)?;
    builder.add_output_note(RawOutputNote::Full(allow_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    consume_admin_note(&mut mock_chain, faucet.id(), &allow_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(other_account.id())
        .authenticated_input_note(p2id_note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_NOT_ALLOWED);

    Ok(())
}

/// Verifies that `mint_and_send` works on a `BasicFungibleFaucet` whose `TokenPolicyManager`
/// installs the asset-callback slots (here via [`TransferPolicy::with_basic_allowlist`]) once the
/// faucet itself is allowlisted so it can satisfy the send policy when minting.
#[tokio::test]
async fn mint_and_send_on_allowlist_basic_faucet() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_allowlist_transfer(&mut builder, owner_id)?;

    // The send policy is invoked from `on_before_asset_added_to_note`, where the native
    // account is the note creator (the faucet itself when minting). Seed the faucet's own
    // ID into the allowlist via an admin note so the mint can proceed.
    let allow_faucet_note = build_admin_note(owner_id, faucet.id(), "allow_account", 9)?;
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
        @transaction_script
        pub proc main
            push.0 push.0

            push.{recipient}
            push.{note_type}
            push.{tag}
            push.{amount}

            exec.::miden::protocol::active_account::get_id
            exec.::miden::standards::assets::fungible_asset::create

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
        .build_transaction(faucet.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 1);
    Ok(())
}

// TESTS — ALLOWLIST MANAGER WITH PER-PROCEDURE RBAC ROLES
// ================================================================================================

/// Maps both `allow_account` and `disallow_account` to a single `ALLOWLISTER` role, so one role
/// gates both operations.
fn allowlister_roles() -> BTreeMap<AccountProcedureRoot, RoleSymbol> {
    BTreeMap::from([
        (AllowlistManager::allow_account_root(), role("ALLOWLISTER")),
        (AllowlistManager::disallow_account_root(), role("ALLOWLISTER")),
    ])
}

/// Builds a fungible faucet whose allowlist admin is gated by `Authority::RbacControlled`, with
/// both `allow_account` and `disallow_account` mapped to the `ALLOWLISTER` role.
fn add_rbac_faucet_with_allowlist(
    builder: &mut MockChainBuilder,
    admin: AccountId,
    initial_allowed: impl IntoIterator<Item = AccountId>,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let allow_list = AllowlistStorage::with_allowed_accounts(initial_allowed);

    let account_builder = AccountBuilder::new([71u8; 32])
        .account_type(AccountType::Public)
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .with_component(faucet)
        .with_components(AccessControl::Rbac {
            admin,
            procedure_roles: allowlister_roles(),
        })
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .active_send_policy(TransferPolicy::with_basic_allowlist(allow_list.clone()))
                .active_receive_policy(TransferPolicy::with_basic_allowlist(allow_list))
                .build(),
        )
        .with_component(Pausable::unpaused())
        .with_component(AllowlistManager);

    builder.add_account_from_builder(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )
}

/// A single `ALLOWLISTER` role holder can both allow and disallow accounts, and the effect is
/// observable through the transfer policy.
#[tokio::test]
async fn rbac_allowlister_can_allow_and_disallow() -> anyhow::Result<()> {
    let admin = test_account_id(60);
    let allowlister = test_account_id(61);

    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_rbac_faucet_with_allowlist(&mut builder, admin, [])?;

    let asset = FungibleAsset::new(faucet.id(), 100)?;
    let p2id_after_allow = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;
    let p2id_after_disallow = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let grant = build_grant_role_note(admin, &role("ALLOWLISTER"), allowlister)?;
    let allow = build_admin_note(allowlister, target_account.id(), "allow_account", 41)?;
    let disallow = build_admin_note(allowlister, target_account.id(), "disallow_account", 42)?;
    for note in [&grant, &allow, &disallow] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Admin grants ALLOWLISTER; the role holder then allows the target.
    consume_admin_note(&mut mock_chain, faucet.id(), &grant).await?;
    consume_admin_note(&mut mock_chain, faucet.id(), &allow).await?;

    // Allowed → receiving the asset succeeds.
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(p2id_after_allow.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    // The same role disallows the target.
    consume_admin_note(&mut mock_chain, faucet.id(), &disallow).await?;

    // Disallowed → receiving the asset now fails.
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let result = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(p2id_after_disallow.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_NOT_ALLOWED);

    Ok(())
}

/// A sender that does not hold the `ALLOWLISTER` role cannot invoke `allow_account`.
#[tokio::test]
async fn rbac_allow_fails_when_sender_lacks_role() -> anyhow::Result<()> {
    let admin = test_account_id(62);
    let stranger = test_account_id(63);

    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_rbac_faucet_with_allowlist(&mut builder, admin, [])?;

    let allow = build_admin_note(stranger, target_account.id(), "allow_account", 43)?;
    builder.add_output_note(RawOutputNote::Full(allow.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(faucet.id())
        .authenticated_input_note(allow.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);

    Ok(())
}
