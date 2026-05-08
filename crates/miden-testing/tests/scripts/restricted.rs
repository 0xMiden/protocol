//! Tests for the [`miden_standards::account::faucets::Restricted`] admin procedures
//! and the [`miden_standards::account::policies::TransferIfNotBlocklisted`] transfer policy
//! callbacks dispatched by the [`miden_standards::account::policies::TokenPolicyManager`].

extern crate alloc;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::asset::{Asset, AssetCallbackFlag, FungibleAsset};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::BasicFungibleFaucet;
use miden_standards::account::metadata::{FungibleTokenMetadataBuilder, TokenName};
use miden_standards::account::policies::{
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyAuthority,
    PolicyRegistration,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

const ERR_RESTRICTED_ACCOUNT_IS_BLOCKED: MasmError =
    MasmError::from_static_str("account is blocked");

const ERR_RESTRICTED_ALREADY_BLOCKED: MasmError =
    MasmError::from_static_str("account is already blocked");

const ERR_RESTRICTED_NOT_BLOCKED: MasmError = MasmError::from_static_str("account is not blocked");

/// Builds a fungible faucet with a [`TokenPolicyManager`] configured with
/// [`TransferPolicy::IfNotBlocklisted`] on both send and receive. The manager pulls in the
/// [`miden_standards::account::faucets::Restricted`] companion component so the predicate has
/// access to the per-account blocked-accounts storage and admin procedures.
fn add_faucet_with_restricted_transfer(builder: &mut MockChainBuilder) -> anyhow::Result<Account> {
    let faucet_metadata = FungibleTokenMetadataBuilder::new(
        TokenName::new("SYM")?,
        "SYM".try_into()?,
        8,
        1_000_000u64,
    )
    .build()?;

    let account_builder = AccountBuilder::new([43u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(faucet_metadata)
        .with_component(BasicFungibleFaucet)
        .with_components(
            TokenPolicyManager::new(PolicyAuthority::AuthControlled)
                .with_mint_policy(MintPolicyConfig::AllowAll, PolicyRegistration::Active)
                .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)
                .with_send_policy(TransferPolicy::IfNotBlocklisted, PolicyRegistration::Active)
                .with_receive_policy(TransferPolicy::IfNotBlocklisted, PolicyRegistration::Active),
        );

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

async fn execute_faucet_block(
    mock_chain: &mut MockChain,
    faucet_id: AccountId,
    target_id: AccountId,
) -> anyhow::Result<()> {
    let (prefix, suffix) = account_id_felts(target_id);
    let script = format!(
        r#"
        begin
            push.{prefix}
            push.{suffix}
            call.::miden::standards::faucets::restricted::block
            dropw dropw dropw dropw
        end
        "#
    );
    let tx_script = CodeBuilder::default().compile_tx_script(&script)?;
    let executed = mock_chain
        .build_tx_context(faucet_id, &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    Ok(())
}

async fn execute_faucet_unblock(
    mock_chain: &mut MockChain,
    faucet_id: AccountId,
    target_id: AccountId,
) -> anyhow::Result<()> {
    let (prefix, suffix) = account_id_felts(target_id);
    let script = format!(
        r#"
        begin
            push.{prefix}
            push.{suffix}
            call.::miden::standards::faucets::restricted::unblock
            dropw dropw dropw dropw
        end
        "#
    );
    let tx_script = CodeBuilder::default().compile_tx_script(&script)?;
    let executed = mock_chain
        .build_tx_context(faucet_id, &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    Ok(())
}

#[tokio::test]
async fn block_receive_asset_succeeds_when_not_blocked() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_restricted_transfer(&mut builder)?;

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
async fn block_receive_asset_fails_when_recipient_blocked() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_restricted_transfer(&mut builder)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_faucet_block(&mut mock_chain, faucet.id(), target_account.id()).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_RESTRICTED_ACCOUNT_IS_BLOCKED);

    Ok(())
}

#[tokio::test]
async fn block_add_asset_to_note_fails_when_sender_blocked() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_restricted_transfer(&mut builder)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_faucet_block(&mut mock_chain, faucet.id(), target_account.id()).await?;

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

    assert_transaction_executor_error!(result, ERR_RESTRICTED_ACCOUNT_IS_BLOCKED);

    Ok(())
}

#[tokio::test]
async fn block_then_unblock_then_receive_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_restricted_transfer(&mut builder)?;

    let amount: u64 = 50;
    let fungible_asset =
        FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_faucet_block(&mut mock_chain, faucet.id(), target_account.id()).await?;
    execute_faucet_unblock(&mut mock_chain, faucet.id(), target_account.id()).await?;

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
async fn block_already_blocked_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_restricted_transfer(&mut builder)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_faucet_block(&mut mock_chain, faucet.id(), target_account.id()).await?;

    let (prefix, suffix) = account_id_felts(target_account.id());
    let script = format!(
        r#"
        begin
            push.{prefix}
            push.{suffix}
            call.::miden::standards::faucets::restricted::block
            dropw dropw dropw dropw
        end
        "#
    );
    let tx_script = CodeBuilder::default().compile_tx_script(&script)?;
    let result = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_RESTRICTED_ALREADY_BLOCKED);

    Ok(())
}

#[tokio::test]
async fn unblock_when_not_blocked_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_restricted_transfer(&mut builder)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let (prefix, suffix) = account_id_felts(target_account.id());
    let script = format!(
        r#"
        begin
            push.{prefix}
            push.{suffix}
            call.::miden::standards::faucets::restricted::unblock
            dropw dropw dropw dropw
        end
        "#
    );
    let tx_script = CodeBuilder::default().compile_tx_script(&script)?;
    let result = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_RESTRICTED_NOT_BLOCKED);

    Ok(())
}

#[tokio::test]
async fn block_does_not_affect_other_accounts() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let blocked_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let other_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_restricted_transfer(&mut builder)?;

    let amount: u64 = 25;
    let fungible_asset =
        FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        other_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Block a different account — the non-blocked one should still receive.
    execute_faucet_block(&mut mock_chain, faucet.id(), blocked_account.id()).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    mock_chain
        .build_tx_context(other_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Verifies that `mint_and_send` works on a `BasicFungibleFaucet` whose `TokenPolicyManager`
/// installs the asset-callback slots (here via [`TransferPolicy::IfNotBlocklisted`]).
///
/// The protocol fires `on_before_asset_added_to_note` when the mint adds the asset to its
/// output note. Before the protocol fix in 0xMiden/protocol#2879 the kernel rejected this with
/// `ERR_FOREIGN_ACCOUNT_CONTEXT_AGAINST_NATIVE_ACCOUNT` because the issuing faucet was also
/// the native account. The fix short-circuits callback dispatch when the issuer equals the
/// native account, so this test now succeeds.
#[tokio::test]
async fn mint_and_send_on_if_not_blocklisted_basic_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_restricted_transfer(&mut builder)?;
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

            call.::miden::standards::faucets::basic_fungible::mint_and_send

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
