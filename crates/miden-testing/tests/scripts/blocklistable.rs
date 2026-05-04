//! Tests for the [`miden_standards::account::blocklistable::Blocklistable`] admin procedures
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
    TokenPolicyManager,
    TransferPolicyConfig,
};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

const ERR_BLOCKLIST_ACCOUNT_IS_BLOCKLISTED: MasmError =
    MasmError::from_static_str("account is blocklisted");

const ERR_BLOCKLIST_ALREADY_BLOCKLISTED: MasmError =
    MasmError::from_static_str("account is already blocklisted");

const ERR_BLOCKLIST_NOT_BLOCKLISTED: MasmError =
    MasmError::from_static_str("account is not blocklisted");

/// Builds a fungible faucet with a [`TokenPolicyManager`] configured for
/// [`TransferPolicyConfig::IfNotBlocklisted`]. The manager auto-installs the
/// [`miden_standards::account::blocklistable::Blocklistable`] component so the predicate has
/// access to the per-account blocklist storage and admin procedures.
fn add_faucet_with_transfer_blocklist(builder: &mut MockChainBuilder) -> anyhow::Result<Account> {
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
        .with_components(TokenPolicyManager::new(
            PolicyAuthority::AuthControlled,
            MintPolicyConfig::AllowAll,
            BurnPolicyConfig::AllowAll,
            TransferPolicyConfig::IfNotBlocklisted,
        ));

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

async fn execute_faucet_blocklist(
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
            call.::miden::standards::utils::blocklistable::blocklist
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

async fn execute_faucet_unblocklist(
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
            call.::miden::standards::utils::blocklistable::unblocklist
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
async fn blocklist_receive_asset_succeeds_when_not_blocklisted() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_transfer_blocklist(&mut builder)?;

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
async fn blocklist_receive_asset_fails_when_recipient_blocklisted() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_transfer_blocklist(&mut builder)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_faucet_blocklist(&mut mock_chain, faucet.id(), target_account.id()).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_BLOCKLIST_ACCOUNT_IS_BLOCKLISTED);

    Ok(())
}

#[tokio::test]
async fn blocklist_add_asset_to_note_fails_when_sender_blocklisted() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_transfer_blocklist(&mut builder)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_faucet_blocklist(&mut mock_chain, faucet.id(), target_account.id()).await?;

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

    assert_transaction_executor_error!(result, ERR_BLOCKLIST_ACCOUNT_IS_BLOCKLISTED);

    Ok(())
}

#[tokio::test]
async fn blocklist_then_unblocklist_then_receive_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_transfer_blocklist(&mut builder)?;

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

    execute_faucet_blocklist(&mut mock_chain, faucet.id(), target_account.id()).await?;
    execute_faucet_unblocklist(&mut mock_chain, faucet.id(), target_account.id()).await?;

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
async fn blocklist_already_blocklisted_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_transfer_blocklist(&mut builder)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_faucet_blocklist(&mut mock_chain, faucet.id(), target_account.id()).await?;

    let (prefix, suffix) = account_id_felts(target_account.id());
    let script = format!(
        r#"
        begin
            push.{prefix}
            push.{suffix}
            call.::miden::standards::utils::blocklistable::blocklist
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

    assert_transaction_executor_error!(result, ERR_BLOCKLIST_ALREADY_BLOCKLISTED);

    Ok(())
}

#[tokio::test]
async fn unblocklist_when_not_blocklisted_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_transfer_blocklist(&mut builder)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let (prefix, suffix) = account_id_felts(target_account.id());
    let script = format!(
        r#"
        begin
            push.{prefix}
            push.{suffix}
            call.::miden::standards::utils::blocklistable::unblocklist
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

    assert_transaction_executor_error!(result, ERR_BLOCKLIST_NOT_BLOCKLISTED);

    Ok(())
}

#[tokio::test]
async fn blocklist_does_not_affect_other_accounts() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let blocklisted_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let other_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_transfer_blocklist(&mut builder)?;

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

    // Blocklist a different account — the non-blocklisted one should still receive.
    execute_faucet_blocklist(&mut mock_chain, faucet.id(), blocklisted_account.id()).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    mock_chain
        .build_tx_context(other_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}
