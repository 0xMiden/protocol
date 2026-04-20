//! Tests for [`miden_standards::account::pausable::Pausable`] asset callbacks and pause/unpause
//! scripts.

extern crate alloc;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::asset::{
    Asset,
    AssetCallbackFlag,
    FungibleAsset,
    NonFungibleAsset,
    NonFungibleAssetDetails,
};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::BasicFungibleFaucet;
use miden_standards::account::pausable::Pausable;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockFaucetComponent;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

const ERR_PAUSABLE_ENFORCED_PAUSE: MasmError = MasmError::from_static_str("the contract is paused");

const ERR_PAUSABLE_EXPECTED_PAUSE: MasmError =
    MasmError::from_static_str("the contract is not paused");

fn add_faucet_with_pausable(builder: &mut MockChainBuilder) -> anyhow::Result<Account> {
    let basic_faucet = BasicFungibleFaucet::new("SYM".try_into()?, 8, Felt::new(1_000_000))?;

    let account_builder = AccountBuilder::new([43u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(basic_faucet)
        .with_component(Pausable::default());

    builder.add_account_from_builder(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )
}

fn add_faucet_with_pausable_for_account_type(
    builder: &mut MockChainBuilder,
    account_type: AccountType,
) -> anyhow::Result<Account> {
    if !account_type.is_faucet() {
        anyhow::bail!("account type must be a faucet");
    }

    let faucet_component: AccountComponent = match account_type {
        AccountType::FungibleFaucet => {
            BasicFungibleFaucet::new("SYM".try_into()?, 8, Felt::new(1_000_000))?.into()
        },
        AccountType::NonFungibleFaucet => MockFaucetComponent.into(),
        _ => anyhow::bail!("pausable tests only use fungible or non-fungible faucet account types"),
    };

    let account_builder = AccountBuilder::new([43u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(account_type)
        .with_component(faucet_component)
        .with_component(Pausable::default());

    builder.add_account_from_builder(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )
}

async fn execute_faucet_pause(
    mock_chain: &mut MockChain,
    faucet_id: AccountId,
) -> anyhow::Result<()> {
    let pause_script = r#"
        begin
            padw padw push.0
            call.::miden::standards::utils::pausable::pause
            dropw dropw dropw dropw
        end
    "#;
    let tx_script = CodeBuilder::default().compile_tx_script(pause_script)?;
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

async fn execute_faucet_unpause(
    mock_chain: &mut MockChain,
    faucet_id: AccountId,
) -> anyhow::Result<()> {
    let unpause_script = r#"
        begin
            padw padw push.0
            call.::miden::standards::utils::pausable::unpause
            dropw dropw dropw dropw
        end
    "#;
    let tx_script = CodeBuilder::default().compile_tx_script(unpause_script)?;
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

#[rstest::rstest]
#[case::fungible(
    AccountType::FungibleFaucet,
    |faucet_id| {
        Ok(FungibleAsset::new(faucet_id, 100)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[case::non_fungible(
    AccountType::NonFungibleFaucet,
    |faucet_id| {
        let details = NonFungibleAssetDetails::new(faucet_id, vec![1, 2, 3, 4])?;
        Ok(NonFungibleAsset::new(&details)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[tokio::test]
async fn pausable_receive_asset_succeeds_when_unpaused(
    #[case] account_type: AccountType,
    #[case] create_asset: impl FnOnce(AccountId) -> anyhow::Result<Asset>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet = add_faucet_with_pausable_for_account_type(&mut builder, account_type)?;

    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[create_asset(faucet.id())?],
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

#[rstest::rstest]
#[case::fungible(
    AccountType::FungibleFaucet,
    |faucet_id| {
        Ok(FungibleAsset::new(faucet_id, 100)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[case::non_fungible(
    AccountType::NonFungibleFaucet,
    |faucet_id| {
        let details = NonFungibleAssetDetails::new(faucet_id, vec![1, 2, 3, 4])?;
        Ok(NonFungibleAsset::new(&details)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[tokio::test]
async fn pausable_receive_asset_fails_when_paused(
    #[case] account_type: AccountType,
    #[case] create_asset: impl FnOnce(AccountId) -> anyhow::Result<Asset>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet = add_faucet_with_pausable_for_account_type(&mut builder, account_type)?;

    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[create_asset(faucet.id())?],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_faucet_pause(&mut mock_chain, faucet.id()).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_ENFORCED_PAUSE);

    Ok(())
}

#[rstest::rstest]
#[case::fungible(
    AccountType::FungibleFaucet,
    |faucet_id| {
        Ok(FungibleAsset::new(faucet_id, 100)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[case::non_fungible(
    AccountType::NonFungibleFaucet,
    |faucet_id| {
        let details = NonFungibleAssetDetails::new(faucet_id, vec![1, 2, 3, 4])?;
        Ok(NonFungibleAsset::new(&details)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[tokio::test]
async fn pausable_add_asset_to_note_fails_when_paused(
    #[case] account_type: AccountType,
    #[case] create_asset: impl FnOnce(AccountId) -> anyhow::Result<Asset>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet = add_faucet_with_pausable_for_account_type(&mut builder, account_type)?;

    let asset = create_asset(faucet.id())?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_faucet_pause(&mut mock_chain, faucet.id()).await?;

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
        asset_value = asset.to_value_word(),
        asset_key = asset.to_key_word(),
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

    assert_transaction_executor_error!(result, ERR_PAUSABLE_ENFORCED_PAUSE);

    Ok(())
}

#[tokio::test]
async fn pausable_pause_then_unpause_then_receive_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pausable(&mut builder)?;

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

    execute_faucet_pause(&mut mock_chain, faucet.id()).await?;
    execute_faucet_unpause(&mut mock_chain, faucet.id()).await?;

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
async fn pausable_unpause_while_unpaused_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let _wallet = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pausable(&mut builder)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let unpause_script = r#"
        begin
            padw padw push.0
            call.::miden::standards::utils::pausable::unpause
            dropw dropw dropw dropw
        end
    "#;
    let tx_script = CodeBuilder::default().compile_tx_script(unpause_script)?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_EXPECTED_PAUSE);

    Ok(())
}
