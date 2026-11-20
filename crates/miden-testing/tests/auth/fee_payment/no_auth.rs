use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::crypto::ecdh::ecgfp5::SecretKey;
use miden_protocol::note::{Note, NoteType, PartialNote};
use miden_protocol::testing::account_id::{ACCOUNT_ID_FEE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_standards::account::access::Authority;
use miden_standards::account::auth::NoAuth;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{BurnPolicy, MintPolicy, SendPolicy, TokenPolicyManager};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::ERR_FEE_NOTE_HAS_ATTACHMENTS;
use miden_standards::note::{EncryptedAssetsIssuerKey, TxFeeNote};
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{MockChain, assert_transaction_executor_error};

use super::{VERIFICATION_BASE_FEE, attaching_callback_faucet};

// HELPER FUNCTIONS
// ================================================================================================

/// Executes a transaction against a no-auth wallet holding `assets`, on a chain charging
/// `verification_base_fee`, and returns the account together with the raw execution result.
///
/// When `input_note` is given, the note is consumed by the transaction (needed on zero-fee
/// chains, where a note-less transaction would be rejected as a no-op).
async fn execute_no_auth_tx(
    verification_base_fee: u32,
    assets: impl IntoIterator<Item = Asset>,
    input_note: Option<Note>,
) -> anyhow::Result<(Account, Result<ExecutedTransaction, miden_tx::TransactionExecutorError>)> {
    let account = AccountBuilder::new([11; 32])
        .with_component(NoAuth)
        .with_component(BasicWallet)
        .with_assets(assets)
        .account_type(AccountType::Public)
        .build_existing()?;

    let mut builder = MockChain::builder().verification_base_fee(verification_base_fee);
    builder.add_account(account.clone())?;
    if let Some(note) = &input_note {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }
    let mock_chain = builder.build()?;

    let notes: Vec<Note> = input_note.into_iter().collect();
    let result = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_notes(notes)
        .build()?
        .execute()
        .await;

    Ok((account, result))
}

// TESTS
// ================================================================================================

/// The no-auth procedure pays the transaction fee by creating a TX_FEE note funded from the
/// account's own vault in the native fee asset, covering the computed fee.
#[tokio::test]
async fn no_auth_pays_fee_note() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let (_, result) = execute_no_auth_tx(VERIFICATION_BASE_FEE, [fee_asset], None).await?;
    let executed_transaction = result?;

    // exactly one output note is created: the fee note
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);
    assert_eq!(output_note.metadata().tag(), TxFeeNote::TAG);

    // the note carries the native fee asset, covering the computed fee
    let assets = output_note.assets();
    let asset = assets.iter().next().expect("fee note should carry an asset");
    let paid_asset = asset.unwrap_fungible();
    assert_eq!(paid_asset.faucet_id(), fee_faucet_id);
    assert!(paid_asset.amount() >= executed_transaction.compute_fee());

    Ok(())
}

/// The TX_FEE note is sealed, so the `on_before_note_sealed` callback of the fee asset's faucet
/// runs on it. A callback that returns an attachment makes the fee payment fail, because the fee
/// note must not carry attachments.
#[tokio::test]
async fn no_auth_fee_note_rejects_callback_attachment() -> anyhow::Result<()> {
    let fee_faucet = attaching_callback_faucet([12; 32])?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet.id(), 1_000_000)?.into();
    let account = AccountBuilder::new([11; 32])
        .with_component(NoAuth)
        .with_component(BasicWallet)
        .with_assets([fee_asset])
        .account_type(AccountType::Public)
        .build_existing()?;

    let mut builder = MockChain::builder()
        .verification_base_fee(VERIFICATION_BASE_FEE)
        .fee_faucet_id(fee_faucet.id());
    builder.add_account(fee_faucet.clone())?;
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.id())
        .foreign_accounts([mock_chain.get_foreign_account_inputs(fee_faucet.id())?])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_NOTE_HAS_ATTACHMENTS);

    Ok(())
}

/// The fee asset's faucet has the encrypted assets send policy active. The TX_FEE note is public,
/// so the policy returns no attachment for it and the fee payment succeeds.
///
/// The account sends an empty note first, so the fee note is at index 1 and a send policy that
/// leaves the note index on top of its outputs would return a non-zero attachment scheme.
#[tokio::test]
async fn no_auth_fee_note_gets_no_encrypted_assets_attachment() -> anyhow::Result<()> {
    let fee_faucet = FungibleFaucet::builder()
        .name(TokenName::new("ENC")?)
        .symbol("ENC".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000_000)?)
        .build()?;
    let fee_faucet = AccountBuilder::new([12; 32])
        .account_type(AccountType::Public)
        .with_component(NoAuth)
        .with_component(fee_faucet)
        .with_component(Authority::AuthControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .active_send_policy(SendPolicy::with_encrypted_assets(
                    EncryptedAssetsIssuerKey::new(SecretKey::from_bytes(&[7; 40])?.public_key()),
                ))
                .build(),
        )
        .build_existing()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet.id(), 1_000_000)?.into();
    let account = AccountBuilder::new([11; 32])
        .with_component(NoAuth)
        .with_component(BasicWallet)
        .with_assets([fee_asset])
        .account_type(AccountType::Public)
        .build_existing()?;

    let mut builder = MockChain::builder()
        .verification_base_fee(VERIFICATION_BASE_FEE)
        .fee_faucet_id(fee_faucet.id());
    builder.add_account(fee_faucet.clone())?;
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let empty_note = NoteBuilder::new(account.id(), &mut rand::rng())
        .note_type(NoteType::Private)
        .build()?;
    let send_script = SendNotesTransactionScript::new(
        &account.code_interface(),
        &[PartialNote::from(empty_note)],
    )?;

    let executed_transaction = mock_chain
        .build_transaction(account.id())
        .send_notes_script(&send_script)
        .foreign_accounts([mock_chain.get_foreign_account_inputs(fee_faucet.id())?])
        .build()?
        .execute()
        .await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 2);
    let fee_note = executed_transaction.output_notes().get_note(1);
    assert_eq!(fee_note.metadata().tag(), TxFeeNote::TAG);
    assert_eq!(fee_note.metadata().note_type(), NoteType::Public);
    assert!(fee_note.attachments().is_empty());

    let paid_asset = fee_note.assets().iter().next().expect("fee note should carry an asset");
    assert!(paid_asset.unwrap_fungible().amount() >= executed_transaction.compute_fee());

    Ok(())
}

/// On a chain with a zero verification base fee, a no-auth account creates no fee note. The
/// transaction consumes a note so it is not a no-op.
#[tokio::test]
async fn no_auth_no_fee_note_on_zero_fee_chain() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();
    let input_note = NoteBuilder::new(ACCOUNT_ID_SENDER.try_into()?, &mut rand::rng()).build()?;

    let (_, result) = execute_no_auth_tx(0, [fee_asset], Some(input_note)).await?;
    let executed_transaction = result?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 0);

    Ok(())
}
